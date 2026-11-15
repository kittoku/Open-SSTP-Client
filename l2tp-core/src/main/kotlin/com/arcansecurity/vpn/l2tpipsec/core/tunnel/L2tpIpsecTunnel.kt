package com.arcansecurity.vpn.l2tpipsec.core.tunnel

import com.arcansecurity.vpn.l2tpipsec.core.esp.EspException
import com.arcansecurity.vpn.l2tpipsec.core.esp.EspInboundSa
import com.arcansecurity.vpn.l2tpipsec.core.esp.EspOutboundSa
import com.arcansecurity.vpn.l2tpipsec.core.esp.UdpEncapsulation
import com.arcansecurity.vpn.l2tpipsec.core.ike.ExchangeType
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeTransport
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeV1Negotiator
import com.arcansecurity.vpn.l2tpipsec.core.ike.IsakmpHeader
import com.arcansecurity.vpn.l2tpipsec.core.ike.NatTraversalFlavor
import com.arcansecurity.vpn.l2tpipsec.core.ike.Phase1Result
import com.arcansecurity.vpn.l2tpipsec.core.ike.Phase2Result
import com.arcansecurity.vpn.l2tpipsec.core.l2tp.L2tpTransport
import com.arcansecurity.vpn.l2tpipsec.core.l2tp.L2tpTunnel
import com.arcansecurity.vpn.l2tpipsec.core.net.UdpDatagram
import com.arcansecurity.vpn.l2tpipsec.core.ppp.PppFrame
import com.arcansecurity.vpn.l2tpipsec.core.ppp.PppProtocol
import com.arcansecurity.vpn.l2tpipsec.core.ppp.PppSession
import com.arcansecurity.vpn.l2tpipsec.core.util.Log
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.UnknownHostException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Drives one complete L2TP/IPsec connection and then pumps packets through it.
 *
 * The layering, outermost first, is:
 * ```
 * UDP/4500 datagram  <- the only socket we own, protected from the VPN we are building
 *   ESP transport mode (RFC 4303 + RFC 3948 encapsulation)
 *     UDP 1701 -> 1701          <- inner transport-layer datagram; there is NO inner IP header
 *       L2TPv2 data message
 *         PPP frame
 *           the user's IP packet, read from / written to the TUN interface
 * ```
 * [run] blocks on the calling thread until the tunnel terminates; [stop] unblocks it.
 */
class L2tpIpsecTunnel(
    private val config: VpnConfig,
    private val socketFactory: UdpSocketFactory,
    private val tunProvider: TunProvider,
    private val listener: TunnelListener = TunnelListener.NONE,
    private val logger: VpnLogger = VpnLogger.NONE,
    private val clock: Clock = Clock.SYSTEM,
) {
    private val log = Log("Tunnel", logger)
    private val stopRequested = AtomicBoolean(false)

    private val bytesIn = AtomicLong()
    private val bytesOut = AtomicLong()
    private val packetsIn = AtomicLong()
    private val packetsOut = AtomicLong()

    @Volatile private var connectedSinceMs = 0L
    @Volatile private var socket: UdpSocketChannel? = null
    @Volatile private var tun: TunInterface? = null
    @Volatile private var readerThread: Thread? = null
    @Volatile private var uplinkThread: Thread? = null
    @Volatile private var maintenanceThread: Thread? = null

    @Volatile
    var state: TunnelState = TunnelState.IDLE
        private set

    val stats: TunnelStats
        get() = TunnelStats(
            bytesIn = bytesIn.get(),
            bytesOut = bytesOut.get(),
            packetsIn = packetsIn.get(),
            packetsOut = packetsOut.get(),
            connectedSinceMs = connectedSinceMs,
            ipsecRekeys = ipsecRekeys.get(),
            ikeRekeys = ikeRekeys.get(),
        )

    // Datagrams demultiplexed off the single UDP socket by the reader thread.
    private val ikeQueue = ArrayBlockingQueue<ByteArray>(32)
    private val l2tpQueue = ArrayBlockingQueue<ByteArray>(256)

    /**
     * ISAKMP messages a negotiator read off [ikeQueue] and could not own.
     *
     * A rekey runs a second negotiator on the maintenance thread, and that thread is the only
     * consumer of [ikeQueue], so for the few round trips a Main Mode takes the new negotiator is
     * the one draining it — and everything still arriving for the SA being replaced is addressed
     * to cookies it does not have and encrypted under keys it cannot derive. Parking those here
     * rather than dropping them is what keeps a DPD probe, a Delete or a peer-initiated Quick Mode
     * alive across the window.
     *
     * It is deliberately *not* [ikeQueue]: putting a message back on the queue the negotiator is
     * reading would have it read, reject and requeue the same datagram for ever. [drainIkeQueue]
     * empties this first, and because it runs on the same thread as the rekey it cannot possibly
     * run before the new context has been installed — which is what stops a deferred message from
     * being attributed to the SA that was current when it arrived.
     */
    private val deferredIkeQueue = ArrayBlockingQueue<ByteArray>(16)

    /**
     * Pushed onto [l2tpQueue] to wake the packet pump for something that is not a packet.
     *
     * The pump now sleeps until the PPP and L2TP state machines say they have work, which can be
     * twenty seconds; without a way to interrupt that, a stop request or a failure raised by the
     * maintenance thread would sit unnoticed for as long. Matched by identity, so a genuine
     * zero-length payload cannot be mistaken for it.
     */
    private val wakeUp = ByteArray(0)

    /** Last time the counters were published, by whichever thread had just moved them. */
    private val lastStatsAtMs = AtomicLong()

    // Reader-thread state. The overflow warning is rate-limited because the reader is the hot
    // path: one line per dropped datagram is how a log gets to a gigabyte in a minute.
    private var droppedDatagrams = 0L
    private var lastOverflowLogMs = 0L

    // Packet-pump state, rate-limited for the same reason.
    private var malformedPppFrames = 0L
    private var lastMalformedLogMs = 0L

    /** Set by the connect watchdog so the failure can be attributed to the phase that stalled. */
    @Volatile private var stalledIn: TunnelState? = null

    /**
     * Ends the connect watchdog, and decides the race between it and a connect that completes at
     * the same instant. It cannot be inferred from [state]: a connect that fails on its own leaves
     * the state at FAILED and then IDLE, neither of which is CONNECTED, so a watchdog keyed off
     * the state would go on polling — and finally condemn — a tunnel that is already gone.
     */
    private val connectSettled = AtomicBoolean(false)

    @Volatile private var natTraversal = false
    private lateinit var serverAddress: InetAddress
    private lateinit var ikeEndpoint: InetSocketAddress
    private lateinit var natTEndpoint: InetSocketAddress

    // ---------------------------------------------------------------- security associations
    //
    // Rekeying means two generations of SA are alive at once for a short while, so everything here
    // comes in a current/previous pair. Only the maintenance thread writes them; the reader and
    // uplink threads read the volatile references, which is why an SA object is never mutated in
    // place once published.

    private val ikeRekeys = AtomicLong()
    private val ipsecRekeys = AtomicLong()

    /**
     * Serialises every use of a negotiator: rekeys run on the maintenance thread, teardown does
     * not. It is a [ReentrantLock] rather than a monitor because the teardown must be able to give
     * up on it — see [sendPoliteIkeTeardown].
     */
    private val ikeLock = ReentrantLock()

    /**
     * Serialises the outbound ESP path. Two threads send through it — the uplink thread forwarding
     * TUN traffic and the packet pump flushing PPP and L2TP control frames — and an
     * [EspOutboundSa] holds a single `Mac`, so letting both in at once yields an ICV computed over
     * an interleaving of two packets, which the peer silently drops.
     */
    private val sendLock = Any()

    @Volatile private var ikeTransport: SocketIkeTransport? = null
    @Volatile private var ike: IkeContext? = null
    @Volatile private var previousIke: IkeContext? = null
    @Volatile private var previousIkeExpiresAtMs = 0L

    @Volatile private var phase2: Phase2Result? = null
    @Volatile private var espIn: EspInboundSa? = null
    @Volatile private var espOut: EspOutboundSa? = null
    @Volatile private var previousPhase2: Phase2Result? = null
    @Volatile private var previousEspIn: EspInboundSa? = null
    @Volatile private var previousEspExpiresAtMs = 0L
    @Volatile private var phase2RekeyAtMs = Long.MAX_VALUE

    // One failure streak per phase, so a couple of failed IPsec attempts cannot eat the ISAKMP
    // budget or the other way round: three failures of *one* SA mean the peer has stopped playing,
    // three failures spread over both mean very little. Maintenance thread only.
    private var ipsecRekeyFailures = 0
    private var isakmpRekeyFailures = 0

    /** Raised by the maintenance thread; the packet pump turns it into the tunnel's failure. */
    @Volatile private var maintenanceFailure: TunnelException? = null

    private val rekeyJitter = java.util.Random()

    /** One ISAKMP SA and the negotiator that owns its cookies and keys. */
    private class IkeContext(
        val negotiator: IkeV1Negotiator,
        val phase1: Phase1Result,
        /** Only the maintenance thread reads or writes this, to back a failed rekey off. */
        var rekeyAtMs: Long,
    ) {
        fun owns(header: IsakmpHeader): Boolean =
            header.initiatorCookie.contentEquals(phase1.initiatorCookie) &&
                header.responderCookie.contentEquals(phase1.responderCookie)
    }

    fun run() {
        try {
            connectAndPump()
        } catch (e: TunnelException) {
            log.e("tunnel failed: ${e.message}", e)
            setState(TunnelState.FAILED, e.message)
            listener.onFailed(e.kind, e.message ?: e.kind.name, e)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            log.i("tunnel interrupted")
        } catch (e: Exception) {
            // A stalled connect surfaces here as whatever I/O error the watchdog's socket close
            // produced, which says nothing useful. Report the phase that actually stopped making
            // progress instead — that is the difference between "check your PSK" and "check your
            // password".
            val stalled = stalledIn
            if (stalled != null) {
                val message = stallMessage(stalled)
                log.e(message)
                setState(TunnelState.FAILED, message)
                listener.onFailed(kindForStall(stalled), message, e)
            } else {
                // An I/O error that is not a stall is the socket itself refusing to carry the
                // traffic — no route, no network, an ICMP port-unreachable. Saying INTERNAL for
                // that sends the user looking at their credentials instead of at their signal.
                val kind = if (e is IOException) TunnelErrorKind.NETWORK_UNREACHABLE else TunnelErrorKind.INTERNAL
                log.e("unexpected tunnel error", e)
                setState(TunnelState.FAILED, e.message)
                listener.onFailed(kind, e.message ?: e.javaClass.simpleName, e)
            }
        } finally {
            shutdown()
            listener.onDisconnected()
        }
    }

    /** Idempotent and safe to call from any thread. */
    fun stop() {
        if (!stopRequested.compareAndSet(false, true)) return
        log.i("stop requested")
        // Closing the TUN is what unblocks the uplink thread, which is parked in a read that no
        // timeout will ever interrupt. The socket is deliberately left open: the control thread
        // still has to push PPP Terminate, L2TP CDN/StopCCN and the ISAKMP deletes out of it, and
        // without them the server keeps the session alive until its own DPD notices. It closes the
        // socket itself once that is done; the reaper below is only the backstop for a control
        // thread that is wedged somewhere it cannot see the stop flag.
        runCatching { tun?.close() }
        uplinkThread?.interrupt()
        maintenanceThread?.interrupt()
        l2tpQueue.offer(wakeUp)
        // Captured now rather than read from the fields when the reaper fires: two seconds later
        // they may already have been cleared, or in principle repopulated, and the reaper must
        // only ever finish off the socket that was live when the stop was asked for.
        val doomed = socket
        val reader = readerThread
        Thread({
            runCatching { Thread.sleep(SHUTDOWN_GRACE_MS) }
            runCatching { doomed?.close() }
            reader?.interrupt()
        }, "l2tp-vpn-reaper").apply { isDaemon = true }.start()
    }

    // ------------------------------------------------------------------ connection sequence

    private fun connectAndPump() {
        setState(TunnelState.RESOLVING)
        serverAddress = try {
            InetAddress.getByName(config.serverHost)
        } catch (e: UnknownHostException) {
            throw TunnelException(TunnelErrorKind.DNS_FAILURE, "cannot resolve ${config.serverHost}", e)
        }
        ikeEndpoint = InetSocketAddress(serverAddress, config.ikePort)
        natTEndpoint = InetSocketAddress(serverAddress, config.natTraversalPort)

        val sock = socketFactory.open()
        socket = sock
        log.i("socket bound to ${sock.localAddress.hostAddress}:${sock.localPort}, server ${serverAddress.hostAddress}")

        startReaderThread(sock)
        startConnectWatchdog()

        setState(TunnelState.IKE_PHASE1)
        val transport = SocketIkeTransport(sock)
        ikeTransport = transport
        val negotiator = IkeV1Negotiator(config, transport, clock, logger)
        val phase1 = negotiator.establishPhase1()
        ike = IkeContext(negotiator, phase1, rekeyDeadline(phase1.lifetimeSeconds))
        log.i(
            "IKE phase 1 up: ${config.phase1.encryption}/${config.phase1.hash}/${config.phase1.dhGroup}, " +
                "nat local=${phase1.localBehindNat} remote=${phase1.remoteBehindNat} flavor=${phase1.natTraversalFlavor}",
        )
        if (phase1.natTraversalFlavor == NatTraversalFlavor.NONE) {
            throw TunnelException(
                TunnelErrorKind.IPSEC_SA_FAILED,
                "the server did not negotiate NAT traversal; an unrooted Android client can only " +
                    "carry ESP inside UDP/4500",
            )
        }
        checkStop()

        setState(TunnelState.IKE_PHASE2)
        val firstPhase2 = negotiator.establishPhase2(phase1)
        installPhase2(firstPhase2)
        log.i(
            "IPsec SA up: in=0x%08x out=0x%08x %s/%s lifetime=%ds".format(
                firstPhase2.inboundSpi, firstPhase2.outboundSpi, firstPhase2.encryption,
                firstPhase2.integrity, firstPhase2.lifetimeSeconds,
            ),
        )
        checkStop()

        val tunnelMtu = Mtu.tunnelMtu(Mtu.DEFAULT_PATH_MTU, firstPhase2.encryption, firstPhase2.integrity, config.mtu)
        log.i("negotiated tunnel MTU: $tunnelMtu")

        setState(TunnelState.L2TP_TUNNEL)
        val l2tp = L2tpTunnel(
            transport = SocketL2tpTransport(),
            hostName = config.l2tpHostName,
            clock = clock,
            logger = logger,
            helloIntervalMs = config.l2tpHelloIntervalMs,
        )
        val sessionInfo = l2tp.connect(config.connectTimeoutMs)
        setState(TunnelState.L2TP_SESSION)
        log.i(
            "L2TP session up: tunnel ${sessionInfo.localTunnelId}->${sessionInfo.remoteTunnelId} " +
                "session ${sessionInfo.localSessionId}->${sessionInfo.remoteSessionId} peer=${sessionInfo.peerHostName}",
        )
        checkStop()

        setState(TunnelState.PPP_NEGOTIATION)
        val ppp = PppSession(
            username = config.username,
            password = config.password,
            allowedAuth = config.allowedPppAuth,
            requestedMru = tunnelMtu,
            send = { protocol, payload -> sendPppFrame(l2tp, protocol, payload, 0, payload.size) },
            clock = clock,
            logger = logger,
        )
        val pppResult = negotiatePpp(l2tp, ppp)
        log.i("PPP up: ${pppResult.localAddress} peer ${pppResult.remoteAddress} dns=${pppResult.dnsServers}")

        // The header budget is only half the story: the peer also tells us, in LCP, the largest
        // frame it is willing to receive. Handing the TUN anything above that is the classic
        // "ping works but TLS hangs" failure, because only the full-size packets get dropped.
        val effectiveMtu = minOf(tunnelMtu, pppResult.mru)
        if (effectiveMtu != tunnelMtu) {
            log.i("lowering the tunnel MTU from $tunnelMtu to $effectiveMtu; the peer asked for MRU ${pppResult.mru}")
        }

        // A peer that pushes the same resolver twice (Livebox does) would otherwise be installed
        // twice on the system.
        val dns = config.dnsOverride.ifEmpty { pppResult.dnsServers }.distinct()
        val device = tunProvider.establish(
            TunParameters(
                address = pppResult.localAddress,
                prefixLength = 32,
                mtu = effectiveMtu,
                dnsServers = dns,
                blockIpv6 = config.blockIpv6,
            ),
        ) ?: throw TunnelException(TunnelErrorKind.TUN_UNAVAILABLE, "the system refused to create the VPN interface")
        tun = device

        // The watchdog and this thread both want to decide how the connect ended; whoever gets the
        // flag wins. Losing means the deadline expired a heartbeat ago and the socket is being
        // closed underneath us, so announcing a tunnel we cannot keep would be worse than failing.
        if (!connectSettled.compareAndSet(false, true)) {
            throw TunnelException(kindForStall(state), stallMessage(state))
        }
        connectedSinceMs = clock.nowMs()
        setState(TunnelState.CONNECTED)
        listener.onConnected(
            TunnelInfo(
                serverAddress = serverAddress.hostAddress ?: config.serverHost,
                assignedAddress = pppResult.localAddress,
                peerAddress = pppResult.remoteAddress,
                dnsServers = dns,
                mtu = effectiveMtu,
                natDetected = phase1.localBehindNat || phase1.remoteBehindNat,
                udpEncapsulated = firstPhase2.udpEncapsulated,
                phase1Description = "${config.phase1.encryption}/${config.phase1.hash}/${config.phase1.dhGroup}",
                phase2Description = "${firstPhase2.encryption}/${firstPhase2.integrity}" +
                    (config.phase2.pfsGroup?.let { "/$it" } ?: "/no-pfs"),
                pppAuthDescription = pppResult.authProtocolUsed?.name ?: "none",
            ),
        )

        startUplinkThread(l2tp, device, effectiveMtu)
        startMaintenanceThread()
        pumpDownlink(l2tp, ppp, device)
    }

    /** Runs LCP / authentication / IPCP until the session opens, fails, or the deadline expires. */
    private fun negotiatePpp(l2tp: L2tpTunnel, ppp: PppSession): com.arcansecurity.vpn.l2tpipsec.core.ppp.PppResult {
        ppp.start()
        val deadline = clock.nowMs() + config.connectTimeoutMs
        while (!stopRequested.get() && clock.nowMs() < deadline) {
            checkSendAborted()
            val packet = l2tpQueue.poll(100, TimeUnit.MILLISECONDS)
            if (packet != null) {
                when (val received = l2tp.onPacket(packet, 0, packet.size)) {
                    is L2tpTunnel.Received.Data -> deliverPppFrame(packet, received, ppp, device = null)
                    is L2tpTunnel.Received.Closed ->
                        throw TunnelException(TunnelErrorKind.L2TP_FAILED, "peer closed the session: ${received.reason}")
                    else -> Unit
                }
            }
            ppp.tick()
            l2tp.tick()
            ppp.failure?.let { throw it }
            ppp.result?.let { return it }
        }
        checkStop()
        throw TunnelException(TunnelErrorKind.PPP_FAILED, "PPP negotiation timed out in phase ${ppp.phase}")
    }

    // ------------------------------------------------------------------ packet pumps

    /**
     * Bounds the whole establishment, not just the individual layers. Each layer has its own
     * retransmission budget, and a peer that answers phase 1 and then goes quiet would otherwise
     * keep the user on a spinner for the sum of all of them — a wrong pre-shared key, which
     * strongSwan answers with silence rather than a notify, takes over a minute that way.
     */
    private fun startConnectWatchdog() {
        val deadline = clock.nowMs() + config.connectTimeoutMs
        Thread({
            while (!stopRequested.get() && !connectSettled.get()) {
                if (clock.nowMs() >= deadline) {
                    // Losing the flag means the connect completed at this very instant; leave it be.
                    if (!connectSettled.compareAndSet(false, true)) return@Thread
                    stalledIn = state
                    log.w("connect deadline expired in state $state; aborting")
                    runCatching { socket?.close() }
                    return@Thread
                }
                runCatching { Thread.sleep(WATCHDOG_POLL_MS) }
            }
        }, "l2tp-vpn-connect-watchdog").apply { isDaemon = true }.start()
    }

    private fun startReaderThread(sock: UdpSocketChannel) {
        val thread = Thread({
            val buffer = ByteArray(4096)
            var consecutiveFailures = 0
            while (!stopRequested.get()) {
                val datagram = try {
                    sock.receive(buffer, READER_TIMEOUT_MS).also { consecutiveFailures = 0 }
                } catch (e: Exception) {
                    // The socket is closed underneath us on the way out — by the reaper, by the
                    // final shutdown, or by the connect watchdog. A closed descriptor fails
                    // instantly and forever, so retrying it is a hot spin that buries the log and
                    // pins a core; there is nothing left to read either way, so leave.
                    if (stopRequested.get() || stalledIn != null) break
                    if (++consecutiveFailures >= MAX_CONSECUTIVE_READ_FAILURES) {
                        log.e("abandoning the socket after $consecutiveFailures failed reads", e)
                        break
                    }
                    log.w("socket read failed", e)
                    continue
                } ?: continue
                try {
                    dispatchInbound(buffer, datagram.length)
                } catch (e: Exception) {
                    log.w("dropping malformed inbound datagram", e)
                }
            }
            log.d { "reader thread finished" }
        }, "l2tp-vpn-reader")
        thread.isDaemon = true
        readerThread = thread
        thread.start()
    }

    private fun dispatchInbound(buffer: ByteArray, length: Int) {
        if (length <= 0) return
        if (!natTraversal) {
            // Before the float to UDP/4500 everything arriving is a bare ISAKMP message.
            if (!ikeQueue.offer(buffer.copyOf(length))) onQueueOverflow("IKE")
            return
        }
        when (UdpEncapsulation.classify(buffer, 0, length)) {
            UdpEncapsulation.Kind.KEEPALIVE -> Unit
            UdpEncapsulation.Kind.IKE -> {
                val marker = UdpEncapsulation.NON_ESP_MARKER.size
                if (!ikeQueue.offer(buffer.copyOfRange(marker, length))) onQueueOverflow("IKE")
            }
            UdpEncapsulation.Kind.ESP -> {
                // During a rekey two inbound SAs are live, so the SPI in the ESP header — not
                // "whichever one is current" — decides which keys to use.
                val sa = inboundSaFor(spiOf(buffer)) ?: run {
                    log.d { "dropping ESP for unknown SPI 0x${Integer.toHexString(spiOf(buffer))}" }
                    return
                }
                val decapsulated = try {
                    sa.decapsulate(buffer, 0, length)
                } catch (e: EspException) {
                    log.d { "dropping ESP packet: ${e.message}" }
                    return
                }
                val udp = UdpDatagram.parse(decapsulated.payload)
                if (udp.destinationPort != config.l2tpPort) {
                    log.d { "dropping inner datagram for port ${udp.destinationPort}" }
                    return
                }
                bytesIn.addAndGet(length.toLong())
                packetsIn.incrementAndGet()
                maybePublishStats()
                val l2tpPacket = decapsulated.payload.copyOfRange(udp.payloadOffset, udp.payloadOffset + udp.payloadLength)
                if (!l2tpQueue.offer(l2tpPacket)) onQueueOverflow("L2TP")
            }
            UdpEncapsulation.Kind.UNKNOWN -> log.d { "dropping unrecognised datagram of $length bytes" }
        }
    }

    /** Reader thread only, hence the plain fields. */
    private fun onQueueOverflow(queue: String) {
        droppedDatagrams++
        val now = clock.nowMs()
        if (now - lastOverflowLogMs < OVERFLOW_LOG_PERIOD_MS) return
        lastOverflowLogMs = now
        log.w("the inbound $queue queue is full; $droppedDatagrams datagrams dropped so far")
    }

    /**
     * The SPI of an ESP packet. It is an opaque 32-bit value, kept signed all the way through so
     * that it compares exactly against [EspInboundSa.spi], which is decoded the same way; the four
     * bytes are guaranteed to be there because only [UdpEncapsulation.Kind.ESP] gets here.
     */
    private fun spiOf(packet: ByteArray): Int =
        ((packet[0].toInt() and 0xFF) shl 24) or ((packet[1].toInt() and 0xFF) shl 16) or
            ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF)

    private fun inboundSaFor(spi: Int): EspInboundSa? =
        espIn?.takeIf { it.spi == spi } ?: previousEspIn?.takeIf { it.spi == spi }

    private fun startUplinkThread(l2tp: L2tpTunnel, device: TunInterface, mtu: Int) {
        val thread = Thread({
            val ipPacket = ByteArray(mtu + 128)
            val pppScratch = ByteArray(mtu + 256)
            while (!stopRequested.get()) {
                val length = try {
                    device.readPacket(ipPacket)
                } catch (e: Exception) {
                    if (stopRequested.get()) break
                    log.w("TUN read failed", e)
                    break
                }
                if (length <= 0) break
                try {
                    val pppLength = PppFrame.encodeInto(pppScratch, 0, PppProtocol.IPV4, ipPacket, 0, length)
                    sendL2tpPayload(l2tp.encodePppFrame(pppScratch, 0, pppLength))
                } catch (e: Exception) {
                    if (stopRequested.get()) break
                    log.w("failed to forward an outbound packet", e)
                }
            }
            log.d { "uplink thread finished" }
        }, "l2tp-vpn-uplink")
        thread.isDaemon = true
        uplinkThread = thread
        thread.start()
    }

    private fun pumpDownlink(
        l2tp: L2tpTunnel,
        ppp: PppSession,
        device: TunInterface,
    ) {
        while (!stopRequested.get()) {
            // Sleep until PPP or L2TP actually has something due — an open session with nothing
            // outstanding is twenty seconds away from its next LCP echo — while an inbound packet
            // or a `wakeUp` still returns immediately. Ticking on a fixed period instead was most
            // of what the app cost in battery.
            val wait = (minOf(l2tp.nextDeadlineMs(), ppp.nextDeadlineMs()) - clock.nowMs())
                .coerceIn(0L, MAX_PUMP_WAIT_MS)
            val packet = l2tpQueue.poll(wait, TimeUnit.MILLISECONDS)
            if (packet != null && packet !== wakeUp) {
                when (val received = l2tp.onPacket(packet, 0, packet.size)) {
                    is L2tpTunnel.Received.Data -> deliverPppFrame(packet, received, ppp, device)
                    // Reported by throwing rather than by calling the listener from here: one
                    // failure path means the state and the callback cannot disagree, and cannot
                    // both fire.
                    is L2tpTunnel.Received.Closed ->
                        throw TunnelException(TunnelErrorKind.PEER_DISCONNECTED, received.reason)
                    else -> Unit
                }
            }

            maintenanceFailure?.let { throw it }
            ppp.tick()
            l2tp.tick()
            ppp.failure?.let { throw it }
            if (!ppp.isOpen) throw TunnelException(TunnelErrorKind.PPP_FAILED, "PPP went down (phase ${ppp.phase})")
        }
        // A clean stop: unwind the stack politely so the server frees its resources immediately.
        runCatching { ppp.terminate("client shutdown") }
        runCatching { l2tp.close() }
        sendPoliteIkeTeardown()
    }

    /**
     * Deletes both the superseded and the current IPsec SA, then the ISAKMP SA.
     *
     * The wait for the negotiator is bounded: a rekey holds it for as long as its retransmission
     * budget lasts, and blocking here for that long would push the Delete out after the reaper had
     * already closed the socket — which is the whole failure the grace period exists to avoid,
     * since a peer that never sees it keeps the dead session and ignores the next SCCRQ.
     */
    private fun sendPoliteIkeTeardown() {
        val context = ike ?: return
        val acquired = runCatching { ikeLock.tryLock(TEARDOWN_LOCK_WAIT_MS, TimeUnit.MILLISECONDS) }
            .getOrDefault(false)
        if (!acquired) {
            log.w("a rekey still holds the negotiator; leaving without sending the ISAKMP deletes")
            return
        }
        try {
            runCatching {
                previousPhase2?.let { context.negotiator.sendEspDelete(context.phase1, it.inboundSpi) }
                context.negotiator.sendDeleteNotifications(context.phase1, phase2)
            }
        } finally {
            ikeLock.unlock()
        }
    }

    /**
     * Parses and dispatches one inbound PPP frame.
     *
     * A malformed frame is dropped, never thrown: this runs on the packet pump, and letting a runt
     * out of here would tear down a working tunnel over a single corrupt datagram. The layer below
     * already drops malformed L2TP the same way. The TUN write is deliberately left uncovered — a
     * TUN that will not take a packet is gone, and the pump should stop.
     *
     * [device] is null while PPP is still negotiating, when there is nowhere to put user traffic
     * yet; such a packet goes to the session, which ignores protocols it does not handle.
     */
    private fun deliverPppFrame(
        packet: ByteArray,
        received: L2tpTunnel.Received.Data,
        ppp: PppSession,
        device: TunInterface?,
    ) {
        val frame = try {
            PppFrame.parse(packet, received.offset, received.length)
        } catch (e: Exception) {
            onMalformedPppFrame(e)
            return
        }
        if (device != null && frame.protocol == PppProtocol.IPV4) {
            device.writePacket(packet, frame.payloadOffset, frame.payloadLength)
            return
        }
        try {
            ppp.onFrame(frame.protocol, packet, frame.payloadOffset, frame.payloadLength)
        } catch (e: Exception) {
            onMalformedPppFrame(e)
        }
    }

    /** Packet pump only, hence the plain fields; rate-limited for the same reason as the reader's. */
    private fun onMalformedPppFrame(error: Exception) {
        malformedPppFrames++
        val now = clock.nowMs()
        if (now - lastMalformedLogMs < OVERFLOW_LOG_PERIOD_MS) return
        lastMalformedLogMs = now
        log.w("dropped a malformed PPP frame ($malformedPppFrames so far): ${error.message}")
    }

    // ------------------------------------------------------------------ rekeying

    /**
     * Owns everything ISAKMP once the tunnel is up: the inbound IKE queue, both rekey schedules,
     * and the retirement of superseded SAs.
     *
     * It is a thread of its own because a rekey blocks on the peer for a round trip or three, and
     * doing that on the packet pump would stall user traffic — and because the pump owns the PPP
     * and L2TP state machines, which are explicitly single-threaded.
     */
    private fun startMaintenanceThread() {
        val thread = Thread({
            var lastKeepalive = clock.nowMs()
            while (!stopRequested.get() && maintenanceFailure == null) {
                try {
                    drainIkeQueue()
                    val now = clock.nowMs()
                    considerRekeys(now)
                    retireSupersededSas(now)
                    if (now - lastKeepalive >= config.natKeepaliveIntervalMs) {
                        sendNatKeepalive()
                        lastKeepalive = now
                    }
                    // Blocks on the queue rather than sleeping a fixed period: an inbound ISAKMP
                    // message wakes it at once, and otherwise it stays asleep until something is
                    // genuinely due. The cap is a safety net for an interrupt that never arrives.
                    val wait = (nextMaintenanceDeadlineMs(lastKeepalive) - clock.nowMs())
                        .coerceIn(MIN_MAINTENANCE_WAIT_MS, MAX_MAINTENANCE_WAIT_MS)
                    ikeQueue.poll(wait, TimeUnit.MILLISECONDS)?.let { handleIkeMessage(it) }
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    break
                } catch (e: TunnelException) {
                    maintenanceFailure = e
                    // The pump reports it, and it may be asleep for a while yet.
                    l2tpQueue.offer(wakeUp)
                } catch (e: Exception) {
                    if (stopRequested.get()) break
                    log.w("maintenance pass failed", e)
                }
            }
            log.d { "maintenance thread finished" }
        }, "l2tp-vpn-maintenance")
        thread.isDaemon = true
        maintenanceThread = thread
        thread.start()
    }

    /**
     * Dispatches every inbound ISAKMP message to the negotiator that owns its SA.
     *
     * Messages a rekey handed back come first: they arrived before anything still on [ikeQueue],
     * and a Delete must not be applied out of order with the exchange that followed it.
     */
    private fun drainIkeQueue() {
        while (!stopRequested.get()) {
            handleIkeMessage(deferredIkeQueue.poll() ?: ikeQueue.poll() ?: return)
        }
    }

    private fun handleIkeMessage(message: ByteArray) {
        val header = try {
            IsakmpHeader.decode(message)
        } catch (e: Exception) {
            log.w("dropping a malformed ISAKMP datagram", e)
            return
        }
        val context = ike?.takeIf { it.owns(header) } ?: previousIke?.takeIf { it.owns(header) }
        if (context == null) {
            log.w("dropping an ISAKMP message for an SA we do not know")
            return
        }
        try {
            when (header.exchangeType) {
                ExchangeType.INFORMATIONAL -> applyInformational(context, message)
                ExchangeType.QUICK_MODE -> answerPeerQuickMode(context, message)
                else -> log.w("ignoring an unsolicited exchange of type ${header.exchangeType}")
            }
        } catch (e: TunnelException) {
            throw e
        } catch (e: Exception) {
            log.w("could not process an inbound ISAKMP message", e)
        }
    }

    /**
     * The next moment the maintenance thread actually has work: a rekey, the retirement of a
     * superseded SA, or a NAT keepalive.
     *
     * Sleeping until then rather than polling on a fixed period is what lets the CPU reach deep
     * idle. A tunnel that is up but carrying nothing should cost almost nothing, and the keepalive
     * is the floor the protocol imposes.
     */
    private fun nextMaintenanceDeadlineMs(lastKeepaliveMs: Long): Long {
        var next = lastKeepaliveMs + config.natKeepaliveIntervalMs
        if (config.rekeyEnabled) {
            next = minOf(next, phase2RekeyAtMs)
            ike?.let { next = minOf(next, it.rekeyAtMs) }
        }
        if (previousPhase2 != null) next = minOf(next, previousEspExpiresAtMs)
        if (previousIke != null) next = minOf(next, previousIkeExpiresAtMs)
        return next
    }

    private fun applyInformational(context: IkeContext, message: ByteArray) {
        val result = ikeLock.withLock { context.negotiator.handleInformational(context.phase1, message) }
        result.deletedEspSpis.forEach(::onPeerDeletedIpsecSa)
        if (result.isakmpDeleted && context === ike) {
            // Losing the ISAKMP SA does not by itself break ESP, but it leaves us unable to rekey
            // or to tear anything down cleanly, so build a fresh one immediately.
            log.w("peer deleted the ISAKMP SA; renegotiating phase 1")
            rekeyPhase1()
        }
    }

    /** A Delete names the sender's inbound SPIs, which are the ones we send on. */
    private fun onPeerDeletedIpsecSa(spi: Int) {
        val superseded = previousPhase2
        if (superseded != null && (superseded.outboundSpi == spi || superseded.inboundSpi == spi)) {
            log.i("peer retired the superseded IPsec SA 0x${Integer.toHexString(spi)}")
            previousPhase2 = null
            previousEspIn = null
            return
        }
        val current = phase2 ?: return
        if (current.outboundSpi == spi || current.inboundSpi == spi) {
            log.w("peer deleted the IPsec SA we are using; rekeying now")
            phase2RekeyAtMs = 0
        } else {
            log.d { "peer deleted an IPsec SA we do not have: 0x${Integer.toHexString(spi)}" }
        }
    }

    private fun answerPeerQuickMode(context: IkeContext, message: ByteArray) {
        val result = ikeLock.withLock {
            context.negotiator.respondToQuickMode(context.phase1, message)
        } ?: return
        requireUdpEncapsulated(result)
        installPhase2(result)
        // The streak counts consecutive failures to replace this SA, whoever started the exchange:
        // without this a couple of failed attempts of our own would still be held against us long
        // after the peer had rekeyed successfully on its own schedule.
        ipsecRekeyFailures = 0
        ipsecRekeys.incrementAndGet()
        log.i(
            "IPsec SA rekeyed by the peer: in=0x%08x out=0x%08x".format(result.inboundSpi, result.outboundSpi),
        )
    }

    private fun considerRekeys(now: Long) {
        if (!config.rekeyEnabled) return
        val exhausted = espOut?.exhausted == true
        if (exhausted || now >= phase2RekeyAtMs) {
            rekeyPhase2(if (exhausted) "ESP sequence space nearly exhausted" else "lifetime")
        }
        val context = ike ?: return
        if (now >= context.rekeyAtMs) rekeyPhase1()
    }

    private fun rekeyPhase2(reason: String) {
        val context = ike ?: return
        log.i("rekeying the IPsec SA ($reason)")
        val result = try {
            ikeLock.withLock { context.negotiator.establishPhase2(context.phase1) }
        } catch (e: Exception) {
            onRekeyFailure(RekeySubject.IPSEC, e)
            return
        }
        requireUdpEncapsulated(result)
        installPhase2(result)
        ipsecRekeyFailures = 0
        ipsecRekeys.incrementAndGet()
        log.i("IPsec SA rekeyed: in=0x%08x out=0x%08x".format(result.inboundSpi, result.outboundSpi))
    }

    /**
     * Renegotiates the ISAKMP SA with a brand-new negotiator, because the cookies and the whole key
     * schedule belong to one SA and cannot be reused. The old context stays reachable for a moment
     * so a delete or a DPD ack that is already in flight still decrypts.
     *
     * This blocks the maintenance thread for the few round trips a Main Mode takes, and that thread
     * is the only consumer of [ikeQueue], so the new negotiator drains the queue on its behalf for
     * the whole window. Everything it reads and cannot own comes back through
     * [IkeTransport.deferForeignMessage] into [deferredIkeQueue], which the loop below empties as
     * soon as this returns — by which point [ike] and [previousIke] both name the SA they should.
     */
    private fun rekeyPhase1() {
        val old = ike ?: return
        val transport = ikeTransport ?: return
        log.i("rekeying the ISAKMP SA")
        val negotiator = IkeV1Negotiator(config, transport, clock, logger)
        val phase1 = try {
            ikeLock.withLock { negotiator.establishPhase1() }
        } catch (e: Exception) {
            onRekeyFailure(RekeySubject.ISAKMP, e)
            return
        }
        previousIke = old
        previousIkeExpiresAtMs = clock.nowMs() + config.saOverlapMs
        ike = IkeContext(negotiator, phase1, rekeyDeadline(phase1.lifetimeSeconds))
        isakmpRekeyFailures = 0
        ikeRekeys.incrementAndGet()
        log.i("ISAKMP SA rekeyed")
    }

    /** Which schedule a rekey belongs to, so a failure backs off the right one. */
    private enum class RekeySubject(val label: String, val errorKind: TunnelErrorKind) {
        IPSEC("IPsec", TunnelErrorKind.IPSEC_SA_FAILED),
        ISAKMP("ISAKMP", TunnelErrorKind.IKE_NO_RESPONSE),
    }

    private fun onRekeyFailure(subject: RekeySubject, error: Exception) {
        val failures = when (subject) {
            RekeySubject.IPSEC -> ++ipsecRekeyFailures
            RekeySubject.ISAKMP -> ++isakmpRekeyFailures
        }
        log.w("${subject.label} rekey attempt $failures failed: ${error.message}", error)
        if (failures >= MAX_REKEY_FAILURES) {
            maintenanceFailure = TunnelException(
                subject.errorKind,
                "could not rekey the ${subject.label} SA after $failures attempts",
                error,
            )
            return
        }
        // Back off the schedule that actually failed, and stay well inside the remaining lifetime
        // so there is room to try again. Pushing an ISAKMP failure onto the IPsec deadline does
        // both halves of the damage: the ISAKMP attempt is left due, so it is retried on the very
        // next maintenance pass with no back-off at all, and a healthy IPsec SA with most of an
        // hour still to live is replaced for no reason fifteen seconds later.
        val retryAt = clock.nowMs() + REKEY_RETRY_MS
        when (subject) {
            RekeySubject.IPSEC -> phase2RekeyAtMs = retryAt
            RekeySubject.ISAKMP -> ike?.rekeyAtMs = retryAt
        }
    }

    private fun requireUdpEncapsulated(result: Phase2Result) {
        if (!result.udpEncapsulated) {
            throw TunnelException(
                TunnelErrorKind.IPSEC_SA_FAILED,
                "the server selected plain ESP instead of UDP-encapsulated ESP",
            )
        }
    }

    /**
     * Publishes a freshly negotiated SA pair. Outbound switches over at once — that is what the
     * peer expects once it has answered — while the SA being replaced stays valid for inbound
     * traffic until [VpnConfig.saOverlapMs] has passed, so the packets the peer had already put on
     * the wire are not thrown away.
     *
     * The order of the writes is load-bearing, because the reader thread reads [espIn] and
     * [previousEspIn] as two separate volatile loads and must never find the outgoing SA in
     * neither. Demoting it into [previousEspIn] *before* overwriting [espIn] is what guarantees
     * that: a reader that already sees the new [espIn] is, by the ordering of the two volatile
     * writes, guaranteed to see the demoted one too. Publishing the new inbound SA before the new
     * outbound one matters for the same reason on the peer's side — it may already be sending on
     * the new SPI, and it certainly will once we do.
     */
    private fun installPhase2(result: Phase2Result) {
        previousPhase2 = phase2
        previousEspIn = espIn
        previousEspExpiresAtMs = clock.nowMs() + config.saOverlapMs
        espIn = EspInboundSa(
            spi = result.inboundSpi,
            encryption = result.encryption,
            integrity = result.integrity,
            encryptionKey = result.inboundEncryptionKey,
            integrityKey = result.inboundIntegrityKey,
        )
        espOut = EspOutboundSa(
            spi = result.outboundSpi,
            encryption = result.encryption,
            integrity = result.integrity,
            encryptionKey = result.outboundEncryptionKey,
            integrityKey = result.outboundIntegrityKey,
        )
        phase2 = result
        phase2RekeyAtMs = rekeyDeadline(result.lifetimeSeconds)
    }

    private fun retireSupersededSas(now: Long) {
        val old = previousPhase2
        if (old != null && now >= previousEspExpiresAtMs) {
            previousPhase2 = null
            previousEspIn = null
            ike?.let { context ->
                runCatching {
                    ikeLock.withLock { context.negotiator.sendEspDelete(context.phase1, old.inboundSpi) }
                }
            }
            log.i("retired IPsec SA 0x${Integer.toHexString(old.inboundSpi)}")
        }
        val oldIke = previousIke
        if (oldIke != null && now >= previousIkeExpiresAtMs) {
            previousIke = null
            runCatching { ikeLock.withLock { oldIke.negotiator.sendIsakmpDelete(oldIke.phase1) } }
            log.i("retired the superseded ISAKMP SA")
        }
    }

    /**
     * When to start replacing an SA. Peers commonly rekey at around 90% of the lifetime, so going
     * earlier keeps us the initiator, which is the simpler side to be on; the jitter stops two
     * tunnels that came up together from rekeying in lockstep for ever.
     */
    private fun rekeyDeadline(lifetimeSeconds: Int): Long {
        if (!config.rekeyEnabled) return Long.MAX_VALUE
        if (lifetimeSeconds <= 0) {
            // Nothing to schedule against, so the SA runs until the peer gives out. Say so loudly:
            // silently disabling the rekey is how a tunnel comes to die an hour in with no clue in
            // the log as to why.
            log.w("the negotiated lifetime is $lifetimeSeconds s, which is unusable; this SA will never be rekeyed")
            return Long.MAX_VALUE
        }
        val fraction = REKEY_FRACTION_MIN + rekeyJitter.nextDouble() * (REKEY_FRACTION_SPAN)
        val delay = (lifetimeSeconds * 1000L * fraction).toLong().coerceAtLeast(MIN_REKEY_DELAY_MS)
        return clock.nowMs() + delay
    }

    // ------------------------------------------------------------------ send helpers

    /**
     * Wraps an L2TP packet in UDP/1701 and ESP and puts it on the wire.
     *
     * Called from both the uplink thread and the packet pump, hence [sendLock]. The socket send is
     * inside it too, so ESP sequence numbers reach the wire in the order they were allocated and
     * the peer's replay window never has to absorb a reordering we caused ourselves.
     */
    private fun sendL2tpPayload(l2tpPacket: ByteArray) {
        synchronized(sendLock) {
            val sa = espOut ?: return
            val sock = socket ?: return
            val inner = UdpDatagram.encode(config.l2tpPort, config.l2tpPort, l2tpPacket)
            val esp = sa.encapsulate(inner, nextHeader = 17)
            sock.send(esp, 0, esp.size, natTEndpoint)
            bytesOut.addAndGet(esp.size.toLong())
            packetsOut.incrementAndGet()
            maybePublishStats()
        }
    }

    private fun sendPppFrame(l2tp: L2tpTunnel, protocol: Int, payload: ByteArray, offset: Int, length: Int) {
        val frame = PppFrame.encode(protocol, payload, offset, length)
        sendL2tpPayload(l2tp.encodePppFrame(frame))
    }

    /** RFC 3948 section 4: a single 0xFF byte keeps the NAT mapping for UDP/4500 alive. */
    private fun sendNatKeepalive() {
        val sock = socket ?: return
        if (!natTraversal) return
        val payload = UdpEncapsulation.NAT_KEEPALIVE
        runCatching { sock.send(payload, 0, payload.size, natTEndpoint) }
    }

    // ------------------------------------------------------------------ plumbing

    /**
     * The abort signal for the negotiating layers. They each sit in their own retransmission loop
     * and have no idea the tunnel is going away, so the transports they were handed are where a
     * stop request or an expired connect deadline has to become an exception. Relying on the
     * socket close alone is not enough: a socket that merely times out never reports anything, and
     * the layer above would keep retransmitting into the void.
     *
     * Sending stays allowed once a stop is requested, because the polite teardown — PPP Terminate,
     * L2TP CDN/StopCCN, ISAKMP Delete — still has to get out.
     */
    private fun checkReceiveAborted() {
        if (stopRequested.get()) throw InterruptedException("stopped")
        checkSendAborted()
    }

    private fun checkSendAborted() {
        val stalled = stalledIn ?: return
        throw TunnelException(kindForStall(stalled), stallMessage(stalled))
    }

    private fun kindForStall(stalled: TunnelState) = when (stalled) {
        TunnelState.RESOLVING, TunnelState.IKE_PHASE1, TunnelState.IKE_PHASE2 -> TunnelErrorKind.IKE_NO_RESPONSE
        TunnelState.L2TP_TUNNEL, TunnelState.L2TP_SESSION -> TunnelErrorKind.L2TP_FAILED
        TunnelState.PPP_NEGOTIATION -> TunnelErrorKind.PPP_FAILED
        else -> TunnelErrorKind.INTERNAL
    }

    private fun stallMessage(stalled: TunnelState) =
        "the server stopped responding during $stalled (no answer within ${config.connectTimeoutMs / 1000}s)"

    private inner class SocketIkeTransport(private val sock: UdpSocketChannel) : IkeTransport {
        override val localAddress: InetAddress get() = sock.localAddress
        override val localPort: Int get() = sock.localPort
        override val remoteAddress: InetAddress get() = serverAddress
        override val natTraversalActive: Boolean get() = natTraversal

        override fun enableNatTraversal() {
            if (!natTraversal) {
                log.i("floating IKE to UDP/${config.natTraversalPort}")
                natTraversal = true
            }
        }

        override fun sendIsakmp(message: ByteArray) {
            checkSendAborted()
            if (natTraversal) {
                val marker = UdpEncapsulation.NON_ESP_MARKER
                val framed = ByteArray(marker.size + message.size)
                System.arraycopy(marker, 0, framed, 0, marker.size)
                System.arraycopy(message, 0, framed, marker.size, message.size)
                sock.send(framed, 0, framed.size, natTEndpoint)
            } else {
                sock.send(message, 0, message.size, ikeEndpoint)
            }
        }

        override fun receiveIsakmp(timeoutMs: Int): ByteArray? {
            checkReceiveAborted()
            return ikeQueue.poll(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
        }

        override fun deferForeignMessage(message: ByteArray) {
            // Bounded and dropped on overflow rather than blocked on: the only thread that empties
            // this is the very thread a rekey is blocking, so waiting for room here would deadlock
            // the tunnel outright.
            if (!deferredIkeQueue.offer(message)) {
                log.w("dropping an ISAKMP message for a superseded SA; the deferred queue is full")
            }
        }
    }

    private inner class SocketL2tpTransport : L2tpTransport {
        override fun send(packet: ByteArray, offset: Int, length: Int) {
            checkSendAborted()
            sendL2tpPayload(if (offset == 0 && length == packet.size) packet else packet.copyOfRange(offset, offset + length))
        }

        override fun receive(timeoutMs: Int): ByteArray? {
            checkReceiveAborted()
            return l2tpQueue.poll(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
        }
    }

    /**
     * Publishes the counters at most once a second, from whichever thread has just moved them.
     *
     * The pump used to do this on a timer, which meant waking every second for the whole life of
     * the tunnel to republish an identical snapshot. A counter only changes when a packet moves,
     * and the thread that moved it is already awake.
     */
    private fun maybePublishStats() {
        val now = clock.nowMs()
        val last = lastStatsAtMs.get()
        if (now - last < STATS_INTERVAL_MS) return
        if (!lastStatsAtMs.compareAndSet(last, now)) return
        listener.onStats(stats)
    }

    private fun setState(next: TunnelState, detail: String? = null) {
        state = next
        listener.onStateChanged(next, detail)
    }

    private fun checkStop() {
        if (stopRequested.get()) throw InterruptedException("stopped")
    }

    private fun shutdown() {
        // A tunnel that failed keeps FAILED as its terminal state: `state` is what a caller polls,
        // and overwriting it with IDLE leaves it with no record of why the tunnel went away.
        val failed = state == TunnelState.FAILED
        setState(TunnelState.DISCONNECTING)
        // Nothing else raises the flag when the tunnel dies on its own rather than being stopped,
        // and without it the maintenance thread and the connect watchdog outlive run() — the
        // maintenance thread for good, waking every 250 ms to poll a socket that is already shut.
        stopRequested.set(true)
        connectSettled.set(true)
        runCatching { tun?.close() }
        runCatching { socket?.close() }
        tun = null
        socket = null
        readerThread?.interrupt()
        uplinkThread?.interrupt()
        maintenanceThread?.interrupt()
        state = if (failed) TunnelState.FAILED else TunnelState.IDLE
    }

    private companion object {
        /** How long the socket outlives a stop request so the teardown messages can leave. */
        const val SHUTDOWN_GRACE_MS = 2_000L

        /** How long the teardown waits for a rekey to let go of the negotiator. */
        const val TEARDOWN_LOCK_WAIT_MS = 500L

        /** A healthy socket does not fail repeatedly; past this the reader gives up rather than spin. */
        const val MAX_CONSECUTIVE_READ_FAILURES = 16

        /**
         * How long the reader blocks before merely re-checking the stop flag. It can be this long
         * because what actually unblocks it is the socket being closed, by `stop()` or by the
         * connect watchdog; the timeout is only a safety net.
         */
        const val READER_TIMEOUT_MS = 30_000

        /** Upper bound on a maintenance sleep, so a missed interrupt cannot wedge the thread. */
        const val MAX_MAINTENANCE_WAIT_MS = 30_000L

        /** Floor, so a deadline that is already in the past cannot turn the loop into a spin. */
        const val MIN_MAINTENANCE_WAIT_MS = 50L

        /**
         * Upper bound on a pump sleep. The pump is normally woken by a packet or by `wakeUp`; this
         * only bounds how long a lost wake-up could go unnoticed.
         */
        const val MAX_PUMP_WAIT_MS = 30_000L

        const val STATS_INTERVAL_MS = 1_000L
        const val WATCHDOG_POLL_MS = 200L

        /** Floor between two "inbound queue full" warnings; the reader is the hot path. */
        const val OVERFLOW_LOG_PERIOD_MS = 1_000L

        /** Rekey somewhere in 75%..85% of the negotiated lifetime. */
        const val REKEY_FRACTION_MIN = 0.75
        const val REKEY_FRACTION_SPAN = 0.10
        const val MIN_REKEY_DELAY_MS = 10_000L
        const val REKEY_RETRY_MS = 15_000L
        const val MAX_REKEY_FAILURES = 3
    }
}
