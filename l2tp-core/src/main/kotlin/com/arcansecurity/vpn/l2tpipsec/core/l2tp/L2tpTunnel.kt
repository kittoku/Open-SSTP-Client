package com.arcansecurity.vpn.l2tpipsec.core.l2tp

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.Clock
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelErrorKind
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelException
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.Log
import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger

/** What the session hands up/down. The tunnel layer supplies the transport. */
interface L2tpTransport {
    /** Sends one complete L2TP packet (the caller adds UDP/1701 + ESP). */
    fun send(packet: ByteArray, offset: Int = 0, length: Int = packet.size)

    /** Next L2TP packet, or null on timeout. */
    fun receive(timeoutMs: Int): ByteArray?
}

data class L2tpSessionInfo(
    val localTunnelId: Int,
    val remoteTunnelId: Int,
    val localSessionId: Int,
    val remoteSessionId: Int,
    val peerHostName: String?,
)

/**
 * Establishes the control connection (SCCRQ/SCCRP/SCCCN) and one incoming call
 * (ICRQ/ICRP/ICCN), then carries PPP frames.
 *
 * This is the LAC side of RFC 2661: the client dials out, so the *call* is nonetheless an
 * "incoming" one from the LNS's point of view, which is why establishment uses ICRQ and not OCRQ.
 *
 * The instance is not thread-safe. [connect] blocks on the transport; afterwards [onPacket] and
 * [tick] must be driven from the same packet-pump thread. [close] is the one exception and only
 * ever appends to the send path.
 */
class L2tpTunnel(
    private val transport: L2tpTransport,
    private val hostName: String,
    private val clock: Clock = Clock.SYSTEM,
    private val logger: VpnLogger = VpnLogger.NONE,
    private val tunnelSecret: String? = null,
    private val retransmitTimeoutMs: Int = 1_000,
    private val maxRetransmits: Int = 5,
    /** How often [tick] sends a HELLO; it doubles as the liveness probe for the whole tunnel. */
    private val helloIntervalMs: Int = 60_000,
) {
    private val log = Log("l2tp", logger)

    @Volatile
    var info: L2tpSessionInfo? = null
        private set

    private var localTunnelId = 0
    private var remoteTunnelId = 0
    private var localSessionId = 0
    private var remoteSessionId = 0

    /** Sequence number of the next control message we send (RFC 2661 section 5.8). */
    private var ns = 0

    /** Sequence number we expect next from the peer; also the Nr we advertise. */
    private var nr = 0

    /** Set when [nr] advanced and no outgoing message has carried the new value yet. */
    private var ackPending = false

    private var helloDueAtMs = Long.MAX_VALUE
    private var controlConnectionUp = false
    private var sessionUp = false
    private var terminated = false

    /** Control messages sent but not yet acknowledged, oldest first. */
    private val unacked = ArrayDeque<PendingControl>()

    private class PendingControl(
        val ns: Int,
        val sessionId: Int,
        val type: L2tpMessageType,
        val avps: List<L2tpAvp>,
    ) {
        var attempts = 0
        var nextAttemptAtMs = 0L
    }

    /** Runs SCCRQ→SCCRP→SCCCN then ICRQ→ICRP→ICCN. Throws TunnelException(L2TP_FAILED) on failure. */
    fun connect(timeoutMs: Int): L2tpSessionInfo {
        check(info == null && !terminated) { "this L2TP tunnel has already been used" }
        return try {
            establish(timeoutMs)
        } catch (e: ProtocolException) {
            // A peer that answers with something unusable is a tunnel failure, not a bug here.
            throw TunnelException(TunnelErrorKind.L2TP_FAILED, "the LNS sent an unusable message: ${e.message}", e)
        }
    }

    private fun establish(timeoutMs: Int): L2tpSessionInfo {
        val deadline = clock.nowMs() + timeoutMs
        localTunnelId = randomId()
        log.i("opening the L2TP control connection as '$hostName' (tunnel id $localTunnelId)")

        sendControl(
            L2tpMessageType.SCCRQ,
            listOf(
                // Version 1, revision 0: the only value L2TPv2 defines (RFC 2661 section 4.4.3).
                L2tpAvp.u16(L2tpAvpType.ProtocolVersion, 0x0100),
                L2tpAvp.text(L2tpAvpType.HostName, hostName),
                // RFC 2661 section 4.4.5 numbers from the most significant bit: A (async framing)
                // is bit 30 and S (sync framing) bit 31, so 3 claims both and the LNS can never
                // reject us on framing.
                L2tpAvp.u32(L2tpAvpType.FramingCapabilities, 0x0000_0003),
                L2tpAvp.u32(L2tpAvpType.BearerCapabilities, 0x0000_0003),
                L2tpAvp.u16(L2tpAvpType.FirmwareRevision, 0x0001, mandatory = false),
                L2tpAvp.u16(L2tpAvpType.AssignedTunnelId, localTunnelId),
                L2tpAvp.u16(L2tpAvpType.ReceiveWindowSize, RECEIVE_WINDOW),
            ),
        )

        val sccrp = awaitControl(deadline, L2tpMessageType.SCCRP)
        remoteTunnelId = sccrp.avps
            .requireAvp(L2tpAvpType.AssignedTunnelId, "SCCRP")
            .asU16()
        if (remoteTunnelId == 0) throw failure("the LNS assigned tunnel id 0")
        val peerHostName = sccrp.avps.find(L2tpAvpType.HostName)?.asText()
        controlConnectionUp = true
        log.i("LNS '${peerHostName ?: "?"}' accepted the control connection with tunnel id $remoteTunnelId")

        val challenge = sccrp.avps.find(L2tpAvpType.Challenge)?.value
        val sccnAvps = ArrayList<L2tpAvp>(1)
        if (challenge != null) {
            val secret = tunnelSecret
                ?: throw failure(
                    "the LNS requires tunnel authentication but no L2TP tunnel secret is configured",
                )
            // RFC 2661 section 5.1.1: the response authenticates the message it travels in.
            val response = L2tpAuth.challengeResponse(L2tpMessageType.SCCCN, secret, challenge)
            sccnAvps += L2tpAvp.raw(L2tpAvpType.ChallengeResponse, response)
        }
        sendControl(L2tpMessageType.SCCCN, sccnAvps)

        localSessionId = randomId()
        sendControl(
            L2tpMessageType.ICRQ,
            listOf(
                L2tpAvp.u16(L2tpAvpType.AssignedSessionId, localSessionId),
                L2tpAvp.u32(L2tpAvpType.CallSerialNumber, randomCallSerial()),
            ),
        )

        val icrp = awaitControl(deadline, L2tpMessageType.ICRP)
        remoteSessionId = icrp.avps
            .requireAvp(L2tpAvpType.AssignedSessionId, "ICRP")
            .asU16()
        if (remoteSessionId == 0) throw failure("the LNS assigned session id 0")

        sendControl(
            L2tpMessageType.ICCN,
            listOf(
                // We are not a real modem: report a nominal 100 Mbit/s and synchronous framing.
                L2tpAvp.u32(L2tpAvpType.TxConnectSpeed, 100_000_000L),
                L2tpAvp.u32(L2tpAvpType.FramingType, 0x0000_0001),
            ),
            sessionId = remoteSessionId,
        )

        sessionUp = true
        helloDueAtMs = clock.nowMs() + helloIntervalMs
        val established = L2tpSessionInfo(
            localTunnelId = localTunnelId,
            remoteTunnelId = remoteTunnelId,
            localSessionId = localSessionId,
            remoteSessionId = remoteSessionId,
            peerHostName = peerHostName,
        )
        info = established
        log.i("L2TP session established: $established")
        return established
    }

    /** Encodes a PPP frame as an L2TP data message ready to hand to the ESP layer. */
    fun encodePppFrame(ppp: ByteArray, offset: Int = 0, length: Int = ppp.size): ByteArray {
        checkSession()
        return L2tpCodec.encodeData(remoteTunnelId, remoteSessionId, ppp, offset, length)
    }

    fun encodePppFrameInto(out: ByteArray, outOffset: Int, ppp: ByteArray, offset: Int, length: Int): Int {
        checkSession()
        return L2tpCodec.encodeDataInto(out, outOffset, remoteTunnelId, remoteSessionId, ppp, offset, length)
    }

    /**
     * Classifies one received L2TP packet. Data messages for our session yield [Received.Data]
     * (offset/length into the caller's array); control messages are answered internally
     * (ZLB acks, HELLO replies, retransmissions) and yield [Received.Handled] or [Received.Closed].
     */
    sealed interface Received {
        data class Data(val offset: Int, val length: Int) : Received

        data object Handled : Received

        data class Closed(val reason: String) : Received

        data object Ignored : Received
    }

    fun onPacket(packet: ByteArray, offset: Int = 0, length: Int = packet.size): Received {
        val header: L2tpHeader
        val payloadOffset: Int
        try {
            val parsed = L2tpCodec.parseHeader(packet, offset, length)
            header = parsed.first
            payloadOffset = parsed.second
        } catch (e: ProtocolException) {
            log.w("dropping a malformed L2TP packet: ${e.message}")
            return Received.Ignored
        }

        if (!header.isControl) {
            if (info == null || header.tunnelId != localTunnelId || header.sessionId != localSessionId) {
                log.d { "dropping a data message for tunnel ${header.tunnelId}/session ${header.sessionId}" }
                return Received.Ignored
            }
            return Received.Data(payloadOffset, header.payloadLength)
        }

        val avps = try {
            L2tpCodec.parseAvps(packet, payloadOffset, header.payloadLength, tunnelSecret)
        } catch (e: ProtocolException) {
            log.w("dropping a control message with malformed AVPs: ${e.message}")
            return Received.Ignored
        }

        return when (val outcome = handleControl(header, avps)) {
            is ControlOutcome.Message -> {
                // Nothing upstream is waiting for it, so the acknowledgement has to go out now.
                flushAck()
                log.d { "unsolicited ${outcome.type} ignored" }
                Received.Handled
            }

            ControlOutcome.Consumed -> Received.Handled
            ControlOutcome.Dropped -> Received.Ignored
            is ControlOutcome.Terminated -> Received.Closed(outcome.reason)
        }
    }

    /** Called periodically; sends HELLO and retransmits unacked control messages. */
    /**
     * When [tick] would next have something to do, as an absolute [Clock] time, or
     * [Long.MAX_VALUE] when nothing is pending.
     *
     * It exists so the packet pump can sleep until something is genuinely due instead of ticking on
     * a fixed period: an established tunnel carrying nothing has only the HELLO ahead of it, a
     * minute away, and waking the CPU sixty times to discover that is what the battery pays for.
     *
     * Every branch of [tick] must be represented here. Returning a later time than [tick] would act
     * on delays a retransmission; [L2tpDeadlineTest] pins the two together so a new timer cannot be
     * added to one without the other.
     *
     * Call it from the same thread as [tick] — this class is not thread-safe.
     */
    fun nextDeadlineMs(): Long {
        if (terminated) return Long.MAX_VALUE
        // Mirrors tick()'s flushAck. It is unreachable through onPacket today, which acknowledges
        // everything it does not hand upstream before returning — but the contract of this method
        // is to cover every branch of tick(), and keeping the two in step is what stops a future
        // deferred acknowledgement from sitting unsent while the pump sleeps.
        if (ackPending) return 0L
        var next = Long.MAX_VALUE
        unacked.firstOrNull()?.let { next = minOf(next, it.nextAttemptAtMs) }
        if (sessionUp) next = minOf(next, helloDueAtMs)
        return next
    }

    fun tick() {
        if (terminated) return
        val now = clock.nowMs()
        serviceRetransmits(now)
        if (sessionUp && now >= helloDueAtMs) {
            helloDueAtMs = now + helloIntervalMs
            // One HELLO in flight is enough; piling them up would only speed up the give-up.
            if (unacked.none { it.type == L2tpMessageType.HELLO }) {
                sendControl(L2tpMessageType.HELLO, emptyList())
            }
        }
        flushAck()
    }

    /** Sends CDN then StopCCN. Best effort. */
    fun close(reason: String = "client shutdown") {
        if (terminated) return
        terminated = true
        log.i("closing the L2TP tunnel: $reason")
        // Each leg is attempted on its own: a failed CDN must not cost us the StopCCN.
        if (sessionUp) {
            bestEffort {
                transmitOnce(
                    L2tpMessageType.CDN,
                    listOf(
                        resultCode(CDN_ADMINISTRATIVE),
                        L2tpAvp.u16(L2tpAvpType.AssignedSessionId, localSessionId),
                    ),
                    sessionId = remoteSessionId,
                )
            }
        }
        if (controlConnectionUp) {
            bestEffort {
                transmitOnce(
                    L2tpMessageType.StopCCN,
                    listOf(
                        L2tpAvp.u16(L2tpAvpType.AssignedTunnelId, localTunnelId),
                        resultCode(STOPCCN_GENERAL_REQUEST),
                    ),
                )
            }
        }
        sessionUp = false
        controlConnectionUp = false
        unacked.clear()
    }

    /** Largest PPP frame that fits given the payload budget available to the data message. */
    fun maxPppFrameFor(budget: Int): Int = (budget - L2tpCodec.dataHeaderSize(true)).coerceAtLeast(0)

    // ---------------------------------------------------------------- control channel internals

    private class ControlMessage(val type: L2tpMessageType, val avps: List<L2tpAvp>)

    private sealed interface ControlOutcome {
        /** An in-order message of a type we understand, ready for the caller. */
        class Message(val type: L2tpMessageType, val avps: List<L2tpAvp>) : ControlOutcome

        /** Fully dealt with here: a ZLB ack, a duplicate, a HELLO or an unknown message type. */
        data object Consumed : ControlOutcome

        /** Not ours (wrong tunnel id): no state changed. */
        data object Dropped : ControlOutcome

        class Terminated(val reason: String) : ControlOutcome
    }

    /**
     * Waits for [expected], servicing retransmissions and answering everything else that arrives
     * in the meantime. Throws once the deadline passes, the peer tears the tunnel down, or a
     * control message goes unacknowledged too many times.
     */
    private fun awaitControl(deadlineMs: Long, expected: L2tpMessageType): ControlMessage {
        while (true) {
            val now = clock.nowMs()
            if (now >= deadlineMs) throw failure("timed out waiting for $expected")
            serviceRetransmits(now)

            val nextTimer = unacked.firstOrNull()?.nextAttemptAtMs ?: deadlineMs
            val waitMs = (minOf(deadlineMs, nextTimer) - clock.nowMs()).coerceIn(1L, Int.MAX_VALUE.toLong())
            val packet = transport.receive(waitMs.toInt()) ?: continue

            val header: L2tpHeader
            val payloadOffset: Int
            try {
                val parsed = L2tpCodec.parseHeader(packet, 0, packet.size)
                header = parsed.first
                payloadOffset = parsed.second
            } catch (e: ProtocolException) {
                log.w("dropping a malformed L2TP packet: ${e.message}")
                continue
            }
            if (!header.isControl) {
                log.d { "dropping a data message received before the session was established" }
                continue
            }
            val avps = try {
                L2tpCodec.parseAvps(packet, payloadOffset, header.payloadLength, tunnelSecret)
            } catch (e: ProtocolException) {
                log.w("dropping a control message with malformed AVPs: ${e.message}")
                continue
            }

            when (val outcome = handleControl(header, avps)) {
                is ControlOutcome.Message -> {
                    if (outcome.type == expected) return ControlMessage(outcome.type, outcome.avps)
                    // Some LNSes send a HELLO or an SLI mid-handshake; ack it and keep waiting.
                    flushAck()
                    log.d { "ignoring ${outcome.type} while waiting for $expected" }
                }

                is ControlOutcome.Terminated -> throw failure(outcome.reason)
                ControlOutcome.Consumed, ControlOutcome.Dropped -> Unit
            }
        }
    }

    private fun handleControl(header: L2tpHeader, avps: List<L2tpAvp>): ControlOutcome {
        if (header.tunnelId != localTunnelId) {
            log.d { "dropping a control message addressed to tunnel ${header.tunnelId}" }
            return ControlOutcome.Dropped
        }
        // Nr acknowledges everything the peer has received, whatever else the message does.
        processAck(header.nr)

        // A ZLB carries no AVPs and consumes no sequence number (RFC 2661 section 5.8).
        if (avps.isEmpty()) {
            log.d { "<- ZLB ns=${header.ns} nr=${header.nr}" }
            return ControlOutcome.Consumed
        }

        if (header.ns != nr) {
            // Duplicate or out of order: re-acknowledge what we do have and drop it.
            log.d { "out-of-order control message ns=${header.ns}, expecting $nr" }
            sendZlbAck()
            return ControlOutcome.Consumed
        }
        nr = (nr + 1) and SEQ_MASK
        ackPending = true

        val messageTypeAvp = avps.find(L2tpAvpType.MessageType)
        val code = try {
            messageTypeAvp?.asU16()
        } catch (e: ProtocolException) {
            log.w("malformed Message Type AVP: ${e.message}")
            null
        }
        val type = code?.let { L2tpMessageType.of(it) }
        if (type == null) {
            log.w("ignoring control message with unsupported type $code")
            flushAck()
            return ControlOutcome.Consumed
        }
        log.d { "<- $type ns=${header.ns} nr=${header.nr}" }
        // RFC 2661 section 4.2 says an unrecognised AVP with the M bit set must bring the tunnel
        // down. Liveboxes emit mandatory AVPs that are not in the RFC, and losing the connection
        // over one is worse for the user than ignoring it, so it only leaves a trace.
        for (avp in avps) {
            if (avp.mandatory && avp.avpType == null) log.w("ignoring an unknown mandatory AVP in $type: $avp")
        }

        return when (type) {
            L2tpMessageType.StopCCN -> {
                val reason = L2tpResultCodes.describe(type, avps)
                controlConnectionUp = false
                sessionUp = false
                terminated = true
                unacked.clear()
                ControlOutcome.Terminated(reason)
            }

            L2tpMessageType.CDN -> {
                val reason = L2tpResultCodes.describe(type, avps)
                sessionUp = false
                // The control connection survives, so the ack still has to go out.
                flushAck()
                ControlOutcome.Terminated(reason)
            }

            L2tpMessageType.HELLO -> {
                sendZlbAck()
                ControlOutcome.Consumed
            }

            else -> ControlOutcome.Message(type, avps)
        }
    }

    /** Drops every message the peer's Nr covers; sequence numbers are 16-bit and wrap. */
    private fun processAck(peerNr: Int) {
        // Nr is the next Ns the peer expects, so it can never run past the next one we will send.
        // Anything beyond that is a peer bug or a very old duplicate whose Nr has drifted more than
        // half the sequence space away, and honouring it would retire messages the peer never saw:
        // they would then never be retransmitted and the exchange would stall until the deadline.
        if (peerNr != ns && !seqBefore(peerNr, ns)) {
            log.w("ignoring an acknowledgement of nr=$peerNr; we have only sent up to ns=${(ns - 1) and SEQ_MASK}")
            return
        }
        while (true) {
            val head = unacked.firstOrNull() ?: return
            if (!seqBefore(head.ns, peerNr)) return
            unacked.removeFirst()
            log.d { "${head.type} ns=${head.ns} acknowledged" }
        }
    }

    private fun sendControl(type: L2tpMessageType, avps: List<L2tpAvp>, sessionId: Int = 0) {
        val full = ArrayList<L2tpAvp>(avps.size + 1)
        // RFC 2661 section 4.1: the Message Type AVP MUST be the first AVP of the message.
        full += L2tpAvp.u16(L2tpAvpType.MessageType, type.code)
        full += avps
        val pending = PendingControl(ns, sessionId, type, full)
        ns = (ns + 1) and SEQ_MASK
        unacked.addLast(pending)
        pending.nextAttemptAtMs = clock.nowMs() + retransmitTimeoutMs
        transmit(pending)
    }

    /** Sends a control message without arming a retransmission; used for the teardown. */
    private fun transmitOnce(type: L2tpMessageType, avps: List<L2tpAvp>, sessionId: Int = 0) {
        val full = ArrayList<L2tpAvp>(avps.size + 1)
        full += L2tpAvp.u16(L2tpAvpType.MessageType, type.code)
        full += avps
        val packet = L2tpCodec.encodeControl(remoteTunnelId, sessionId, ns, nr, full)
        ns = (ns + 1) and SEQ_MASK
        ackPending = false
        log.d { "-> $type (unacknowledged)" }
        transport.send(packet, 0, packet.size)
    }

    /** (Re)encodes with the current Nr so a retransmission also refreshes the acknowledgement. */
    private fun transmit(pending: PendingControl) {
        val packet = L2tpCodec.encodeControl(remoteTunnelId, pending.sessionId, pending.ns, nr, pending.avps)
        ackPending = false
        log.d { "-> ${pending.type} ns=${pending.ns} nr=$nr" }
        transport.send(packet, 0, packet.size)
    }

    private fun serviceRetransmits(now: Long) {
        val head = unacked.firstOrNull() ?: return
        if (now < head.nextAttemptAtMs) return
        if (head.attempts >= maxRetransmits) {
            throw failure("${head.type} was not acknowledged after $maxRetransmits retransmissions")
        }
        head.attempts++
        head.nextAttemptAtMs = now + backoffMs(head.attempts)
        log.w("retransmitting ${head.type} (attempt ${head.attempts + 1})")
        transmit(head)
    }

    /** Exponential backoff as recommended by RFC 2661 section 5.8, capped so retries stay useful. */
    private fun backoffMs(attempts: Int): Long =
        (retransmitTimeoutMs.toLong() shl minOf(attempts, MAX_BACKOFF_SHIFT)).coerceAtMost(MAX_BACKOFF_MS)

    private fun flushAck() {
        if (ackPending) sendZlbAck()
    }

    /**
     * Zero-Length Body message: a control message with no AVPs whose only job is to carry Nr. It
     * consumes no sequence number and is never retransmitted.
     */
    private fun sendZlbAck() {
        val packet = L2tpCodec.encodeControl(remoteTunnelId, 0, ns, nr, emptyList())
        ackPending = false
        log.d { "-> ZLB ns=$ns nr=$nr" }
        transport.send(packet, 0, packet.size)
    }

    private fun checkSession() {
        check(sessionUp) { "no L2TP session is established" }
    }

    /** The peer may already be gone during teardown; the caller is shutting down regardless. */
    private inline fun bestEffort(block: () -> Unit) {
        try {
            block()
        } catch (e: Exception) {
            log.w("could not send part of the L2TP teardown: ${e.message}", e)
        }
    }

    private fun resultCode(code: Int): L2tpAvp = L2tpAvp.u16(L2tpAvpType.ResultCode, code)

    private fun failure(message: String): TunnelException =
        TunnelException(TunnelErrorKind.L2TP_FAILED, message)

    private fun randomId(): Int {
        val b = Bytes.randomNonZero(2)
        return ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)
    }

    private fun randomCallSerial(): Long {
        val b = Bytes.random(4)
        var v = 0L
        for (x in b) v = (v shl 8) or (x.toLong() and 0xFF)
        return v
    }

    private companion object {
        const val SEQ_MASK = 0xFFFF

        /** Control messages we are willing to buffer; also what we advertise to the LNS. */
        const val RECEIVE_WINDOW = 8

        const val MAX_BACKOFF_SHIFT = 4
        const val MAX_BACKOFF_MS = 16_000L

        const val STOPCCN_GENERAL_REQUEST = 1
        const val CDN_ADMINISTRATIVE = 3

        /** True when [a] precedes [b] in the 16-bit wrapping sequence space. */
        fun seqBefore(a: Int, b: Int): Boolean {
            val diff = (b - a) and SEQ_MASK
            return diff != 0 && diff < 0x8000
        }
    }
}
