package kittoku.osc.l2tp

import android.net.VpnService
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.Datagram
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.UdpSocketChannel
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.UdpSocketFactory
import com.arcansecurity.vpn.l2tpipsec.core.util.Log
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import java.util.Collections

/**
 * Opens the UDP sockets the IKE/ESP/L2TP stack talks to the concentrator through.
 *
 * Two things here are load-bearing:
 *
 *  * **`VpnService.protect(socket)`.** Without it the tunnel's own packets would be routed back
 *    into the TUN interface the moment it is established, and the connection would deadlock in a
 *    routing loop. Every socket this factory hands out is protected before it is used, and a
 *    refusal is treated as fatal rather than silently ignored.
 *  * **A real [UdpSocketChannel.localAddress].** The socket is bound to the wildcard address so
 *    the kernel can pick the source per destination, which means `socket.localAddress` is
 *    `0.0.0.0`. The IKE identity payload and both NAT-D hashes are computed over the local
 *    address, so a wildcard would make the peer's NAT detection nonsense. We therefore probe the
 *    routing table with a throwaway connected socket — a UDP `connect` sends nothing, it only
 *    resolves the route — and report the address of the interface that actually reaches the peer.
 */
class AndroidUdpSocketFactory @JvmOverloads constructor(
    private val service: VpnService,
    /** Resolved peer address, used to pick the outgoing interface. */
    private val serverAddress: InetAddress? = null,
    private val logger: VpnLogger = VpnLogger.NONE,
) : UdpSocketFactory {

    private val log = Log(TAG, logger)
    private val openSockets = Collections.synchronizedSet(mutableSetOf<DatagramSocket>())

    @Volatile
    private var cachedLocalAddress: InetAddress? = null

    /** The source address the stack will appear to come from. Never `0.0.0.0`. */
    val localAddress: InetAddress get() = resolveLocalAddress()

    override fun open(): UdpSocketChannel {
        val socket = DatagramSocket(null).apply {
            reuseAddress = true
            bind(InetSocketAddress(0))
        }
        if (!service.protect(socket)) {
            socket.close()
            throw IOException(
                "VpnService.protect() refused the socket; refusing to continue, its traffic " +
                    "would be routed back into the tunnel",
            )
        }
        openSockets += socket
        val local = resolveLocalAddress()
        log.d { "Opened protected UDP socket ${local.hostAddress}:${socket.localPort}" }
        return ProtectedUdpSocket(socket, local) { openSockets -= socket }
    }

    /**
     * Closes every socket handed out so far.
     *
     * A blocking `DatagramSocket.receive` cannot be interrupted; closing the socket underneath it
     * is the only way to make the tunnel thread return promptly when the user hits Disconnect or
     * the default network changes.
     */
    fun closeAll() {
        // Snapshot and clear under one lock. Clearing afterwards would also drop a socket that
        // open() added in between, and a socket we no longer track is a leaked file descriptor.
        val sockets = synchronized(openSockets) {
            val snapshot = openSockets.toList()
            openSockets.clear()
            snapshot
        }
        sockets.forEach { runCatching { it.close() } }
    }

    private fun resolveLocalAddress(): InetAddress {
        cachedLocalAddress?.let { return it }
        val resolved = probeRouteToPeer() ?: firstUsableInterfaceAddress() ?: LOOPBACK
        cachedLocalAddress = resolved
        log.i("Local address for this tunnel: ${resolved.hostAddress}")
        return resolved
    }

    /**
     * Asks the kernel which source address it would use to reach the peer. `connect` on a UDP
     * socket is a purely local operation: no packet leaves the device.
     */
    private fun probeRouteToPeer(): InetAddress? {
        val fallbackTarget = runCatching { InetAddress.getByName(ROUTE_PROBE_HOST) }.getOrNull()
        val target = serverAddress ?: fallbackTarget ?: return null
        return try {
            DatagramSocket().use { probe ->
                // Protect it too: during a reconnect the old TUN may still be up, and an
                // unprotected probe would resolve its route through tun0 and report the tunnel's
                // own address.
                //
                // A refusal is handled differently from open(), and deliberately. open() must fail
                // hard because its socket carries the IKE, ESP and L2TP traffic, and an unprotected
                // one routes that back into the tunnel it is building. This socket sends nothing at
                // all — a UDP connect() is purely local — so there is no loop to prevent; the only
                // thing at risk is the answer. So we throw the answer away instead of the
                // connection, and let resolveLocalAddress() fall through to its next source rather
                // than hand the IKE identity and both NAT-D hashes an address off the wrong
                // interface, which the peer rejects with nothing in the log to explain why.
                if (!service.protect(probe)) {
                    log.w("VpnService.protect() refused the route probe; discarding its answer")
                    return null
                }
                probe.connect(InetSocketAddress(target, ROUTE_PROBE_PORT))
                probe.localAddress?.takeUnless { it.isAnyLocalAddress || it.isLoopbackAddress }
            }
        } catch (e: Exception) {
            log.w("Could not probe the route to ${target.hostAddress}", e)
            null
        }
    }

    /** Last resort: the first non-loopback IPv4 address of an up interface. */
    private fun firstUsableInterfaceAddress(): InetAddress? = try {
        NetworkInterface.getNetworkInterfaces()
            .asSequence()
            .filter { it.isUp && !it.isLoopback }
            .flatMap { it.inetAddresses.asSequence() }
            .firstOrNull { it is Inet4Address && !it.isLoopbackAddress && !it.isAnyLocalAddress }
    } catch (e: Exception) {
        log.w("Could not enumerate network interfaces", e)
        null
    }

    private companion object {
        const val TAG = "UdpSocket"
        /** Only used to resolve a route when the peer address is not known yet. */
        const val ROUTE_PROBE_HOST = "8.8.8.8"
        const val ROUTE_PROBE_PORT = 53
        val LOOPBACK: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    }
}

/**
 * A [UdpSocketChannel] over a protected [DatagramSocket].
 *
 * `receive` is not reentrant: it reuses one [DatagramPacket] under a lock, which is what the
 * stack's single reader thread wants and cheap enough not to allocate per ESP packet.
 */
private class ProtectedUdpSocket(
    private val socket: DatagramSocket,
    override val localAddress: InetAddress,
    private val onClosed: () -> Unit,
) : UdpSocketChannel {

    private val receivePacket = DatagramPacket(ByteArray(0), 0)
    private var appliedTimeoutMs = -1

    override val localPort: Int get() = socket.localPort

    override fun send(data: ByteArray, offset: Int, length: Int, destination: InetSocketAddress) {
        socket.send(DatagramPacket(data, offset, length, destination))
    }

    override fun receive(buffer: ByteArray, timeoutMs: Int): Datagram? {
        // Java reads a zero timeout as "block forever", which is never what the caller means.
        val timeout = timeoutMs.coerceAtLeast(1)
        return synchronized(receivePacket) {
            // Inside the lock with the rest: appliedTimeoutMs only saves a setsockopt per datagram,
            // and racing it would leave the socket on a timeout nobody asked for.
            if (timeout != appliedTimeoutMs) {
                socket.soTimeout = timeout
                appliedTimeoutMs = timeout
            }
            receivePacket.setData(buffer, 0, buffer.size)
            try {
                socket.receive(receivePacket)
                Datagram(receivePacket.length, receivePacket.socketAddress as InetSocketAddress)
            } catch (e: SocketTimeoutException) {
                null
            }
        }
    }

    override fun close() {
        socket.close()
        onClosed()
    }
}
