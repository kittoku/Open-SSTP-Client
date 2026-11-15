package com.arcansecurity.vpn.l2tpipsec.core.tunnel

import java.io.Closeable
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * The handful of platform services the protocol stack needs. Keeping them behind interfaces is
 * what allows the entire client to run inside JVM unit tests against loopback sockets and an
 * in-memory TUN.
 */

data class Datagram(val length: Int, val source: InetSocketAddress)

/** A UDP socket that bypasses the VPN it is establishing (`VpnService.protect` on Android). */
interface UdpSocketChannel : Closeable {
    val localAddress: InetAddress
    val localPort: Int

    /**
     * Implementations must tolerate concurrent calls: the tunnel sends user traffic, control
     * frames and IKE from three different threads through the one socket it owns. `DatagramSocket`
     * and `DatagramChannel` both satisfy this. [close] may also be called while a [receive] is in
     * flight, and must make that call fail rather than block for ever.
     */
    fun send(data: ByteArray, offset: Int, length: Int, destination: InetSocketAddress)

    /** Blocks for at most [timeoutMs]; returns `null` on timeout. Only one thread receives. */
    fun receive(buffer: ByteArray, timeoutMs: Int): Datagram?
}

fun interface UdpSocketFactory {
    /** Opens a protected socket on an ephemeral local port. */
    fun open(): UdpSocketChannel
}

/** The virtual interface the OS routes traffic through once the tunnel is up. */
interface TunInterface : Closeable {
    /** Blocking read of exactly one IP packet; returns the length, or -1 once closed. */
    fun readPacket(buffer: ByteArray): Int

    fun writePacket(buffer: ByteArray, offset: Int, length: Int)
}

data class TunParameters(
    val address: String,
    val prefixLength: Int,
    val mtu: Int,
    val dnsServers: List<String>,
    val searchDomain: String? = null,
    val blockIpv6: Boolean = true,
)

fun interface TunProvider {
    /** Creates the TUN once PPP has produced an address; returns `null` if the user revoked it. */
    fun establish(params: TunParameters): TunInterface?
}

/** Injected so tests can drive timeouts and retransmissions deterministically. */
interface Clock {
    fun nowMs(): Long
    fun sleep(millis: Long)

    companion object {
        val SYSTEM = object : Clock {
            override fun nowMs(): Long = System.currentTimeMillis()
            override fun sleep(millis: Long) = Thread.sleep(millis)
        }
    }
}
