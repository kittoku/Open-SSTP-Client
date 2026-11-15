package com.arcansecurity.vpn.l2tpipsec.core.tunnel

import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspIntegrity

/**
 * Works out how much room is left for the user's IP packets once every header in the stack has
 * taken its cut. Getting this wrong is the classic L2TP/IPsec failure mode: the tunnel comes up,
 * ping works, and then TLS handshakes hang forever because full-size segments are silently
 * dropped somewhere with the DF bit set.
 *
 * On the wire a data packet looks like:
 * ```
 * IP(20) UDP(8) | ESP: SPI(4) Seq(4) IV(bs) [ UDP(8) L2TP(8) PPP(4) <IP packet> pad padLen(1) nh(1) ] ICV
 * ```
 * The outer IP and UDP headers are added by the OS, so they only reduce the budget we may hand to
 * the socket; everything inside is ours to account for.
 */
object Mtu {
    /** Outer IPv4 header. */
    const val IPV4_HEADER = 20

    /** Outer UDP/4500 header. */
    const val UDP_HEADER = 8

    /** L2TP data header: flags(2) length(2) tunnel(2) session(2). */
    const val L2TP_DATA_HEADER = 8

    /** PPP header carried in an L2TP data message: FF 03 plus the 2-byte protocol field. */
    const val PPP_HEADER = 4

    /** Inner UDP/1701 header. */
    const val INNER_UDP_HEADER = 8

    /** Conservative path MTU when the platform will not tell us the real one. */
    const val DEFAULT_PATH_MTU = 1500

    /** Smallest MTU worth handing the TUN: the IPv4 minimum reassembly buffer of RFC 791. */
    const val MINIMUM_MTU = 576

    /** Bytes available for the ESP packet itself, given a physical path MTU. */
    fun espBudget(pathMtu: Int): Int = pathMtu - IPV4_HEADER - UDP_HEADER

    /**
     * Largest ESP plaintext that still fits in [espBudget] bytes on the wire.
     *
     * This is the same quantity as `EspOutboundSa.maxPayloadFor`, arrived at independently: the
     * budget has to be computed before any SA exists, and an SA cannot be built without key
     * material. `MtuTest` pins the two together across every cipher and integrity algorithm, so a
     * change to either side breaks the build rather than the full-size packets.
     */
    fun maxEspPayload(espBudget: Int, encryption: EspEncryption, integrity: EspIntegrity): Int {
        val block = encryption.blockBytes
        val fixed = 4 + 4 + block + integrity.icvBytes // SPI, sequence, IV, ICV
        val forPaddedPlaintext = ((espBudget - fixed) / block) * block
        // The padded plaintext holds the payload plus the pad-length and next-header bytes.
        return (forPaddedPlaintext - 2).coerceAtLeast(0)
    }

    /**
     * The MTU to give the TUN interface: the largest IP packet that survives the whole stack,
     * clamped by the user's configured ceiling and floored at [MINIMUM_MTU].
     *
     * The floor is deliberate. A path so small that the headers do not leave 576 bytes is one no
     * IPv4 host is required to cope with anyway, and offering the system a smaller MTU than that
     * makes it refuse the interface outright — a tunnel that fragments is still better than one
     * that will not come up.
     */
    fun tunnelMtu(
        pathMtu: Int,
        encryption: EspEncryption,
        integrity: EspIntegrity,
        configuredCeiling: Int,
    ): Int {
        val payload = maxEspPayload(espBudget(pathMtu), encryption, integrity)
        val computed = payload - INNER_UDP_HEADER - L2TP_DATA_HEADER - PPP_HEADER
        return minOf(computed, configuredCeiling).coerceAtLeast(MINIMUM_MTU)
    }
}
