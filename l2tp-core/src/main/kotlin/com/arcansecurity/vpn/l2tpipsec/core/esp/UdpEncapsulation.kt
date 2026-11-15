package com.arcansecurity.vpn.l2tpipsec.core.esp

/**
 * RFC 3948 UDP encapsulation helpers for the single socket bound to UDP/4500.
 *
 * An unrooted Android app cannot open a raw IP socket, so ESP is *always* carried inside UDP/4500
 * here, whether or not a NAT was detected. That port multiplexes three kinds of traffic, told
 * apart by their first bytes:
 *
 * - IKE messages, prefixed with the 4-byte non-ESP marker (RFC 3948 section 2.2). An ESP packet
 *   can never be confused with one because SPI 0 is reserved and never negotiated.
 * - ESP packets, starting directly with their SPI.
 * - NAT keepalives, a single 0xFF byte (RFC 3948 section 4).
 */
object UdpEncapsulation {

    /** The RFC 3948 UDP-encapsulation port; also the IKE port once NAT traversal is in use. */
    const val PORT = 4500

    /** Four zero bytes prefixed to IKE messages so they cannot be read as an ESP SPI. */
    val NON_ESP_MARKER: ByteArray = byteArrayOf(0, 0, 0, 0)

    /** RFC 3948 section 4 NAT keepalive payload: a single 0xFF byte. */
    val NAT_KEEPALIVE: ByteArray = byteArrayOf(0xFF.toByte())

    /**
     * Smallest datagram that could plausibly be ESP, with the narrowest transforms IKEv1 will
     * negotiate here: SPI (4), sequence number (4), an 8-byte IV, one 8-byte cipher block and a
     * 12-byte ICV. Shorter ones are junk and are not worth handing to an SA.
     */
    const val MIN_ESP_SIZE = 4 + 4 + 8 + 8 + 12

    /** Classifies a datagram received on port 4500. */
    enum class Kind { IKE, ESP, KEEPALIVE, UNKNOWN }

    fun classify(data: ByteArray, offset: Int, length: Int): Kind {
        // A subtraction, not a sum: `offset + length` can overflow and wrap the check into a pass.
        if (offset < 0 || length <= 0 || length > data.size - offset) return Kind.UNKNOWN
        if (length == 1) {
            // Against the literal rather than NAT_KEEPALIVE[0], which callers can write to.
            return if (data[offset] == KEEPALIVE_BYTE) Kind.KEEPALIVE else Kind.UNKNOWN
        }
        if (length > NON_ESP_MARKER.size && hasNonEspMarker(data, offset, length)) return Kind.IKE
        return if (length >= MIN_ESP_SIZE) Kind.ESP else Kind.UNKNOWN
    }

    /**
     * True when the [length]-byte datagram at [offset] starts with the non-ESP marker, i.e. an SPI
     * field of zero.
     *
     * [length] is the datagram, not the buffer: the reader thread reuses one array for every
     * packet, so the four bytes that follow a short datagram are whatever the previous one left
     * behind and must never be mistaken for a marker.
     */
    fun hasNonEspMarker(data: ByteArray, offset: Int, length: Int): Boolean =
        offset >= 0 && length >= NON_ESP_MARKER.size && length <= data.size - offset &&
            data[offset].toInt() == 0 && data[offset + 1].toInt() == 0 &&
            data[offset + 2].toInt() == 0 && data[offset + 3].toInt() == 0

    /** RFC 3948 section 4 keepalive byte, as a literal so the public array cannot redefine it. */
    private const val KEEPALIVE_BYTE: Byte = 0xFF.toByte()
}
