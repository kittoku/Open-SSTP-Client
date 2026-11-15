package com.arcansecurity.vpn.l2tpipsec.core.net

/**
 * The one's-complement checksum shared by IPv4, UDP and ICMP (RFC 1071).
 *
 * The tunnel itself only ever produces one: the checksum of the inner UDP/1701 datagram carrying
 * L2TP, and even that one only when [UdpDatagram.encode] is given the addresses. The rest is here
 * because [Ipv4Header] and the tests need to stamp and verify headers.
 */
object InternetChecksum {

    /**
     * RFC 1071 one's-complement sum over a byte range, already complemented and folded to 16 bits.
     *
     * Feeding a buffer that already carries its own correct checksum yields 0, which is the usual
     * way to validate a received header.
     */
    fun compute(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): Int =
        fold(partialSum(data, offset, length))

    /**
     * Same sum, prefixed by the 12-byte IPv4 pseudo-header (source, destination, zero, protocol,
     * payload length) that RFC 768 / RFC 793 require for UDP and TCP.
     *
     * [payloadLength] is also what goes into the pseudo-header length field, so the caller must
     * pass the *whole* transport datagram (header included), not just its body.
     */
    fun computeWithPseudoHeader(
        src: ByteArray,
        dst: ByteArray,
        protocol: Int,
        payload: ByteArray,
        payloadOffset: Int = 0,
        payloadLength: Int = payload.size - payloadOffset,
    ): Int {
        require(src.size >= 4 && dst.size >= 4) { "IPv4 addresses must be 4 bytes" }
        // The pseudo-header is an even number of bytes, so it never shifts the parity of the
        // payload words and the two partial sums can simply be added.
        var sum = partialSum(src, 0, 4) + partialSum(dst, 0, 4) +
            (protocol and 0xFF) + (payloadLength and 0xFFFF)
        sum += partialSum(payload, payloadOffset, payloadLength)
        return fold(sum)
    }

    /** Un-complemented running sum; kept as a [Long] so the carries can be folded in at the end. */
    private fun partialSum(data: ByteArray, offset: Int, length: Int): Long {
        // Written as a subtraction: `offset + length` can overflow, and a wrapped comparison used
        // to let the loop below run over an empty range and report a checksum of a buffer it never
        // read.
        require(offset >= 0 && length >= 0 && length <= data.size - offset) {
            "range of $length bytes at $offset outside a ${data.size}-byte buffer"
        }
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        // RFC 1071 section 4.1: an odd-length buffer is padded on the right with a zero byte.
        if (i < end) sum += (data[i].toInt() and 0xFF) shl 8
        return sum
    }

    private fun fold(sum: Long): Int {
        var s = sum
        while (s ushr 16 != 0L) s = (s and 0xFFFF) + (s ushr 16)
        return (s.inv() and 0xFFFF).toInt()
    }
}
