package com.arcansecurity.vpn.l2tpipsec.core.net

import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException

/**
 * UDP codec (RFC 768) for the *inner* UDP/1701 datagram that carries L2TP.
 *
 * The outer UDP/4500 datagram is produced by the kernel through an ordinary [java.net.DatagramSocket];
 * this object only exists because ESP transport mode protects a transport-layer datagram, so we
 * have to build that datagram ourselves before handing it to [com.arcansecurity.vpn.l2tpipsec.core.esp.EspOutboundSa].
 */
object UdpDatagram {

    const val HEADER_SIZE = 8

    /** The L2TP control/data port; the inner datagram uses it on both ends. */
    const val L2TP_PORT = 1701

    /**
     * Encodes a UDP header + payload. When [sourceIp]/[destinationIp] are null the checksum field
     * is left at 0, which IPv4 explicitly allows and which is what L2TP-over-IPsec does: behind a
     * NAT the sender's address is rewritten after the checksum would have been computed
     * (RFC 3948 section 3.1.2), so a zero checksum avoids the fix-up entirely.
     */
    fun encode(
        sourcePort: Int,
        destinationPort: Int,
        payload: ByteArray,
        payloadOffset: Int = 0,
        payloadLength: Int = payload.size - payloadOffset,
        sourceIp: ByteArray? = null,
        destinationIp: ByteArray? = null,
    ): ByteArray {
        // Checked here as well as in encodeInto: a negative length would otherwise blow up in the
        // array allocation below, before the message that says what is actually wrong.
        require(payloadLength >= 0) { "negative payload length $payloadLength" }
        val out = ByteArray(HEADER_SIZE + payloadLength)
        encodeInto(out, 0, sourcePort, destinationPort, payload, payloadOffset, payloadLength)
        if (sourceIp != null && destinationIp != null) {
            var sum = InternetChecksum.computeWithPseudoHeader(
                sourceIp, destinationIp, Ipv4Header.PROTO_UDP, out, 0, out.size,
            )
            // RFC 768: a computed checksum of zero is transmitted as all ones, because zero is the
            // reserved "no checksum" value.
            if (sum == 0) sum = 0xFFFF
            out[6] = (sum ushr 8).toByte()
            out[7] = sum.toByte()
        }
        return out
    }

    /**
     * Writes the header and payload straight into [out] with a zero checksum, returning the number
     * of bytes written. For callers that already own a big enough buffer - the ESP plaintext
     * buffer, say - and want to fill it in instead of paying an allocation and a copy per packet.
     *
     * [out] may be the same array as [payload], even with overlapping ranges: the payload is moved
     * before the header is stamped, so the header never lands on bytes still to be read.
     */
    fun encodeInto(
        out: ByteArray,
        outOffset: Int,
        sourcePort: Int,
        destinationPort: Int,
        payload: ByteArray,
        payloadOffset: Int,
        payloadLength: Int,
    ): Int {
        require(payloadLength >= 0) { "negative payload length $payloadLength" }
        // Every range check here is a subtraction, never a sum: the sums can overflow an `Int` and
        // a wrapped comparison would pass.
        require(payloadOffset >= 0 && payloadLength <= payload.size - payloadOffset) {
            "payload range of $payloadLength bytes at $payloadOffset outside ${payload.size} bytes"
        }
        val total = HEADER_SIZE + payloadLength
        require(total <= 0xFFFF) { "UDP length $total does not fit in 16 bits" }
        require(outOffset >= 0 && total <= out.size - outOffset) {
            "output buffer too small: need $total bytes at $outOffset, have ${out.size}"
        }
        // The payload moves first. System.arraycopy handles overlap, so this is also correct when
        // [out] is [payload]; stamping the header first would overwrite bytes still to be read.
        System.arraycopy(payload, payloadOffset, out, outOffset + HEADER_SIZE, payloadLength)
        out[outOffset] = (sourcePort ushr 8).toByte()
        out[outOffset + 1] = sourcePort.toByte()
        out[outOffset + 2] = (destinationPort ushr 8).toByte()
        out[outOffset + 3] = destinationPort.toByte()
        out[outOffset + 4] = (total ushr 8).toByte()
        out[outOffset + 5] = total.toByte()
        out[outOffset + 6] = 0
        out[outOffset + 7] = 0
        return total
    }

    /** Ports plus the payload slice, described as a range inside the caller's buffer. */
    data class Parsed(
        val sourcePort: Int,
        val destinationPort: Int,
        val payloadOffset: Int,
        val payloadLength: Int,
    )

    /**
     * Parses a UDP datagram. The header length field wins over [length] as long as it fits, so a
     * buffer that was padded by the caller still yields the exact payload. The checksum field is
     * not looked at: the sender is allowed to leave it at zero and this one does.
     *
     * The payload is described as a range inside [data] rather than copied out, and the three
     * header fields are read by hand instead of through a
     * [com.arcansecurity.vpn.l2tpipsec.core.util.ByteReader], because this runs once per received packet on
     * the forwarding path. The caller must copy the payload out before the buffer is reused.
     */
    fun parse(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): Parsed {
        if (offset < 0 || length < 0 || length > data.size - offset) {
            throw ProtocolException("UDP range of $length bytes at $offset outside ${data.size} bytes")
        }
        if (length < HEADER_SIZE) throw ProtocolException("truncated UDP header: $length bytes")
        val sourcePort = u16(data, offset)
        val destinationPort = u16(data, offset + 2)
        val declared = u16(data, offset + 4)
        if (declared < HEADER_SIZE) throw ProtocolException("UDP length field $declared below header size")
        if (declared > length) {
            throw ProtocolException("UDP length field $declared exceeds the $length bytes received")
        }
        return Parsed(
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            payloadOffset = offset + HEADER_SIZE,
            payloadLength = declared - HEADER_SIZE,
        )
    }

    private fun u16(b: ByteArray, at: Int): Int =
        ((b[at].toInt() and 0xFF) shl 8) or (b[at + 1].toInt() and 0xFF)
}
