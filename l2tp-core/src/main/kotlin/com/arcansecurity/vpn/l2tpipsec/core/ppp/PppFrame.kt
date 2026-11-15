package com.arcansecurity.vpn.l2tpipsec.core.ppp

import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException

/** PPP protocol numbers (RFC 1700 "PPP DLL protocol numbers") used by this stack. */
object PppProtocol {
    const val IPV4 = 0x0021
    const val IPV6 = 0x0057
    const val IPCP = 0x8021
    const val IPV6CP = 0x8057
    const val LCP = 0xC021
    const val PAP = 0xC023
    const val CHAP = 0xC223
    const val CCP = 0x80FD

    /** Human readable name for logs; unknown values are rendered as hex. */
    fun name(protocol: Int): String = when (protocol) {
        IPV4 -> "IPv4"
        IPV6 -> "IPv6"
        IPCP -> "IPCP"
        IPV6CP -> "IPv6CP"
        LCP -> "LCP"
        PAP -> "PAP"
        CHAP -> "CHAP"
        CCP -> "CCP"
        else -> "0x%04X".format(protocol)
    }
}

/**
 * A bare PPP frame as carried by L2TP. Address/Control (FF 03) is included by default because
 * that is what pppd emits on an L2TP session, but it is accepted either way on receive
 * (RFC 2661 section 5.4 allows omitting it).
 *
 * There is no HDLC framing here: L2TP already delimits the frame, so there are no flags, no byte
 * stuffing and no FCS (RFC 2661 section 4.3).
 */
object PppFrame {

    private const val ADDRESS = 0xFF
    private const val CONTROL = 0x03

    /**
     * Builds a complete frame. When [payloadOffset] is non-zero the caller must also pass
     * [payloadLength]; the default only covers the common "whole array" case.
     */
    fun encode(
        protocol: Int,
        payload: ByteArray,
        payloadOffset: Int = 0,
        payloadLength: Int = payload.size,
        withAddressControl: Boolean = true,
    ): ByteArray {
        val out = ByteArray(headerSize(withAddressControl) + payloadLength)
        encodeInto(out, 0, protocol, payload, payloadOffset, payloadLength, withAddressControl)
        return out
    }

    /**
     * Writes the frame straight into [out] at [outOffset], which lets the tunnel assemble the
     * L2TP header and the PPP frame in a single buffer with no intermediate copy.
     *
     * @return the number of bytes written.
     */
    fun encodeInto(
        out: ByteArray,
        outOffset: Int,
        protocol: Int,
        payload: ByteArray,
        payloadOffset: Int,
        payloadLength: Int,
        withAddressControl: Boolean = true,
    ): Int {
        require(protocol in 0..0xFFFF) { "protocol out of range: $protocol" }
        val need = headerSize(withAddressControl) + payloadLength
        require(outOffset >= 0 && payloadLength >= 0 && outOffset + need <= out.size) {
            "output buffer too small: need $need at $outOffset in ${out.size}"
        }
        var p = outOffset
        if (withAddressControl) {
            out[p++] = ADDRESS.toByte()
            out[p++] = CONTROL.toByte()
        }
        // The protocol field is always emitted uncompressed: PFC is never negotiated by this client.
        out[p++] = (protocol ushr 8).toByte()
        out[p++] = protocol.toByte()
        System.arraycopy(payload, payloadOffset, out, p, payloadLength)
        return need
    }

    /** Where the payload of a received frame starts, and which protocol carries it. */
    data class Parsed(val protocol: Int, val payloadOffset: Int, val payloadLength: Int)

    /** Tolerates a present or absent FF 03 and 1- or 2-byte protocol fields (PFC). */
    fun parse(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): Parsed {
        if (offset < 0 || length < 0 || offset + length > data.size) {
            throw ProtocolException("PPP frame range $offset+$length outside ${data.size} bytes")
        }
        val end = offset + length
        var p = offset
        if (end - p >= 2 && (data[p].toInt() and 0xFF) == ADDRESS && (data[p + 1].toInt() and 0xFF) == CONTROL) {
            p += 2
        }
        if (end - p < 1) throw ProtocolException("PPP frame has no protocol field")
        val first = data[p].toInt() and 0xFF
        val protocol: Int
        if (first and 1 == 1) {
            // RFC 1661 section 6.5: a compressed protocol field is the single odd low-order byte.
            protocol = first
            p += 1
        } else {
            if (end - p < 2) throw ProtocolException("PPP frame truncated inside the protocol field")
            protocol = (first shl 8) or (data[p + 1].toInt() and 0xFF)
            p += 2
        }
        return Parsed(protocol, p, end - p)
    }

    /** Bytes [encode] prepends to the payload. */
    fun headerSize(withAddressControl: Boolean = true): Int = if (withAddressControl) 4 else 2
}
