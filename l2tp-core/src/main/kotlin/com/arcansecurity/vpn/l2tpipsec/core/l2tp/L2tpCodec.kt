package com.arcansecurity.vpn.l2tpipsec.core.l2tp

import com.arcansecurity.vpn.l2tpipsec.core.util.ByteReader
import com.arcansecurity.vpn.l2tpipsec.core.util.ByteWriter
import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException
import java.security.MessageDigest

/**
 * Wire codec for L2TPv2 headers and AVPs (RFC 2661 sections 3.1 and 4.1).
 *
 * The codec is stateless: the sequencing, retransmission and session state live in [L2tpTunnel].
 * Data-path helpers come in a `...Into` flavour so the packet pump can build an L2TP message
 * straight into the buffer that ESP will encrypt, without an intermediate copy.
 */
object L2tpCodec {

    /** The only version this stack speaks; RFC 3931 (L2TPv3) is a different protocol. */
    const val VERSION = 2

    private const val FLAG_CONTROL = 0x8000
    private const val FLAG_LENGTH = 0x4000
    private const val FLAG_SEQUENCE = 0x0800
    private const val FLAG_OFFSET = 0x0200
    private const val FLAG_PRIORITY = 0x0100
    private const val VERSION_MASK = 0x000F

    private const val AVP_MANDATORY = 0x8000
    private const val AVP_HIDDEN = 0x4000
    private const val AVP_LENGTH_MASK = 0x03FF

    /** Fixed part of a data header: flags, tunnel id and session id, plus the optional Length. */
    private const val DATA_HEADER_MIN = 6

    /**
     * Decodes one L2TP header and returns it together with the absolute offset of the payload.
     * The payload size is [L2tpHeader.payloadLength].
     *
     * @throws ProtocolException on anything a conforming peer would not send: a version other
     *   than 2, a control message missing its mandatory L/S bits, or a declared length that does
     *   not fit in the bytes received.
     */
    fun parseHeader(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): Pair<L2tpHeader, Int> {
        if (offset < 0 || length < 0 || offset + length > data.size) {
            throw ProtocolException("L2TP packet range $offset..${offset + length} is outside a ${data.size}-byte buffer")
        }
        val r = ByteReader(data, offset, offset + length)
        val flags = r.u16()
        val version = flags and VERSION_MASK
        if (version != VERSION) throw ProtocolException("unsupported L2TP version $version, expected $VERSION")

        val isControl = flags and FLAG_CONTROL != 0
        val hasLength = flags and FLAG_LENGTH != 0
        val hasSequence = flags and FLAG_SEQUENCE != 0
        val hasOffset = flags and FLAG_OFFSET != 0
        val isPriority = flags and FLAG_PRIORITY != 0
        // RFC 2661 section 3.1: control messages always carry the Length and Sequence fields.
        if (isControl && (!hasLength || !hasSequence)) {
            throw ProtocolException("control message without the mandatory L and S bits (flags 0x%04x)".format(flags))
        }

        val declaredLength = if (hasLength) r.u16() else 0
        val tunnelId = r.u16()
        val sessionId = r.u16()
        val ns = if (hasSequence) r.u16() else 0
        val nr = if (hasSequence) r.u16() else 0
        val offsetSize = if (hasOffset) r.u16() else 0
        // The offset pad is unused filler between the header and the payload.
        if (hasOffset) r.skip(offsetSize)

        val headerSize = r.position - offset
        val total = if (hasLength) declaredLength else length
        if (total < headerSize) {
            throw ProtocolException("L2TP length $total is shorter than its $headerSize-byte header")
        }
        if (total > length) {
            throw ProtocolException("truncated L2TP packet: header declares $total bytes, $length received")
        }

        val header = L2tpHeader(
            isControl = isControl,
            hasLength = hasLength,
            hasSequence = hasSequence,
            hasOffset = hasOffset,
            isPriority = isPriority,
            version = version,
            length = total,
            tunnelId = tunnelId,
            sessionId = sessionId,
            ns = ns,
            nr = nr,
            offsetSize = offsetSize,
        )
        return header to r.position
    }

    /**
     * Builds a control message. An empty [avps] produces a ZLB, the acknowledgement-only message
     * of RFC 2661 section 5.8.
     */
    fun encodeControl(tunnelId: Int, sessionId: Int, ns: Int, nr: Int, avps: List<L2tpAvp>): ByteArray {
        val w = ByteWriter(128)
        w.u16(FLAG_CONTROL or FLAG_LENGTH or FLAG_SEQUENCE or VERSION)
        val lengthAt = w.reserve(2)
        w.u16(tunnelId and 0xFFFF)
        w.u16(sessionId and 0xFFFF)
        w.u16(ns and 0xFFFF)
        w.u16(nr and 0xFFFF)
        for (avp in avps) writeAvp(w, avp)
        w.patchU16(lengthAt, w.size)
        return w.toByteArray()
    }

    /**
     * Builds a data message carrying [payloadLength] bytes of PPP. The Sequence bit is never set:
     * ESP already discards replays and reordering, and LNSes commonly refuse sequenced data.
     */
    fun encodeData(
        tunnelId: Int,
        sessionId: Int,
        payload: ByteArray,
        payloadOffset: Int = 0,
        payloadLength: Int = payload.size,
        includeLength: Boolean = true,
    ): ByteArray {
        val out = ByteArray(dataHeaderSize(includeLength) + payloadLength)
        encodeDataInto(out, 0, tunnelId, sessionId, payload, payloadOffset, payloadLength, includeLength)
        return out
    }

    /**
     * Same bytes as [encodeData] but written in place at [outOffset]; returns the number of bytes
     * written so the caller can hand `out[outOffset until outOffset + n]` to the ESP layer.
     */
    fun encodeDataInto(
        out: ByteArray,
        outOffset: Int,
        tunnelId: Int,
        sessionId: Int,
        payload: ByteArray,
        payloadOffset: Int,
        payloadLength: Int,
        includeLength: Boolean = true,
    ): Int {
        val headerSize = dataHeaderSize(includeLength)
        val total = headerSize + payloadLength
        require(payloadLength >= 0 && payloadOffset >= 0 && payloadOffset + payloadLength <= payload.size) {
            "payload range $payloadOffset..${payloadOffset + payloadLength} is outside a ${payload.size}-byte buffer"
        }
        require(outOffset >= 0 && outOffset + total <= out.size) {
            "$total bytes do not fit at offset $outOffset of a ${out.size}-byte buffer"
        }
        require(!includeLength || total <= 0xFFFF) { "data message of $total bytes overflows the 16-bit Length field" }

        var p = outOffset
        val flags = (if (includeLength) FLAG_LENGTH else 0) or VERSION
        out[p++] = (flags ushr 8).toByte()
        out[p++] = flags.toByte()
        if (includeLength) {
            out[p++] = (total ushr 8).toByte()
            out[p++] = total.toByte()
        }
        out[p++] = (tunnelId ushr 8).toByte()
        out[p++] = tunnelId.toByte()
        out[p++] = (sessionId ushr 8).toByte()
        out[p++] = sessionId.toByte()
        System.arraycopy(payload, payloadOffset, out, p, payloadLength)
        return total
    }

    /** Size of a data header for MTU budgeting. */
    fun dataHeaderSize(includeLength: Boolean): Int = DATA_HEADER_MIN + if (includeLength) 2 else 0

    /**
     * Decodes the AVP list of a control message.
     *
     * When [hiddenSecret] is set, AVPs with the H bit are de-obfuscated per RFC 2661 section 4.3
     * using the Random Vector AVP that precedes them (or [randomVector] when the caller already
     * knows it). The returned AVP keeps `hidden = true` to record how it arrived, but its value is
     * the recovered cleartext. Without a secret the obfuscated body is returned untouched, which
     * is what makes encode/parse round-trip.
     */
    fun parseAvps(
        data: ByteArray,
        offset: Int,
        length: Int,
        hiddenSecret: String? = null,
        randomVector: ByteArray? = null,
    ): List<L2tpAvp> {
        if (offset < 0 || length < 0 || offset + length > data.size) {
            throw ProtocolException("AVP range $offset..${offset + length} is outside a ${data.size}-byte buffer")
        }
        val r = ByteReader(data, offset, offset + length)
        val avps = ArrayList<L2tpAvp>(8)
        var vector = randomVector
        while (r.hasRemaining) {
            val head = r.u16()
            val avpLength = head and AVP_LENGTH_MASK
            if (avpLength < L2tpAvp.HEADER_SIZE) {
                throw ProtocolException("AVP length $avpLength is shorter than the ${L2tpAvp.HEADER_SIZE}-byte AVP header")
            }
            if (avpLength - 2 > r.remaining) {
                throw ProtocolException("AVP length $avpLength overruns the message by ${avpLength - 2 - r.remaining} byte(s)")
            }
            val body = r.slice(avpLength - 2)
            val vendorId = body.u16()
            val type = body.u16()
            var value = body.rest()

            val hidden = head and AVP_HIDDEN != 0
            if (hidden && hiddenSecret != null) {
                val vec = vector ?: throw ProtocolException(
                    "hidden AVP $type arrived before any Random Vector AVP (RFC 2661 section 4.3)",
                )
                value = unhide(type, value, hiddenSecret, vec)
            }
            val avp = L2tpAvp(
                mandatory = head and AVP_MANDATORY != 0,
                hidden = hidden,
                vendorId = vendorId,
                type = type,
                value = value,
            )
            if (avp.avpType == L2tpAvpType.RandomVector) vector = avp.value
            avps += avp
        }
        return avps
    }

    fun encodeAvps(avps: List<L2tpAvp>): ByteArray {
        val w = ByteWriter(128)
        for (avp in avps) writeAvp(w, avp)
        return w.toByteArray()
    }

    /**
     * Writes an AVP verbatim. Hiding on transmission is deliberately not implemented: it protects
     * nothing that the enclosing IPsec SA does not already protect, so the H bit is only ever
     * written back for an AVP a caller assembled itself.
     */
    private fun writeAvp(w: ByteWriter, avp: L2tpAvp) {
        val total = avp.encodedSize
        require(total <= L2tpAvp.MAX_ENCODED_SIZE) {
            "AVP ${avp.type} is $total bytes, the 10-bit Length field tops out at ${L2tpAvp.MAX_ENCODED_SIZE}"
        }
        var head = total
        if (avp.mandatory) head = head or AVP_MANDATORY
        if (avp.hidden) head = head or AVP_HIDDEN
        w.u16(head)
        w.u16(avp.vendorId and 0xFFFF)
        w.u16(avp.type and 0xFFFF)
        w.bytes(avp.value)
    }

    /**
     * Reverses the AVP hiding of RFC 2661 section 4.3.
     *
     * The obfuscated body is a chain of 16-byte blocks XORed with MD5 digests: the first digest is
     * `MD5(attribute type | secret | random vector)`, every later one is `MD5(secret | previous
     * ciphertext block)`. The recovered cleartext starts with the 2-byte length of the original
     * value, which is what lets the sender append arbitrary padding.
     */
    private fun unhide(type: Int, hidden: ByteArray, secret: String, randomVector: ByteArray): ByteArray {
        if (hidden.size < 2) {
            throw ProtocolException("hidden AVP body of ${hidden.size} byte(s) cannot hold the original length")
        }
        val secretBytes = secret.toByteArray(Charsets.UTF_8)
        val md5 = MessageDigest.getInstance("MD5")
        md5.update(byteArrayOf((type ushr 8).toByte(), type.toByte()))
        md5.update(secretBytes)
        md5.update(randomVector)
        var pad = md5.digest()

        val plain = ByteArray(hidden.size)
        var i = 0
        while (i < hidden.size) {
            val n = minOf(pad.size, hidden.size - i)
            for (j in 0 until n) plain[i + j] = (hidden[i + j].toInt() xor pad[j].toInt()).toByte()
            md5.reset()
            md5.update(secretBytes)
            md5.update(hidden, i, n)
            pad = md5.digest()
            i += n
        }

        val originalLength = ((plain[0].toInt() and 0xFF) shl 8) or (plain[1].toInt() and 0xFF)
        if (originalLength > plain.size - 2) {
            throw ProtocolException(
                "hidden AVP declares $originalLength value bytes but only ${plain.size - 2} were sent",
            )
        }
        return plain.copyOfRange(2, 2 + originalLength)
    }
}

/** Tunnel authentication of RFC 2661 section 5.1.1. */
object L2tpAuth {

    /**
     * `MD5(message type | shared secret | challenge)`, where the message type is the single octet
     * of the message the response travels in (SCCCN for a LAC answering the LNS's SCCRP).
     */
    fun challengeResponse(messageType: L2tpMessageType, secret: String, challenge: ByteArray): ByteArray {
        val md5 = MessageDigest.getInstance("MD5")
        md5.update(byteArrayOf(messageType.code.toByte()))
        md5.update(secret.toByteArray(Charsets.UTF_8))
        md5.update(challenge)
        return md5.digest()
    }
}
