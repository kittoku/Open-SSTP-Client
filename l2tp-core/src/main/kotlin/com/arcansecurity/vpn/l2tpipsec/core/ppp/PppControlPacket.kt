package com.arcansecurity.vpn.l2tpipsec.core.ppp

import com.arcansecurity.vpn.l2tpipsec.core.util.ByteReader
import com.arcansecurity.vpn.l2tpipsec.core.util.ByteWriter
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException

/** Codes shared by every PPP control protocol (RFC 1661 section 5). */
object PppCode {
    const val CONFIGURE_REQUEST = 1
    const val CONFIGURE_ACK = 2
    const val CONFIGURE_NAK = 3
    const val CONFIGURE_REJECT = 4
    const val TERMINATE_REQUEST = 5
    const val TERMINATE_ACK = 6
    const val CODE_REJECT = 7
    const val PROTOCOL_REJECT = 8
    const val ECHO_REQUEST = 9
    const val ECHO_REPLY = 10
    const val DISCARD_REQUEST = 11

    fun name(code: Int): String = when (code) {
        CONFIGURE_REQUEST -> "Configure-Request"
        CONFIGURE_ACK -> "Configure-Ack"
        CONFIGURE_NAK -> "Configure-Nak"
        CONFIGURE_REJECT -> "Configure-Reject"
        TERMINATE_REQUEST -> "Terminate-Request"
        TERMINATE_ACK -> "Terminate-Ack"
        CODE_REJECT -> "Code-Reject"
        PROTOCOL_REJECT -> "Protocol-Reject"
        ECHO_REQUEST -> "Echo-Request"
        ECHO_REPLY -> "Echo-Reply"
        DISCARD_REQUEST -> "Discard-Request"
        else -> "code $code"
    }
}

/** One type-length-value configuration option (RFC 1661 section 6); [value] excludes type and length. */
data class PppOption(val type: Int, val value: ByteArray) {

    val encodedSize: Int get() = 2 + value.size

    override fun equals(other: Any?): Boolean =
        this === other || (other is PppOption && type == other.type && value.contentEquals(other.value))

    override fun hashCode(): Int = 31 * type + value.contentHashCode()

    override fun toString(): String = "PppOption(type=$type, ${value.size} bytes)"
}

/** Code / identifier / options triple shared by LCP and IPCP. */
data class PppControlPacket(val code: Int, val identifier: Int, val data: ByteArray) {

    /**
     * Decodes [data] as a list of configuration options. Only meaningful for the Configure-*
     * codes; anything else carries opaque data.
     */
    fun options(): List<PppOption> {
        val r = ByteReader(data)
        val out = ArrayList<PppOption>(4)
        while (r.hasRemaining) {
            val type = r.u8()
            val length = r.u8()
            // RFC 1661 section 6: length covers the type and length bytes themselves.
            if (length < 2) throw ProtocolException("option $type has length $length < 2")
            out += PppOption(type, r.bytes(length - 2))
        }
        return out
    }

    fun encode(): ByteArray = ByteWriter(HEADER_SIZE + data.size)
        .u8(code)
        .u8(identifier)
        .u16(HEADER_SIZE + data.size)
        .bytes(data)
        .toByteArray()

    override fun equals(other: Any?): Boolean = this === other ||
        (other is PppControlPacket && code == other.code && identifier == other.identifier &&
            data.contentEquals(other.data))

    override fun hashCode(): Int = 31 * (31 * code + identifier) + data.contentHashCode()

    /**
     * The body is summarised, never dumped. A PAP Authenticate-Request body *is* the cleartext
     * password, and a CHAP response is authentication material; nothing logs one of these today,
     * but a `$packet` in a future diagnostic would publish the credential to logcat and to the
     * app's share-log action.
     */
    override fun toString(): String =
        "PppControlPacket(${PppCode.name(code)}, id=$identifier, ${data.size} bytes)"

    companion object {
        /** Code, identifier and the 16-bit length field. */
        const val HEADER_SIZE = 4

        fun parse(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): PppControlPacket {
            if (offset < 0 || length < 0 || offset + length > data.size) {
                throw ProtocolException("control packet range $offset+$length outside ${data.size} bytes")
            }
            val r = ByteReader(data, offset, offset + length)
            if (r.remaining < HEADER_SIZE) throw ProtocolException("control packet truncated: ${r.remaining} bytes")
            val code = r.u8()
            val identifier = r.u8()
            val declared = r.u16()
            if (declared < HEADER_SIZE) throw ProtocolException("control packet length $declared < $HEADER_SIZE")
            if (declared - HEADER_SIZE > r.remaining) {
                throw ProtocolException("control packet claims $declared bytes, only ${r.remaining + HEADER_SIZE} present")
            }
            // Anything past the declared length is padding added by the peer's framing; RFC 1661
            // section 5.1 requires it to be ignored.
            return PppControlPacket(code, identifier, r.bytes(declared - HEADER_SIZE))
        }

        fun ofOptions(code: Int, identifier: Int, options: List<PppOption>): PppControlPacket {
            val w = ByteWriter(32)
            for (o in options) {
                require(o.encodedSize <= 0xFF) { "option ${o.type} is too long: ${o.value.size} bytes" }
                w.u8(o.type).u8(o.encodedSize).bytes(o.value)
            }
            return PppControlPacket(code, identifier, w.toByteArray())
        }
    }
}
