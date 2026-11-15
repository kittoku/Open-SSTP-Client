package com.arcansecurity.vpn.l2tpipsec.core.l2tp

import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException

/**
 * L2TP header shared by control and data messages (RFC 2661 section 3.1).
 *
 * ```
 *  0                   1                   2                   3
 * |T|L|x|x|S|x|O|P|x|x|x|x| Ver |          Length (opt)         |
 * |           Tunnel ID           |           Session ID          |
 * |              Ns (opt)         |              Nr (opt)         |
 * |      Offset Size (opt)        |    Offset pad... (opt)        |
 * ```
 *
 * [length] is the Length field when [hasLength] is set. When the sender omitted it the parser
 * substitutes the number of bytes actually available, so `length - headerSize` is the payload size
 * in both cases.
 */
data class L2tpHeader(
    val isControl: Boolean,
    val hasLength: Boolean,
    val hasSequence: Boolean,
    val hasOffset: Boolean,
    val isPriority: Boolean,
    val version: Int,
    val length: Int,
    val tunnelId: Int,
    val sessionId: Int,
    val ns: Int,
    val nr: Int,
    val offsetSize: Int,
) {
    /**
     * Bytes the header occupies, optional fields and offset padding included. The Length field
     * counts the whole message, so the payload starts this many bytes into the packet.
     */
    val headerSize: Int
        get() = 2 + (if (hasLength) 2 else 0) + 4 + (if (hasSequence) 4 else 0) +
            (if (hasOffset) 2 + offsetSize else 0)

    /** Payload bytes following the header: AVPs for a control message, a PPP frame for data. */
    val payloadLength: Int get() = length - headerSize
}

/** Control message types carried in the Message Type AVP (RFC 2661 section 3.1). */
enum class L2tpMessageType(val code: Int) {
    SCCRQ(1),
    SCCRP(2),
    SCCCN(3),
    StopCCN(4),
    HELLO(6),
    OCRQ(7),
    OCRP(8),
    OCCN(9),
    ICRQ(10),
    ICRP(11),
    ICCN(12),
    CDN(14),
    WEN(15),
    SLI(16),
    ;

    companion object {
        private val byCode = entries.associateBy { it.code }

        /** `null` for a code we do not implement; such a message is acknowledged and dropped. */
        fun of(code: Int): L2tpMessageType? = byCode[code]
    }
}

/** IETF (vendor id 0) AVP attribute types, RFC 2661 section 4.4. */
enum class L2tpAvpType(val code: Int) {
    MessageType(0),
    ResultCode(1),
    ProtocolVersion(2),
    FramingCapabilities(3),
    BearerCapabilities(4),
    TieBreaker(5),
    FirmwareRevision(6),
    HostName(7),
    VendorName(8),
    AssignedTunnelId(9),
    ReceiveWindowSize(10),
    Challenge(11),
    Q931CauseCode(12),
    ChallengeResponse(13),
    AssignedSessionId(14),
    CallSerialNumber(15),
    MinimumBps(16),
    MaximumBps(17),
    BearerType(18),
    FramingType(19),
    CalledNumber(21),
    CallingNumber(22),
    SubAddress(23),
    TxConnectSpeed(24),
    PhysicalChannelId(25),
    InitialReceivedLcpConfreq(26),
    LastSentLcpConfreq(27),
    LastReceivedLcpConfreq(28),
    ProxyAuthenType(29),
    ProxyAuthenName(30),
    ProxyAuthenChallenge(31),
    ProxyAuthenId(32),
    ProxyAuthenResponse(33),
    CallErrors(34),
    Accm(35),
    RandomVector(36),
    PrivateGroupId(37),
    RxConnectSpeed(38),
    SequencingRequired(39),
    ;

    companion object {
        private val byCode = entries.associateBy { it.code }

        fun of(code: Int): L2tpAvpType? = byCode[code]
    }
}

/**
 * One Attribute Value Pair (RFC 2661 section 4.1).
 *
 * ```
 * |M|H|x|x|x|x|  Length (10 bits) |           Vendor ID           |
 * |         Attribute Type        |        Attribute Value ...
 * ```
 *
 * [value] is always the cleartext for AVPs this client builds. For a received AVP with [hidden]
 * set, it is the cleartext only when [L2tpCodec.parseAvps] was given the tunnel secret; otherwise
 * it is still the obfuscated body exactly as it arrived.
 */
data class L2tpAvp(
    val mandatory: Boolean,
    val hidden: Boolean,
    val vendorId: Int,
    val type: Int,
    val value: ByteArray,
) {
    /** The IETF attribute this AVP carries, or `null` for a vendor-specific or unknown one. */
    val avpType: L2tpAvpType? get() = if (vendorId == VENDOR_IETF) L2tpAvpType.of(type) else null

    /** Bytes this AVP occupies on the wire, its 6-byte header included. */
    val encodedSize: Int get() = HEADER_SIZE + value.size

    fun asU16(): Int {
        if (value.size != 2) throw ProtocolException("${describeType()}: expected a 2-byte value, got ${value.size}")
        return ((value[0].toInt() and 0xFF) shl 8) or (value[1].toInt() and 0xFF)
    }

    fun asU32(): Long {
        if (value.size != 4) throw ProtocolException("${describeType()}: expected a 4-byte value, got ${value.size}")
        var v = 0L
        for (b in value) v = (v shl 8) or (b.toLong() and 0xFF)
        return v
    }

    /**
     * Text AVPs are defined as not NUL-terminated, but some LNSes terminate them anyway, so
     * trailing NULs are stripped instead of leaking into host names and error messages.
     */
    fun asText(): String = String(value, Charsets.UTF_8).trimEnd(Char.MIN_VALUE)

    private fun describeType(): String = avpType?.name ?: "AVP $vendorId/$type"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is L2tpAvp) return false
        return mandatory == other.mandatory && hidden == other.hidden &&
            vendorId == other.vendorId && type == other.type && value.contentEquals(other.value)
    }

    override fun hashCode(): Int {
        var result = if (mandatory) 1 else 0
        result = 31 * result + (if (hidden) 1 else 0)
        result = 31 * result + vendorId
        result = 31 * result + type
        result = 31 * result + value.contentHashCode()
        return result
    }

    /**
     * Names the attribute and its size but never its bytes. An AVP body is not automatically
     * harmless: a Challenge Response is authentication material, and once tunnel authentication is
     * wired up a parsed hidden AVP carries its recovered cleartext here. Logs are shareable, so the
     * value stays out of them by construction rather than by remembering not to log it.
     */
    override fun toString(): String = buildString {
        append(describeType())
        if (mandatory) append("(M)")
        if (hidden) append("(H)")
        append('[')
        append(value.size)
        append(" bytes]")
    }

    companion object {
        /** Vendor id 0 selects the IETF attribute space of [L2tpAvpType]. */
        const val VENDOR_IETF = 0

        const val HEADER_SIZE = 6

        /** The Length field is 10 bits wide and counts the header too. */
        const val MAX_ENCODED_SIZE = 0x3FF

        fun u16(type: L2tpAvpType, value: Int, mandatory: Boolean = true): L2tpAvp =
            raw(type, byteArrayOf((value ushr 8).toByte(), value.toByte()), mandatory)

        fun u32(type: L2tpAvpType, value: Long, mandatory: Boolean = true): L2tpAvp = raw(
            type,
            byteArrayOf(
                (value ushr 24).toByte(),
                (value ushr 16).toByte(),
                (value ushr 8).toByte(),
                value.toByte(),
            ),
            mandatory,
        )

        fun text(type: L2tpAvpType, value: String, mandatory: Boolean = true): L2tpAvp =
            raw(type, value.toByteArray(Charsets.UTF_8), mandatory)

        fun raw(type: L2tpAvpType, value: ByteArray, mandatory: Boolean = true): L2tpAvp =
            L2tpAvp(mandatory = mandatory, hidden = false, vendorId = VENDOR_IETF, type = type.code, value = value)
    }
}

/** First IETF AVP of the requested [type], or `null`. */
fun List<L2tpAvp>.find(type: L2tpAvpType): L2tpAvp? =
    firstOrNull { it.vendorId == L2tpAvp.VENDOR_IETF && it.type == type.code }

/** Like [find] but fails the exchange when the peer omitted an AVP the RFC makes mandatory. */
fun List<L2tpAvp>.requireAvp(type: L2tpAvpType, message: String): L2tpAvp =
    find(type) ?: throw ProtocolException("$message: missing the ${type.name} AVP")
