package com.arcansecurity.vpn.l2tpipsec.core.ppp

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.PppAuthProtocol
import com.arcansecurity.vpn.l2tpipsec.core.util.ByteReader
import com.arcansecurity.vpn.l2tpipsec.core.util.ByteWriter
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException

/** PAP packet codes (RFC 1334 section 2.2). */
object PapCode {
    const val AUTHENTICATE_REQUEST = 1
    const val AUTHENTICATE_ACK = 2
    const val AUTHENTICATE_NAK = 3
}

/** CHAP packet codes (RFC 1994 section 4). MS-CHAPv2 reuses them unchanged. */
object ChapCode {
    const val CHALLENGE = 1
    const val RESPONSE = 2
    const val SUCCESS = 3
    const val FAILURE = 4
}

/** Values of the algorithm byte of the LCP Authentication-Protocol option when it names CHAP. */
object ChapAlgorithm {
    /** RFC 1994 section 5: CHAP with MD5. */
    const val MD5 = 5

    /** RFC 2759 section 3: MS-CHAPv2. */
    const val MS_CHAP_V2 = 0x81
}

/**
 * Encoding helpers for the two "simple" authentication protocols. They are separate from
 * [PppSession] only so that the wire format stays readable; MS-CHAPv2 lives in [MsChapV2].
 */
internal object PapPacket {

    /** RFC 1334 section 2.2.1: peer-id length, peer-id, password length, password. */
    fun encodeRequest(peerId: String, password: String): ByteArray {
        val id = peerId.toByteArray(Charsets.UTF_8)
        val pw = password.toByteArray(Charsets.UTF_8)
        require(id.size <= 0xFF) { "PAP peer-id is longer than 255 bytes" }
        require(pw.size <= 0xFF) { "PAP password is longer than 255 bytes" }
        return ByteWriter(2 + id.size + pw.size)
            .u8(id.size).bytes(id)
            .u8(pw.size).bytes(pw)
            .toByteArray()
    }

    /** The human readable part of an Authenticate-Ack/Nak, if the peer bothered to send one. */
    fun message(data: ByteArray): String {
        if (data.isEmpty()) return ""
        val length = data[0].toInt() and 0xFF
        val end = minOf(1 + length, data.size)
        return String(data, 1, end - 1, Charsets.UTF_8)
    }
}

/** A decoded CHAP Challenge or Response: a counted value followed by the peer's name. */
internal class ChapValue(val value: ByteArray, val name: String) {
    companion object {
        fun parse(data: ByteArray): ChapValue {
            val r = ByteReader(data)
            val size = r.u8()
            if (size > r.remaining) throw ProtocolException("CHAP value claims $size bytes, ${r.remaining} left")
            val value = r.bytes(size)
            return ChapValue(value, String(r.rest(), Charsets.UTF_8))
        }
    }
}

internal object ChapPacket {

    fun encode(value: ByteArray, name: String): ByteArray {
        val n = name.toByteArray(Charsets.UTF_8)
        require(value.size <= 0xFF) { "CHAP value is longer than 255 bytes" }
        return ByteWriter(1 + value.size + n.size).u8(value.size).bytes(value).bytes(n).toByteArray()
    }

    /** RFC 1994 section 4.1: the response is `MD5(identifier | secret | challenge)`. */
    fun md5Response(identifier: Int, password: String, challenge: ByteArray): ByteArray {
        val md5 = java.security.MessageDigest.getInstance("MD5")
        md5.update(identifier.toByte())
        md5.update(password.toByteArray(Charsets.UTF_8))
        md5.update(challenge)
        return md5.digest()
    }
}

/** LCP Authentication-Protocol option encoding for the protocols this client accepts. */
internal fun PppAuthProtocol.authOptionValue(): ByteArray = when (this) {
    PppAuthProtocol.PAP -> byteArrayOf(0xC0.toByte(), 0x23)
    PppAuthProtocol.CHAP_MD5 -> byteArrayOf(0xC2.toByte(), 0x23, ChapAlgorithm.MD5.toByte())
    PppAuthProtocol.MSCHAP_V2 -> byteArrayOf(0xC2.toByte(), 0x23, ChapAlgorithm.MS_CHAP_V2.toByte())
}

/**
 * Maps the `E=<code>` field of an MS-CHAPv2 Failure message (RFC 2759 section 6) to something a
 * user can act on. The codes are Windows RAS error numbers.
 */
internal fun msChapErrorDescription(code: Int): String = when (code) {
    646 -> "login not permitted at this time of day"
    647 -> "account disabled"
    648 -> "password expired"
    649 -> "account has no dial-in / VPN permission"
    691 -> "wrong username or password"
    709 -> "password change failed"
    else -> "error $code"
}

/** Digits of the `S=` field: an MS-CHAPv2 authenticator response is a 20-byte SHA-1 digest. */
private const val AUTHENTICATOR_HEX_DIGITS = 40

/** Widest `E=` value that still fits an [Int]; Windows RAS error numbers are three digits. */
private const val MAX_ERROR_CODE_DIGITS = 9

/**
 * Extracts `E=<digits>` from an MS-CHAPv2 Failure message; -1 when the peer did not send a usable
 * one. Only ASCII digits count: `Char.isDigit` is true for every Unicode decimal digit, and a
 * message full of Arabic-Indic digits would otherwise be turned into a nonsense error number.
 */
internal fun parseMsChapErrorCode(message: String): Int {
    val at = message.indexOf("E=")
    if (at < 0) return -1
    var i = at + 2
    var value = 0
    var digits = 0
    while (i < message.length && message[i] in '0'..'9') {
        // A run long enough to overflow the accumulator would otherwise wrap onto a code that
        // means something else entirely, and be reported to the user as that.
        if (digits >= MAX_ERROR_CODE_DIGITS) return -1
        value = value * 10 + (message[i] - '0')
        digits++
        i++
    }
    return if (digits == 0) -1 else value
}

/**
 * Decodes the `S=<40 hex digits>` authenticator response of an MS-CHAPv2 Success message, or null
 * when the peer did not send a well-formed one.
 *
 * The hex is validated and decoded together on purpose. This runs on a message an unauthenticated
 * peer controls, and PPP only unwinds cleanly from [ProtocolException]; letting a damaged `S=`
 * reach a parser that throws [IllegalArgumentException] would take the whole tunnel down instead of
 * failing authentication.
 */
internal fun parseMsChapAuthenticatorResponse(message: String): ByteArray? {
    val at = message.indexOf("S=")
    if (at < 0 || at + 2 + AUTHENTICATOR_HEX_DIGITS > message.length) return null
    val hex = message.substring(at + 2, at + 2 + AUTHENTICATOR_HEX_DIGITS)
    if (!hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
    return Bytes.fromHex(hex)
}
