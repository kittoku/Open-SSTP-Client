package com.arcansecurity.vpn.l2tpipsec.core.ike

import com.arcansecurity.vpn.l2tpipsec.core.util.ByteReader
import com.arcansecurity.vpn.l2tpipsec.core.util.ByteWriter
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException

/** The fixed 28-byte ISAKMP header (RFC 2408 section 3.1). */
class IsakmpHeader(
    val initiatorCookie: ByteArray,
    val responderCookie: ByteArray,
    val nextPayload: Int,
    val exchangeType: Int,
    val flags: Int,
    val messageId: Int,
    val length: Int,
    val version: Int = IsakmpCodec.VERSION,
) {

    val isEncrypted: Boolean get() = flags and IsakmpFlags.ENCRYPTION != 0

    fun encode(): ByteArray = ByteWriter(IsakmpCodec.HEADER_SIZE)
        .bytes(initiatorCookie)
        .bytes(responderCookie)
        .u8(nextPayload)
        .u8(version)
        .u8(exchangeType)
        .u8(flags)
        .i32(messageId)
        .i32(length)
        .toByteArray()

    override fun toString(): String =
        "ISAKMP(i=${Bytes.toHex(initiatorCookie)}, r=${Bytes.toHex(responderCookie)}, " +
            "next=$nextPayload, exch=$exchangeType, flags=0x${flags.toString(16)}, " +
            "mid=0x${Integer.toHexString(messageId)}, len=$length)"

    companion object {
        fun decode(message: ByteArray): IsakmpHeader {
            if (message.size < IsakmpCodec.HEADER_SIZE) {
                throw ProtocolException("ISAKMP message of ${message.size} bytes is shorter than the header")
            }
            val r = ByteReader(message)
            val initiator = r.bytes(8)
            val responder = r.bytes(8)
            val nextPayload = r.u8()
            val version = r.u8()
            if (version ushr 4 != 1) {
                throw ProtocolException("unsupported ISAKMP major version ${version ushr 4}")
            }
            val exchangeType = r.u8()
            val flags = r.u8()
            val messageId = r.i32()
            val length = r.i32()
            return IsakmpHeader(
                initiator, responder, nextPayload, exchangeType, flags, messageId, length, version,
            )
        }
    }
}

/**
 * One payload as it appeared inside a payload block, with the offsets it occupied.
 *
 * The offsets are what makes the Quick Mode and Informational hashes possible: they are taken over
 * "everything after the HASH payload", which must be the exact received bytes rather than a
 * re-encoding.
 */
class PayloadSlice(val type: Int, val start: Int, val end: Int, val body: ByteArray)

/** A decoded payload block: the raw bytes, the slices, and the typed payloads. */
class PayloadChain(val block: ByteArray, val slices: List<PayloadSlice>) {

    val payloads: List<IkePayload> = slices.map { IsakmpCodec.decodePayload(it.type, it.body) }

    val isEmpty: Boolean get() = slices.isEmpty()

    inline fun <reified T : IkePayload> find(): T? = payloads.filterIsInstance<T>().firstOrNull()

    inline fun <reified T : IkePayload> all(): List<T> = payloads.filterIsInstance<T>()

    fun indexOfType(payloadType: Int): Int = slices.indexOfFirst { it.type == payloadType }

    /** The exact bytes of the payload body at [index], as received. */
    fun bodyAt(index: Int): ByteArray = sliceAt(index).body

    /**
     * The exact bytes of every payload after [index], generic headers included. Empty when [index]
     * is the last payload.
     */
    fun bytesAfter(index: Int): ByteArray {
        val from = sliceAt(index).end
        val to = slices.last().end
        return if (to <= from) ByteArray(0) else block.copyOfRange(from, to)
    }

    /**
     * Indices here come from [indexOfType], which answers -1 for a payload the peer left out, and
     * a chain decoded from a "next payload = none" header is empty. Both must surface as "the peer
     * sent something we cannot use" rather than as an [IndexOutOfBoundsException] escaping a parser.
     */
    private fun sliceAt(index: Int): PayloadSlice = slices.getOrNull(index)
        ?: throw ProtocolException("no payload at index $index in a chain of ${slices.size}")
}

/** Encoding and decoding of ISAKMP messages and payload chains. */
object IsakmpCodec {

    const val HEADER_SIZE = 28
    const val VERSION = 0x10
    const val COOKIE_SIZE = 8

    /** Guards against a hostile peer looping us with zero-progress payload chains. */
    private const val MAX_PAYLOADS = 64

    /**
     * Emits the payloads back to back, filling each generic header's "next payload" field with the
     * type of the payload that follows and terminating the chain with [PayloadType.NONE].
     */
    fun encodeChain(payloads: List<IkePayload>): ByteArray {
        val w = ByteWriter(128)
        for ((i, p) in payloads.withIndex()) {
            val body = p.encodeBody()
            w.u8(if (i + 1 < payloads.size) payloads[i + 1].type else PayloadType.NONE)
            w.u8(0)
            w.u16(body.size + 4)
            w.bytes(body)
        }
        return w.toByteArray()
    }

    /**
     * Walks the chain starting at [offset], whose first payload has type [firstType] (taken from
     * the enclosing header). Stops at the first "next payload = none", which is what lets a
     * decrypted block carry trailing CBC padding without upsetting the parser.
     */
    fun decodeChain(block: ByteArray, offset: Int, firstType: Int): List<PayloadSlice> {
        val out = ArrayList<PayloadSlice>(8)
        val r = ByteReader(block, offset)
        var type = firstType
        while (type != PayloadType.NONE) {
            if (out.size >= MAX_PAYLOADS) throw ProtocolException("more than $MAX_PAYLOADS ISAKMP payloads")
            val start = r.position
            val next = r.u8()
            r.skip(1)
            val length = r.u16()
            if (length < 4) throw ProtocolException("ISAKMP payload length $length is below the 4-byte header")
            out += PayloadSlice(type, start, start + length, r.bytes(length - 4))
            type = next
        }
        return out
    }

    fun decodePayload(type: Int, body: ByteArray): IkePayload = when (type) {
        PayloadType.SA -> SaPayload.decode(body)
        PayloadType.PROPOSAL -> ProposalPayload.decode(body)
        PayloadType.TRANSFORM -> TransformPayload.decode(body)
        PayloadType.KE -> KeyExchangePayload(body)
        PayloadType.ID -> IdentificationPayload.decode(body)
        PayloadType.HASH -> HashPayload(body)
        PayloadType.SIG -> SignaturePayload(body)
        PayloadType.NONCE -> NoncePayload(body)
        PayloadType.NOTIFY -> NotifyPayload.decode(body)
        PayloadType.DELETE -> DeletePayload.decode(body)
        PayloadType.VENDOR_ID -> VendorIdPayload(body)
        PayloadType.NAT_D, PayloadType.NAT_D_DRAFT -> NatDiscoveryPayload(type, body)
        PayloadType.NAT_OA, PayloadType.NAT_OA_DRAFT -> NatOriginalAddressPayload.decode(type, body)
        else -> UnknownPayload(type, body)
    }

    /** Assembles a complete datagram from a header and an already-serialised payload block. */
    fun buildMessage(
        initiatorCookie: ByteArray,
        responderCookie: ByteArray,
        exchangeType: Int,
        flags: Int,
        messageId: Int,
        firstPayloadType: Int,
        block: ByteArray,
    ): ByteArray {
        val header = IsakmpHeader(
            initiatorCookie = initiatorCookie,
            responderCookie = responderCookie,
            nextPayload = firstPayloadType,
            exchangeType = exchangeType,
            flags = flags,
            messageId = messageId,
            length = HEADER_SIZE + block.size,
        )
        return Bytes.concat(header.encode(), block)
    }

    /** Convenience overload for cleartext messages built from typed payloads. */
    fun buildMessage(
        initiatorCookie: ByteArray,
        responderCookie: ByteArray,
        exchangeType: Int,
        flags: Int,
        messageId: Int,
        payloads: List<IkePayload>,
    ): ByteArray = buildMessage(
        initiatorCookie,
        responderCookie,
        exchangeType,
        flags,
        messageId,
        payloads.firstOrNull()?.type ?: PayloadType.NONE,
        encodeChain(payloads),
    )

    /**
     * Parses the payload block of [message] given an already-decoded [header].
     *
     * The declared header length is deliberately ignored in favour of the datagram length:
     * implementations disagree about whether it covers the CBC padding of an encrypted message.
     */
    fun decodeMessage(message: ByteArray, header: IsakmpHeader = IsakmpHeader.decode(message)): PayloadChain {
        val block = message.copyOfRange(HEADER_SIZE, message.size)
        return PayloadChain(block, decodeChain(block, 0, header.nextPayload))
    }

    /** Decodes a payload block that has already been decrypted. */
    fun decodeBlock(block: ByteArray, firstPayloadType: Int): PayloadChain =
        PayloadChain(block, decodeChain(block, 0, firstPayloadType))
}
