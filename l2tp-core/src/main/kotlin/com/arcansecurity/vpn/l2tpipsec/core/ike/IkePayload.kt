package com.arcansecurity.vpn.l2tpipsec.core.ike

import com.arcansecurity.vpn.l2tpipsec.core.util.ByteReader
import com.arcansecurity.vpn.l2tpipsec.core.util.ByteWriter
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException

/**
 * One ISAKMP payload, without its 4-byte generic header.
 *
 * The generic header is a property of the *chain* rather than of the payload — its "next payload"
 * field names the payload that follows — so it is emitted by [IsakmpCodec.encodeChain] and stripped
 * by [IsakmpCodec.decodeChain].
 */
sealed class IkePayload {
    abstract val type: Int

    abstract fun encodeBody(): ByteArray
}

/** Security Association payload: DOI, situation, then a chain of proposals. */
class SaPayload(
    val proposals: List<ProposalPayload>,
    val doi: Int = Doi.IPSEC,
    val situation: Int = Doi.SIT_IDENTITY_ONLY,
) : IkePayload() {
    override val type: Int get() = PayloadType.SA

    override fun encodeBody(): ByteArray = ByteWriter(64)
        .i32(doi)
        .i32(situation)
        .bytes(IsakmpCodec.encodeChain(proposals))
        .toByteArray()

    companion object {
        fun decode(body: ByteArray): SaPayload {
            val r = ByteReader(body)
            val doi = r.i32()
            val situation = r.i32()
            val first = if (r.hasRemaining) PayloadType.PROPOSAL else PayloadType.NONE
            val proposals = IsakmpCodec.decodeChain(body, r.position, first).map {
                if (it.type != PayloadType.PROPOSAL) {
                    throw ProtocolException("payload type ${it.type} inside an SA payload")
                }
                ProposalPayload.decode(it.body)
            }
            return SaPayload(proposals, doi, situation)
        }
    }
}

/** Proposal payload: one protocol, its SPI and a chain of transforms. */
class ProposalPayload(
    val number: Int,
    val protocolId: Int,
    val spi: ByteArray,
    val transforms: List<TransformPayload>,
) : IkePayload() {
    override val type: Int get() = PayloadType.PROPOSAL

    override fun encodeBody(): ByteArray = ByteWriter(48)
        .u8(number)
        .u8(protocolId)
        .u8(spi.size)
        .u8(transforms.size)
        .bytes(spi)
        .bytes(IsakmpCodec.encodeChain(transforms))
        .toByteArray()

    companion object {
        fun decode(body: ByteArray): ProposalPayload {
            val r = ByteReader(body)
            val number = r.u8()
            val protocolId = r.u8()
            val spiSize = r.u8()
            val transformCount = r.u8()
            val spi = r.bytes(spiSize)
            val first = if (transformCount > 0) PayloadType.TRANSFORM else PayloadType.NONE
            val transforms = IsakmpCodec.decodeChain(body, r.position, first).map {
                if (it.type != PayloadType.TRANSFORM) {
                    throw ProtocolException("payload type ${it.type} inside a proposal payload")
                }
                TransformPayload.decode(it.body)
            }
            if (transforms.size != transformCount) {
                throw ProtocolException("proposal announces $transformCount transforms, chain has ${transforms.size}")
            }
            return ProposalPayload(number, protocolId, spi, transforms)
        }
    }
}

/** Transform payload: a transform identifier plus its SA attributes. */
class TransformPayload(
    val number: Int,
    val transformId: Int,
    val attributes: List<SaAttribute>,
) : IkePayload() {
    override val type: Int get() = PayloadType.TRANSFORM

    override fun encodeBody(): ByteArray = ByteWriter(32)
        .u8(number)
        .u8(transformId)
        .u16(0)
        .bytes(SaAttribute.encodeAll(attributes))
        .toByteArray()

    fun attribute(attributeType: Int): SaAttribute? = attributes.firstOrNull { it.type == attributeType }

    fun intAttribute(attributeType: Int): Int? = attribute(attributeType)?.intValue

    companion object {
        fun decode(body: ByteArray): TransformPayload {
            val r = ByteReader(body)
            val number = r.u8()
            val transformId = r.u8()
            r.skip(2)
            return TransformPayload(number, transformId, SaAttribute.decodeAll(r))
        }
    }
}

/** Key Exchange payload: the raw Diffie-Hellman public value. */
class KeyExchangePayload(val data: ByteArray) : IkePayload() {
    override val type: Int get() = PayloadType.KE
    override fun encodeBody(): ByteArray = data
}

/** Nonce payload. */
class NoncePayload(val data: ByteArray) : IkePayload() {
    override val type: Int get() = PayloadType.NONCE
    override fun encodeBody(): ByteArray = data
}

/** Hash payload; carries HASH_I / HASH_R in phase 1 and HASH(1..3) in Quick Mode. */
class HashPayload(val data: ByteArray) : IkePayload() {
    override val type: Int get() = PayloadType.HASH
    override fun encodeBody(): ByteArray = data
}

/** Signature payload; only ever received, since this client authenticates with a pre-shared key. */
class SignaturePayload(val data: ByteArray) : IkePayload() {
    override val type: Int get() = PayloadType.SIG
    override fun encodeBody(): ByteArray = data
}

/** Vendor ID payload; the NAT-T dialect and DPD support are advertised through these. */
class VendorIdPayload(val data: ByteArray) : IkePayload() {
    override val type: Int get() = PayloadType.VENDOR_ID
    override fun encodeBody(): ByteArray = data
}

/** Identification payload, used both for peer identities and for Quick Mode traffic selectors. */
class IdentificationPayload(
    val idType: Int,
    val protocolId: Int,
    val port: Int,
    val data: ByteArray,
) : IkePayload() {
    override val type: Int get() = PayloadType.ID

    override fun encodeBody(): ByteArray = ByteWriter(4 + data.size)
        .u8(idType)
        .u8(protocolId)
        .u16(port)
        .bytes(data)
        .toByteArray()

    companion object {
        fun decode(body: ByteArray): IdentificationPayload {
            val r = ByteReader(body)
            val idType = r.u8()
            val protocolId = r.u8()
            val port = r.u16()
            return IdentificationPayload(idType, protocolId, port, r.rest())
        }
    }
}

/** Notify payload (RFC 2408 section 3.14). */
class NotifyPayload(
    val notifyType: Int,
    val protocolId: Int = ProtocolId.ISAKMP,
    val spi: ByteArray = ByteArray(0),
    val data: ByteArray = ByteArray(0),
    val doi: Int = Doi.IPSEC,
) : IkePayload() {
    override val type: Int get() = PayloadType.NOTIFY

    override fun encodeBody(): ByteArray = ByteWriter(16 + spi.size + data.size)
        .i32(doi)
        .u8(protocolId)
        .u8(spi.size)
        .u16(notifyType)
        .bytes(spi)
        .bytes(data)
        .toByteArray()

    companion object {
        fun decode(body: ByteArray): NotifyPayload {
            val r = ByteReader(body)
            val doi = r.i32()
            val protocolId = r.u8()
            val spiSize = r.u8()
            val notifyType = r.u16()
            val spi = r.bytes(spiSize)
            return NotifyPayload(notifyType, protocolId, spi, r.rest(), doi)
        }
    }
}

/** Delete payload (RFC 2408 section 3.15); every SPI must have the same width. */
class DeletePayload(
    val protocolId: Int,
    val spis: List<ByteArray>,
    val doi: Int = Doi.IPSEC,
) : IkePayload() {
    override val type: Int get() = PayloadType.DELETE

    /** Width of one SPI; 4 for ESP, 16 for the ISAKMP SA (both cookies). */
    val spiSize: Int get() = spis.firstOrNull()?.size ?: 0

    override fun encodeBody(): ByteArray {
        require(spis.all { it.size == spiSize }) { "a delete payload cannot mix SPI widths" }
        val w = ByteWriter(12 + spis.size * spiSize)
        w.i32(doi).u8(protocolId).u8(spiSize).u16(spis.size)
        for (spi in spis) w.bytes(spi)
        return w.toByteArray()
    }

    companion object {
        fun decode(body: ByteArray): DeletePayload {
            val r = ByteReader(body)
            val doi = r.i32()
            val protocolId = r.u8()
            val spiSize = r.u8()
            val count = r.u16()
            // RFC 2408 section 3.15 gives every SPI a real width and puts all of them in the
            // payload. Both halves have to be checked before anything is sized off the count: a
            // twelve-byte payload announcing 65535 zero-width SPIs would otherwise have us build a
            // list of 65535 empty arrays out of nothing.
            if (spiSize == 0 && count > 0) {
                throw ProtocolException("delete payload announces $count SPIs of zero width")
            }
            if (count * spiSize > r.remaining) {
                throw ProtocolException(
                    "delete payload announces $count SPIs of $spiSize bytes, ${r.remaining} present",
                )
            }
            val spis = ArrayList<ByteArray>(count)
            repeat(count) { spis += r.bytes(spiSize) }
            return DeletePayload(protocolId, spis, doi)
        }
    }
}

/**
 * NAT discovery payload (RFC 3947 section 3). [type] is 20 for the RFC and 130 for the drafts;
 * the body is nothing but the hash.
 */
class NatDiscoveryPayload(override val type: Int, val hash: ByteArray) : IkePayload() {
    override fun encodeBody(): ByteArray = hash
}

/** NAT original address payload (RFC 3947 section 5.2); [type] is 21 for the RFC, 131 for drafts. */
class NatOriginalAddressPayload(
    override val type: Int,
    val idType: Int,
    val address: ByteArray,
) : IkePayload() {
    override fun encodeBody(): ByteArray = ByteWriter(8)
        .u8(idType)
        .zeros(3)
        .bytes(address)
        .toByteArray()

    companion object {
        fun decode(payloadType: Int, body: ByteArray): NatOriginalAddressPayload {
            val r = ByteReader(body)
            val idType = r.u8()
            r.skip(3)
            return NatOriginalAddressPayload(payloadType, idType, r.rest())
        }
    }
}

/** Any payload this client does not model; kept verbatim so hashes over the chain stay exact. */
class UnknownPayload(override val type: Int, val data: ByteArray) : IkePayload() {
    override fun encodeBody(): ByteArray = data

    override fun toString(): String = "UnknownPayload(type=$type, data=${Bytes.toHex(data)})"
}
