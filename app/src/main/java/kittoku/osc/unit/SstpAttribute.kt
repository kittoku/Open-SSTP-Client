package kittoku.osc.unit

import kittoku.osc.misc.IncomingBuffer
import java.nio.ByteBuffer
import kotlin.math.min


internal const val SSTP_ATTRIBUTE_ID_NO_ERROR: Byte = 0
internal const val SSTP_ATTRIBUTE_ID_ENCAPSULATED_PROTOCOL_ID: Byte = 1
internal const val SSTP_ATTRIBUTE_ID_STATUS_INFO: Byte = 2
internal const val SSTP_ATTRIBUTE_ID_CRYPTO_BINDING: Byte = 3
internal const val SSTP_ATTRIBUTE_ID_CRYPTO_BINDING_REQ: Byte = 4

internal const val CERT_HASH_PROTOCOL_SHA1: Byte = 1
internal const val CERT_HASH_PROTOCOL_SHA256: Byte = 2

internal abstract class Attribute : ShortLengthDataUnit() {
    internal abstract val id: Byte

    override val validLengthRange = 4..Short.MAX_VALUE

    internal fun readHeader(bytes: IncomingBuffer) { setTypedLength(bytes.getShort()) }

    internal fun writeHeader(bytes: ByteBuffer) {
        bytes.put(0)
        bytes.put(id)
        bytes.putShort(getTypedLength())
    }
}

internal class EncapsulatedProtocolId : Attribute() {
    override val id = SSTP_ATTRIBUTE_ID_ENCAPSULATED_PROTOCOL_ID

    override val validLengthRange = 6..6

    internal var protocolId: Short = 1

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        protocolId = bytes.getShort()
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.putShort(protocolId)
    }

    override fun update() { _length = validLengthRange.first }
}

internal class StatusInfo : Attribute() {
    override val id = SSTP_ATTRIBUTE_ID_STATUS_INFO

    override val validLengthRange = 12..Short.MAX_VALUE

    internal var targetId: Byte = 0

    internal var status: Int = 0

    internal var holder = ByteArray(0)

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        bytes.move(3)
        targetId = bytes.getByte()
        status = bytes.getInt()
        holder = ByteArray(_length - validLengthRange.first).also { bytes.get(it) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.put(ByteArray(3))
        bytes.put(targetId)
        bytes.putInt(status)
        bytes.put(holder.sliceArray(0 until min(holder.size, 64)))
    }

    override fun update() {
        _length = validLengthRange.first + min(holder.size, 64)
    }
}

internal class CryptoBinding : Attribute() {
    override val id = SSTP_ATTRIBUTE_ID_CRYPTO_BINDING

    override val validLengthRange = 104..104

    internal var hashProtocol: Byte = 2

    internal val nonce = ByteArray(32)

    internal val certHash = ByteArray(32)

    internal val compoundMac = ByteArray(32)

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        bytes.move(3)
        hashProtocol = bytes.getByte()
        bytes.get(nonce)
        bytes.get(certHash)
        bytes.get(compoundMac)
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.put(ByteArray(3))
        bytes.put(hashProtocol)
        bytes.put(nonce)
        bytes.put(certHash)
        bytes.put(compoundMac)
    }

    override fun update() { _length = validLengthRange.first }
}

internal class CryptoBindingRequest : Attribute() {
    override val id = SSTP_ATTRIBUTE_ID_CRYPTO_BINDING_REQ

    override val validLengthRange = 40..40

    internal var bitmask: Byte = 3

    internal val nonce = ByteArray(32)

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        bytes.move(3)
        bitmask = bytes.getByte()
        bytes.get(nonce)
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.put(ByteArray(3))
        bytes.put(bitmask)
        bytes.put(nonce)
    }

    override fun update() { _length = validLengthRange.first }
}
