package kittoku.osc.unit.sstp

import kittoku.osc.debug.assertAlways
import kittoku.osc.extension.move
import kittoku.osc.extension.padZeroByte
import kittoku.osc.extension.toIntAsUShort
import kittoku.osc.unit.DataUnit
import java.nio.ByteBuffer


internal const val SSTP_ATTRIBUTE_ID_NO_ERROR: Byte = 0
internal const val SSTP_ATTRIBUTE_ID_ENCAPSULATED_PROTOCOL_ID: Byte = 1
internal const val SSTP_ATTRIBUTE_ID_STATUS_INFO: Byte = 2
internal const val SSTP_ATTRIBUTE_ID_CRYPTO_BINDING: Byte = 3
internal const val SSTP_ATTRIBUTE_ID_CRYPTO_BINDING_REQ: Byte = 4

internal const val CERT_HASH_PROTOCOL_SHA1: Byte = 1
internal const val CERT_HASH_PROTOCOL_SHA256: Byte = 2


internal abstract class Attribute : DataUnit() {
    internal abstract val id: Byte
    protected var givenLength = 0

    protected fun readHeader(buffer: ByteBuffer) {
        buffer.move(1)
        assertAlways(buffer.get() == id)
        givenLength = buffer.short.toIntAsUShort()
    }

    protected fun writeHeader(buffer: ByteBuffer) {
        buffer.put(0)
        buffer.put(id)
        buffer.putShort(length.toShort())
    }
}

internal class EncapsulatedProtocolId : Attribute() {
    override val id = SSTP_ATTRIBUTE_ID_ENCAPSULATED_PROTOCOL_ID
    override val length = 6

    internal var protocolId: Short = 1

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)
        assertAlways(givenLength == length)

        protocolId = buffer.short
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        buffer.putShort(protocolId)
    }
}

internal class StatusInfo : Attribute() {
    override val id = SSTP_ATTRIBUTE_ID_STATUS_INFO

    override val length: Int
        get() = minimumLength + holder.size

    private val minimumLength = 12
    private val maximumHolderSize = 64

    internal var targetId: Byte = 0

    internal var status: Int = 0

    internal var holder = ByteArray(0)

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)
        val holderSize = givenLength - minimumLength
        assertAlways(holderSize in 0..maximumHolderSize)

        buffer.move(3)
        targetId = buffer.get()
        status = buffer.int
        holder = ByteArray(holderSize).also {
            buffer.get(it)
        }
    }

    override fun write(buffer: ByteBuffer) {
        assertAlways(holder.size <= maximumHolderSize)

        writeHeader(buffer)
        buffer.padZeroByte(3)
        buffer.put(targetId)
        buffer.putInt(status)
        buffer.put(holder)
    }
}

internal class CryptoBinding : Attribute() {
    override val id = SSTP_ATTRIBUTE_ID_CRYPTO_BINDING
    override val length = 104

    internal var hashProtocol: Byte = 2

    internal val nonce = ByteArray(32)

    internal val certHash = ByteArray(32)

    internal val compoundMac = ByteArray(32)

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)
        assertAlways(givenLength == length)

        buffer.move(3)
        hashProtocol = buffer.get()
        buffer.get(nonce)
        buffer.get(certHash)
        buffer.get(compoundMac)
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)
        buffer.padZeroByte(3)
        buffer.put(hashProtocol)
        buffer.put(nonce)
        buffer.put(certHash)
        buffer.put(compoundMac)
    }
}

internal class CryptoBindingRequest : Attribute() {
    override val id = SSTP_ATTRIBUTE_ID_CRYPTO_BINDING_REQ
    override val length = 40

    internal var bitmask: Byte = 3

    internal val nonce = ByteArray(32)

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)
        assertAlways(givenLength == length)

        buffer.move(3)
        bitmask = buffer.get()
        buffer.get(nonce)
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        buffer.padZeroByte(3)
        buffer.put(bitmask)
        buffer.put(nonce)
    }
}
