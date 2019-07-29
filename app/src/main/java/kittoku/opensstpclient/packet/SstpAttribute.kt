package kittoku.opensstpclient.packet

import kittoku.opensstpclient.misc.SstpParsingError
import java.nio.ByteBuffer
import kotlin.properties.Delegates


internal enum class SstpAttributeId(val value: Byte) {
    SSTP_ATTRIB_NO_ERROR(0),
    SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID(1),
    SSTP_ATTRIB_STATUS_INFO(2),
    SSTP_ATTRIB_CRYPTO_BINDING(3),
    SSTP_ATTRIB_CRYPTO_BINDING_REQ(4)
}

internal enum class HashProtocol(val value: Byte, val str: String) {
    CERT_HASH_PROTOCOL_SHA1(1, "SHA-1"),
    CERT_HASH_PROTOCOL_SHA256(2, "SHA-256")
}

internal enum class SstpAttributeStatus(val value: Int) {
    ATTRIB_STATUS_NO_ERROR(0),
    ATTRIB_STATUS_DUPLICATE_ATTRIBUTE(1),
    ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE(2),
    ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH(3),
    ATTRIB_STATUS_VALUE_NOT_SUPPORTED(4),
    ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED(5),
    ATTRIB_STATUS_RETRY_COUNT_EXCEEDED(6),
    ATTRIB_STATUS_INVALID_FRAME_RECEIVED(7),
    ATTRIB_STATUS_NEGOTIATION_TIMEOUT(8),
    ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG(9),
    ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING(10),
    ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG(11)
}

internal abstract class AbstractSstpAttribute {
    internal abstract val length: Short
    internal abstract val attributeId: SstpAttributeId
    internal abstract fun read(bytes: ByteBuffer) // read value field and parse it
    internal open fun write(bytes: ByteBuffer) {
        // write a header here and value filed in subclass
        bytes.put(0)
        bytes.put(attributeId.value)
        bytes.putShort(length)
    }
}

internal class SstpEncapsulatedProtocolIdAttribute : AbstractSstpAttribute() {
    override val length: Short = 6
    override val attributeId: SstpAttributeId = SstpAttributeId.SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID
    private val protocolId: Short = 1

    override fun read(bytes: ByteBuffer) {
        if (bytes.short != protocolId) {
            throw SstpParsingError("Invalid protocol ID")
        }
    }

    override fun write(bytes: ByteBuffer) {
        super.write(bytes)
        bytes.putShort(protocolId)
    }
}

internal class SstpCryptoBindingRequestAttribute : AbstractSstpAttribute() {
    override val length: Short = 40
    override val attributeId: SstpAttributeId = SstpAttributeId.SSTP_ATTRIB_CRYPTO_BINDING_REQ
    internal var hashProtocol: HashProtocol = HashProtocol.CERT_HASH_PROTOCOL_SHA1
    internal val nonce: ByteBuffer = ByteBuffer.allocate(32)

    override fun read(bytes: ByteBuffer) {
        bytes.position(bytes.position() + 3)

        hashProtocol = when (bytes.get().toInt()) {
            2, 3 -> HashProtocol.CERT_HASH_PROTOCOL_SHA256
            1 -> HashProtocol.CERT_HASH_PROTOCOL_SHA1
            else -> throw SstpParsingError("Invalid Hash Protocol")
        }

        bytes.get(nonce.array())
    }

    override fun write(bytes: ByteBuffer) {
        super.write(bytes)
        repeat(3) { bytes.put(0) }
        bytes.put(hashProtocol.value)
        bytes.put(nonce.array())
    }
}

internal class SstpCryptoBindingAttribute : AbstractSstpAttribute() {
    override val length: Short = 104
    override val attributeId: SstpAttributeId = SstpAttributeId.SSTP_ATTRIB_CRYPTO_BINDING
    internal var hashProtocol: HashProtocol = HashProtocol.CERT_HASH_PROTOCOL_SHA1
    internal val nonce: ByteBuffer = ByteBuffer.allocate(32)
    internal val certHash: ByteBuffer = ByteBuffer.allocate(32)
    internal val compoundMac: ByteBuffer = ByteBuffer.allocate(32)

    override fun read(bytes: ByteBuffer) {
        bytes.position(bytes.position() + 3)

        hashProtocol = when (bytes.get()) {
            HashProtocol.CERT_HASH_PROTOCOL_SHA1.value -> HashProtocol.CERT_HASH_PROTOCOL_SHA1
            HashProtocol.CERT_HASH_PROTOCOL_SHA256.value -> HashProtocol.CERT_HASH_PROTOCOL_SHA256
            else -> throw SstpParsingError("Invalid Hash Protocol Bitmask")
        }

        bytes.get(nonce.array())
        bytes.get(certHash.array())
        bytes.get(compoundMac.array())
    }

    override fun write(bytes: ByteBuffer) {
        super.write(bytes)
        repeat(3) { bytes.put(0) }
        bytes.put(hashProtocol.value)
        bytes.put(nonce.array())
        bytes.put(certHash.array())
        bytes.put(compoundMac.array())
    }
}

internal class SstpStatusInfoAttribute : AbstractSstpAttribute() {
    override val attributeId: SstpAttributeId = SstpAttributeId.SSTP_ATTRIB_STATUS_INFO
    internal var attribID: SstpAttributeId = SstpAttributeId.SSTP_ATTRIB_NO_ERROR
    internal var status: SstpAttributeStatus = SstpAttributeStatus.ATTRIB_STATUS_NO_ERROR
    private val attribValue: ByteArray = ByteArray(64)

    // mutual observable,length = attribLength + 12
    private var islengthWritable: Boolean = true
    private var isattribLengthWritable: Boolean = true
    override var length: Short by Delegates.observable(12.toShort()) { _, _, new ->
        if (isattribLengthWritable) {
            islengthWritable = false
            attribLength = new.toInt() - 12
            islengthWritable = true
        }
    }
    internal var attribLength: Int by Delegates.observable(0) { _, _, new ->
        if (islengthWritable) {
            isattribLengthWritable = false
            length = (new + 12).toShort()
            isattribLengthWritable = true
        }
    }

    override fun read(bytes: ByteBuffer) {
        bytes.position(bytes.position() + 3)

        attribID = when (bytes.get()) {
            SstpAttributeId.SSTP_ATTRIB_NO_ERROR.value -> SstpAttributeId.SSTP_ATTRIB_NO_ERROR
            SstpAttributeId.SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID.value -> SstpAttributeId.SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID
            SstpAttributeId.SSTP_ATTRIB_STATUS_INFO.value -> SstpAttributeId.SSTP_ATTRIB_STATUS_INFO
            SstpAttributeId.SSTP_ATTRIB_CRYPTO_BINDING.value -> SstpAttributeId.SSTP_ATTRIB_CRYPTO_BINDING
            SstpAttributeId.SSTP_ATTRIB_CRYPTO_BINDING_REQ.value -> SstpAttributeId.SSTP_ATTRIB_CRYPTO_BINDING_REQ
            else -> throw SstpParsingError("Invalid attribID")
        }

        status = when (bytes.int) {
            SstpAttributeStatus.ATTRIB_STATUS_NO_ERROR.value -> SstpAttributeStatus.ATTRIB_STATUS_NO_ERROR
            SstpAttributeStatus.ATTRIB_STATUS_DUPLICATE_ATTRIBUTE.value -> SstpAttributeStatus.ATTRIB_STATUS_DUPLICATE_ATTRIBUTE
            SstpAttributeStatus.ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE.value -> SstpAttributeStatus.ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE
            SstpAttributeStatus.ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH.value -> SstpAttributeStatus.ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH
            SstpAttributeStatus.ATTRIB_STATUS_VALUE_NOT_SUPPORTED.value -> SstpAttributeStatus.ATTRIB_STATUS_VALUE_NOT_SUPPORTED
            SstpAttributeStatus.ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED.value -> SstpAttributeStatus.ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED
            SstpAttributeStatus.ATTRIB_STATUS_RETRY_COUNT_EXCEEDED.value -> SstpAttributeStatus.ATTRIB_STATUS_RETRY_COUNT_EXCEEDED
            SstpAttributeStatus.ATTRIB_STATUS_INVALID_FRAME_RECEIVED.value -> SstpAttributeStatus.ATTRIB_STATUS_INVALID_FRAME_RECEIVED
            SstpAttributeStatus.ATTRIB_STATUS_NEGOTIATION_TIMEOUT.value -> SstpAttributeStatus.ATTRIB_STATUS_NEGOTIATION_TIMEOUT
            SstpAttributeStatus.ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG.value -> SstpAttributeStatus.ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG
            SstpAttributeStatus.ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING.value -> SstpAttributeStatus.ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING
            SstpAttributeStatus.ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG.value -> SstpAttributeStatus.ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG
            else -> throw SstpParsingError("Invalid status")
        }

        length = bytes.limit().toShort()
        bytes.get(attribValue, 0, attribLength)
    }

    override fun write(bytes: ByteBuffer) {
        super.write(bytes)
        repeat(3) { bytes.put(0) }
        bytes.put(attribID.value)
        bytes.putInt(status.value)
        bytes.put(attribValue, 0, attribLength)
    }
}
