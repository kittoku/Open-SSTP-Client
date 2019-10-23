package kittoku.opensstpclient.packet

import kittoku.opensstpclient.misc.SstpParsingError
import java.nio.ByteBuffer
import java.nio.charset.Charset
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec


internal enum class SstpMessageType(val value: Short) {
    SSTP_MSG_CALL_CONNECT_REQUEST(1),
    SSTP_MSG_CALL_CONNECT_ACK(2),
    SSTP_MSG_CALL_CONNECT_NAK(3),
    SSTP_MSG_CALL_CONNECTED(4),
    SSTP_MSG_CALL_ABORT(5),
    SSTP_MSG_CALL_DISCONNECT(6),
    SSTP_MSG_CALL_DISCONNECT_ACK(7),
    SSTP_MSG_ECHO_REQUEST(8),
    SSTP_MSG_ECHO_RESPONSE(9)
}

internal class SstpControlPacket {
    // don't reuse packet instance
    var length: Short = 8
    var messageType: SstpMessageType = SstpMessageType.SSTP_MSG_CALL_CONNECT_REQUEST
    private var numAttributes: Short = 0
    internal val attributeList: MutableList<AbstractSstpAttribute> = mutableListOf<AbstractSstpAttribute>()

    fun addAttribute(attribute: AbstractSstpAttribute) {
        numAttributes++
        attributeList.add(attribute)
        length = (length + attribute.length).toShort()
    }

    fun read(bytes: ByteBuffer) {
        // reading starts with MessageType
        length = bytes.limit().toShort()

        messageType = when (bytes.short) {
            SstpMessageType.SSTP_MSG_ECHO_REQUEST.value -> SstpMessageType.SSTP_MSG_ECHO_REQUEST
            SstpMessageType.SSTP_MSG_ECHO_RESPONSE.value -> SstpMessageType.SSTP_MSG_ECHO_RESPONSE
            SstpMessageType.SSTP_MSG_CALL_CONNECT_REQUEST.value -> SstpMessageType.SSTP_MSG_CALL_CONNECT_REQUEST
            SstpMessageType.SSTP_MSG_CALL_CONNECT_ACK.value -> SstpMessageType.SSTP_MSG_CALL_CONNECT_ACK
            SstpMessageType.SSTP_MSG_CALL_CONNECT_NAK.value -> SstpMessageType.SSTP_MSG_CALL_CONNECT_NAK
            SstpMessageType.SSTP_MSG_CALL_CONNECTED.value -> SstpMessageType.SSTP_MSG_CALL_CONNECTED
            SstpMessageType.SSTP_MSG_CALL_ABORT.value -> SstpMessageType.SSTP_MSG_CALL_ABORT
            SstpMessageType.SSTP_MSG_CALL_DISCONNECT.value -> SstpMessageType.SSTP_MSG_CALL_DISCONNECT
            SstpMessageType.SSTP_MSG_CALL_DISCONNECT_ACK.value -> SstpMessageType.SSTP_MSG_CALL_DISCONNECT_ACK
            else -> throw SstpParsingError("Invalid SSTP Message type")
        }

        numAttributes = bytes.short

        repeat(numAttributes.toInt()) {
            bytes.position(bytes.position() + 1)

            val attribute: AbstractSstpAttribute = when (bytes.get()) {
                SstpAttributeId.SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID.value -> SstpEncapsulatedProtocolIdAttribute()
                SstpAttributeId.SSTP_ATTRIB_STATUS_INFO.value -> SstpStatusInfoAttribute()
                SstpAttributeId.SSTP_ATTRIB_CRYPTO_BINDING.value -> SstpCryptoBindingAttribute()
                SstpAttributeId.SSTP_ATTRIB_CRYPTO_BINDING_REQ.value -> SstpCryptoBindingRequestAttribute()
                else -> throw SstpParsingError("Invalid SSTP Attribute ID")
            }

            val proposedAttributeLength = bytes.short
            if (attribute is SstpStatusInfoAttribute) attribute.length = proposedAttributeLength

            attribute.read(bytes)

            attributeList.add(attribute)
        }
    }

    fun write(bytes: ByteBuffer) {
        // writing starts with Version
        bytes.putShort(0x1001.toShort())
        bytes.putShort(length)
        bytes.putShort(messageType.value)
        bytes.putShort(numAttributes)

        for (attribute in attributeList) {
            attribute.write(bytes)
        }
    }

    internal fun computeCmac() {
        val cryptoBinding = attributeList[0] as SstpCryptoBindingAttribute
        val input = ByteBuffer.allocate(length.toInt())
        this.write(input)
        val cmacKeySeed = "SSTP inner method derived CMK".toByteArray(Charset.forName("US-ASCII"))
        val cmkInput = ByteBuffer.allocate(32)
        var hmacProtocol = ""
        var keySize = 0

        when (cryptoBinding.hashProtocol) {
            HashProtocol.CERT_HASH_PROTOCOL_SHA1 -> {
                hmacProtocol = "HmacSHA1"
                keySize = 20
            }
            HashProtocol.CERT_HASH_PROTOCOL_SHA256 -> {
                hmacProtocol = "HmacSHA256"
                keySize = 32

            }
        }
        val hmac = Mac.getInstance(hmacProtocol)
        hmac.init(SecretKeySpec(ByteArray(keySize), hmacProtocol))
        cmkInput.put(cmacKeySeed)
        cmkInput.putShort(keySize.shl(8).toShort())
        cmkInput.put(1)
        val cmk = hmac.doFinal(cmkInput.array())
        hmac.init(SecretKeySpec(cmk, hmacProtocol))
        cryptoBinding.compoundMac.put(hmac.doFinal(input.array()))
    }
}
