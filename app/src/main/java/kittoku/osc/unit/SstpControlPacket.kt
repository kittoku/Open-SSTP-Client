package kittoku.osc.unit

import kittoku.osc.misc.DataUnitParsingError
import kittoku.osc.misc.IncomingBuffer
import java.nio.ByteBuffer


internal const val SSTP_PACKET_TYPE_DATA: Short = 0x1000
internal const val SSTP_PACKET_TYPE_CONTROL: Short = 0x1001

internal const val SSTP_MESSAGE_TYPE_CALL_CONNECT_REQUEST: Short = 1
internal const val SSTP_MESSAGE_TYPE_CALL_CONNECT_ACK: Short = 2
internal const val SSTP_MESSAGE_TYPE_CALL_CONNECT_NAK: Short = 3
internal const val SSTP_MESSAGE_TYPE_CALL_CONNECTED: Short = 4
internal const val SSTP_MESSAGE_TYPE_CALL_ABORT: Short = 5
internal const val SSTP_MESSAGE_TYPE_CALL_DISCONNECT: Short = 6
internal const val SSTP_MESSAGE_TYPE_CALL_DISCONNECT_ACK: Short = 7
internal const val SSTP_MESSAGE_TYPE_ECHO_REQUEST: Short = 8
internal const val SSTP_MESSAGE_TYPE_ECHO_RESPONSE: Short = 9

internal abstract class ControlPacket : ShortLengthDataUnit() {
    internal abstract val type: Short

    override val validLengthRange = 8..Short.MAX_VALUE

    internal fun readHeader(bytes: IncomingBuffer) {
        bytes.move(-4)
        setTypedLength(bytes.getShort())
        bytes.move(2)
    }

    internal fun writeHeader(bytes: ByteBuffer) {
        bytes.putShort(SSTP_PACKET_TYPE_CONTROL)
        bytes.putShort(getTypedLength())
        bytes.putShort(type)
    }
}

internal class SstpCallConnectRequest : ControlPacket() {
    override val type = SSTP_MESSAGE_TYPE_CALL_CONNECT_REQUEST

    override val validLengthRange = 14..14

    internal var protocol = EncapsulatedProtocolId()

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        if (bytes.getShort().toInt() == 1) throw DataUnitParsingError()
        bytes.move(1)
        if (bytes.getByte() != SSTP_ATTRIBUTE_ID_ENCAPSULATED_PROTOCOL_ID) throw DataUnitParsingError()
        EncapsulatedProtocolId().also {
            it.read(bytes)
            protocol = it
        }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.putShort(1)
        protocol.write(bytes)
    }

    override fun update() {
        protocol.update()
        _length = validLengthRange.first
    }
}
internal class SstpCallConnectAck : ControlPacket() {
    override val type = SSTP_MESSAGE_TYPE_CALL_CONNECT_ACK

    override val validLengthRange = 48..48

    internal var request = CryptoBindingRequest()

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        if (bytes.getShort().toInt() != 1) throw DataUnitParsingError()
        bytes.move(1)
        if (bytes.getByte() != SSTP_ATTRIBUTE_ID_CRYPTO_BINDING_REQ) throw DataUnitParsingError()
        CryptoBindingRequest().also {
            it.read(bytes)
            request = it
        }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.putShort(1)
        request.write(bytes)
    }

    override fun update() {
        request.update()
        _length = validLengthRange.first
    }

}

internal class SstpCallConnected : ControlPacket() {
    override val type = SSTP_MESSAGE_TYPE_CALL_CONNECTED

    override val validLengthRange = 112..112

    internal var binding = CryptoBinding()

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        if (bytes.getShort().toInt() != 1) throw DataUnitParsingError()
        bytes.move(1)
        if (bytes.getByte() != SSTP_ATTRIBUTE_ID_CRYPTO_BINDING) throw DataUnitParsingError()
        CryptoBinding().also {
            it.read(bytes)
            binding = it
        }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.putShort(1)
        binding.write(bytes)
    }

    override fun update() {
        binding.update()
        _length = validLengthRange.first
    }
}

internal abstract class TerminatePacket : ControlPacket() {
    override val validLengthRange = 8..Short.MAX_VALUE

    internal var statusInfo: StatusInfo? = null

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        statusInfo = when (bytes.getShort().toInt()) {
            0 -> null
            1 -> {
                bytes.move(1)
                if (bytes.getByte() != SSTP_ATTRIBUTE_ID_STATUS_INFO) throw DataUnitParsingError()
                StatusInfo().also { it.read(bytes) }
            }

            else -> throw DataUnitParsingError()
        }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        statusInfo.also {
            if (it == null) {
                bytes.putShort(0)
            } else {
                bytes.putShort(1)
                it.write(bytes)
            }
        }
    }

    override fun update() {
        statusInfo?.update()
        _length = validLengthRange.first + (statusInfo?._length ?: 0)
    }
}

internal class SstpCallAbort : TerminatePacket() {
    override val type = SSTP_MESSAGE_TYPE_CALL_ABORT
}

internal class SstpCallDisconnect : TerminatePacket() {
    override val type = SSTP_MESSAGE_TYPE_CALL_DISCONNECT
}

internal abstract class NoAttributePacket : ControlPacket() {
    override val validLengthRange = 8..8

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        if (bytes.getShort().toInt() != 0) throw DataUnitParsingError()
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.putShort(0)
    }

    override fun update() {
        _length = validLengthRange.first
    }
}

internal class SstpCallDisconnectAck : NoAttributePacket() {
    override val type = SSTP_MESSAGE_TYPE_CALL_DISCONNECT_ACK
}

internal class SstpEchoRequest : NoAttributePacket() {
    override val type = SSTP_MESSAGE_TYPE_ECHO_REQUEST
}

internal class SstpEchoResponse : NoAttributePacket() {
    override val type = SSTP_MESSAGE_TYPE_ECHO_RESPONSE
}
