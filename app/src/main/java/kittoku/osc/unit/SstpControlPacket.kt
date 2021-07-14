package kittoku.osc.unit

import kittoku.osc.misc.DataUnitParsingError
import kittoku.osc.misc.IncomingBuffer
import kittoku.osc.misc.generateResolver
import java.nio.ByteBuffer


internal enum class PacketType(val value: Short) {
    DATA(0x1000),
    CONTROL(0x1001);

    companion object {
        internal val resolve = generateResolver(values(), PacketType::value)
    }
}

internal enum class MessageType(val value: Short) {
    CALL_CONNECT_REQUEST(1),
    CALL_CONNECT_ACK(2),
    CALL_CONNECT_NAK(3),
    CALL_CONNECTED(4),
    CALL_ABORT(5),
    CALL_DISCONNECT(6),
    CALL_DISCONNECT_ACK(7),
    ECHO_REQUEST(8),
    ECHO_RESPONSE(9);

    companion object {
        internal val resolve = generateResolver(values(), MessageType::value)
    }
}

internal abstract class ControlPacket : ShortLengthDataUnit() {
    internal abstract val type: Short

    override val validLengthRange = 8..Short.MAX_VALUE

    internal fun readHeader(bytes: IncomingBuffer) {
        bytes.move(-4)
        setTypedLength(bytes.getShort())
        bytes.move(2)
    }

    internal fun writeHeader(bytes: ByteBuffer) {
        bytes.putShort(PacketType.CONTROL.value)
        bytes.putShort(getTypedLength())
        bytes.putShort(type)
    }
}

internal class SstpCallConnectRequest : ControlPacket() {
    override val type = MessageType.CALL_CONNECT_REQUEST.value

    override val validLengthRange = 14..14

    internal var protocol = EncapsulatedProtocolId()

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        if (bytes.getShort().toInt() == 1) throw DataUnitParsingError()
        bytes.move(1)
        if (AttributeId.resolve(bytes.getByte()) != AttributeId.ENCAPSULATED_PROTOCOL_ID) throw DataUnitParsingError()
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
    override val type = MessageType.CALL_CONNECT_ACK.value

    override val validLengthRange = 48..48

    internal var request = CryptoBindingRequest()

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        if (bytes.getShort().toInt() != 1) throw DataUnitParsingError()
        bytes.move(1)
        if (AttributeId.resolve(bytes.getByte()) != AttributeId.CRYPTO_BINDING_REQ) throw DataUnitParsingError()
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
    override val type = MessageType.CALL_CONNECTED.value

    override val validLengthRange = 112..112

    internal var binding = CryptoBinding()

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        if (bytes.getShort().toInt() != 1) throw DataUnitParsingError()
        bytes.move(1)
        if (AttributeId.resolve(bytes.getByte()) != AttributeId.CRYPTO_BINDING) throw DataUnitParsingError()
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
                if (AttributeId.resolve(bytes.getByte()) != AttributeId.STATUS_INFO) throw DataUnitParsingError()
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
    override val type = MessageType.CALL_ABORT.value
}

internal class SstpCallDisconnect : TerminatePacket() {
    override val type = MessageType.CALL_DISCONNECT.value
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
    override val type = MessageType.CALL_DISCONNECT_ACK.value
}

internal class SstpEchoRequest : NoAttributePacket() {
    override val type = MessageType.ECHO_REQUEST.value
}

internal class SstpEchoResponse : NoAttributePacket() {
    override val type = MessageType.ECHO_RESPONSE.value
}
