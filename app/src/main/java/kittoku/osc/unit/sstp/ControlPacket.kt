package kittoku.osc.unit.sstp

import kittoku.osc.debug.ParsingDataUnitException
import kittoku.osc.debug.assertAlways
import kittoku.osc.extension.toIntAsUShort
import kittoku.osc.unit.DataUnit
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


internal abstract class ControlPacket : DataUnit() {
    internal abstract val type: Short
    internal abstract val numAttribute: Int

    protected var givenLength = 0
    protected var givenNumAttribute = 0

    protected fun readHeader(buffer: ByteBuffer) {
        assertAlways(buffer.short == SSTP_PACKET_TYPE_CONTROL)
        givenLength = buffer.short.toIntAsUShort()
        assertAlways(buffer.short == type)
        givenNumAttribute = buffer.short.toIntAsUShort()
    }

    protected fun writeHeader(buffer: ByteBuffer) {
        buffer.putShort(SSTP_PACKET_TYPE_CONTROL)
        buffer.putShort(length.toShort())
        buffer.putShort(type)
        buffer.putShort(numAttribute.toShort())
    }
}

internal class SstpCallConnectRequest : ControlPacket() {
    override val type = SSTP_MESSAGE_TYPE_CALL_CONNECT_REQUEST
    override val length = 14
    override val numAttribute = 1

    internal var protocol = EncapsulatedProtocolId()

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)
        assertAlways(givenLength == length)
        assertAlways(givenNumAttribute == numAttribute)

        protocol.read(buffer)
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        protocol.write(buffer)
    }
}

internal class SstpCallConnectAck : ControlPacket() {
    override val type = SSTP_MESSAGE_TYPE_CALL_CONNECT_ACK
    override val length = 48
    override val numAttribute = 1

    internal var request = CryptoBindingRequest()

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)
        assertAlways(givenLength == length)
        assertAlways(givenNumAttribute == numAttribute)

        request.read(buffer)
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        request.write(buffer)
    }
}

internal class SstpCallConnectNak : ControlPacket() {
    override val type = SSTP_MESSAGE_TYPE_CALL_CONNECT_NAK
    override val length: Int
        get() = 8 + statusInfos.fold(0) {sum, info -> sum + info.length } + holder.size

    override val numAttribute: Int
        get() = statusInfos.size

    internal val statusInfos = mutableListOf<StatusInfo>()

    internal var holder = ByteArray(0)

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        repeat(givenNumAttribute) {
            StatusInfo().also {
                it.read(buffer)
                statusInfos.add(it)
            }
        }

        val holderSize = givenLength - length
        assertAlways(holderSize >= 0)

        if (holderSize > 0) {
            holder = ByteArray(holderSize).also { buffer.get(it) }
        }
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        statusInfos.forEach {
            it.write(buffer)
        }

        buffer.put(holder)
    }
}

internal class SstpCallConnected : ControlPacket() {
    override val type = SSTP_MESSAGE_TYPE_CALL_CONNECTED
    override val length = 112
    override val numAttribute = 1

    internal var binding = CryptoBinding()

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)
        assertAlways(givenLength == length)
        assertAlways(givenNumAttribute == numAttribute)

        binding.read(buffer)
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        binding.write(buffer)
    }
}

internal abstract class TerminatePacket : ControlPacket() {
    override val length: Int
        get() = 8 + (statusInfo?.length ?: 0)

    override val numAttribute: Int
        get() = statusInfo?.let { 1 } ?: 0

    internal var statusInfo: StatusInfo? = null

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        statusInfo = when (givenNumAttribute) {
            0 -> null
            1 -> StatusInfo().also { it.read(buffer) }
            else -> throw ParsingDataUnitException()
        }

        assertAlways(givenLength == length)
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        statusInfo?.also {
            it.write(buffer)
        }
    }
}

internal class SstpCallAbort : TerminatePacket() {
    override val type = SSTP_MESSAGE_TYPE_CALL_ABORT
}

internal class SstpCallDisconnect : TerminatePacket() {
    override val type = SSTP_MESSAGE_TYPE_CALL_DISCONNECT
}

internal abstract class NoAttributePacket : ControlPacket() {
    override val length = 8
    override val numAttribute = 0

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)
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
