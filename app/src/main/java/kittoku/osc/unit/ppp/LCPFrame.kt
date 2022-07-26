package kittoku.osc.unit.ppp

import kittoku.osc.debug.assertAlways
import kittoku.osc.unit.ppp.option.LCPOptionPack
import java.nio.ByteBuffer


internal const val LCP_CODE_CONFIGURE_REQUEST: Byte = 1
internal const val LCP_CODE_CONFIGURE_ACK: Byte = 2
internal const val LCP_CODE_CONFIGURE_NAK: Byte = 3
internal const val LCP_CODE_CONFIGURE_REJECT: Byte = 4
internal const val LCP_CODE_TERMINATE_REQUEST: Byte = 5
internal const val LCP_CODE_TERMINATE_ACK: Byte = 6
internal const val LCP_CODE_CODE_REJECT: Byte = 7
internal const val LCP_CODE_PROTOCOL_REJECT: Byte = 8
internal const val LCP_CODE_ECHO_REQUEST: Byte = 9
internal const val LCP_CODE_ECHO_REPLY: Byte = 10
internal const val LCP_CODE_DISCARD_REQUEST: Byte = 11


internal abstract class LCPFrame : Frame() {
    override val protocol = PPP_PROTOCOL_LCP
}

internal abstract class LCPConfigureFrame : LCPFrame() {
    override val length: Int
        get() = headerSize + options.length

    internal var options: LCPOptionPack = LCPOptionPack()

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        options = LCPOptionPack(givenLength - length).also {
            it.read(buffer)
        }
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        options.write(buffer)
    }
}

internal class LCPConfigureRequest : LCPConfigureFrame() {
    override val code = LCP_CODE_CONFIGURE_REQUEST
}

internal class LCPConfigureAck : LCPConfigureFrame() {
    override val code = LCP_CODE_CONFIGURE_ACK
}

internal class LCPConfigureNak : LCPConfigureFrame() {
    override val code = LCP_CODE_CONFIGURE_NAK
}

internal class LCPConfigureReject : LCPConfigureFrame() {
    override val code = LCP_CODE_CONFIGURE_REJECT
}

internal abstract class LCPDataHoldingFrame : LCPFrame() {
    override val length: Int
        get() = headerSize + holder.size

    internal var holder = ByteArray(0)

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        val holderSize = givenLength - length
        assertAlways(holderSize >= 0)

        if (holderSize > 0) {
            holder = ByteArray(holderSize).also { buffer.get(it) }
        }
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        buffer.put(holder)
    }
}

internal class LCPTerminalRequest : LCPDataHoldingFrame() {
    override val code = LCP_CODE_TERMINATE_REQUEST
}

internal class LCPTerminalAck : LCPDataHoldingFrame() {
    override val code = LCP_CODE_TERMINATE_ACK
}

internal class LCPCodeReject : LCPDataHoldingFrame() {
    override val code = LCP_CODE_CODE_REJECT
}

internal class LCPProtocolReject : LCPFrame() {
    override val code = LCP_CODE_PROTOCOL_REJECT
    override val length: Int
        get() = headerSize + Short.SIZE_BYTES + holder.size

    internal var rejectedProtocol: Short = 0

    internal var holder = ByteArray(0)

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        rejectedProtocol = buffer.short

        val holderSize = givenLength - length
        assertAlways(holderSize >= 0)

        if (holderSize > 0) {
            holder = ByteArray(holderSize).also { buffer.get(it) }
        }
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        buffer.putShort(rejectedProtocol)
        buffer.put(holder)
    }
}


internal abstract class LCPMagicNumberFrame : LCPFrame() {
    override val length: Int
        get() = headerSize + Int.SIZE_BYTES + holder.size

    internal var magicNumber = 0

    internal var holder = ByteArray(0)

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        magicNumber = buffer.int

        val holderSize = givenLength - length
        assertAlways(holderSize >= 0)

        if (holderSize > 0) {
            holder = ByteArray(holderSize).also { buffer.get(it) }
        }
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        buffer.putInt(magicNumber)
        buffer.put(holder)
    }
}

internal class LCPEchoRequest : LCPMagicNumberFrame() {
    override val code = LCP_CODE_ECHO_REQUEST
}

internal class LCPEchoReply : LCPMagicNumberFrame() {
    override val code = LCP_CODE_ECHO_REPLY
}

internal class LcpDiscardRequest : LCPMagicNumberFrame() {
    override val code = LCP_CODE_DISCARD_REQUEST
}
