package kittoku.osc.unit.ppp.auth

import kittoku.osc.debug.ParsingDataUnitException
import kittoku.osc.debug.assertAlways
import kittoku.osc.extension.toIntAsUByte
import kittoku.osc.unit.ppp.Frame
import kittoku.osc.unit.ppp.PPP_PROTOCOL_PAP
import java.nio.ByteBuffer


internal const val PAP_CODE_AUTHENTICATE_REQUEST: Byte = 1
internal const val PAP_CODE_AUTHENTICATE_ACK: Byte = 2
internal const val PAP_CODE_AUTHENTICATE_NAK: Byte = 3

internal abstract class PAPFrame : Frame() {
    override val protocol = PPP_PROTOCOL_PAP
}

internal class PAPAuthenticateRequest : PAPFrame() {
    override val code = PAP_CODE_AUTHENTICATE_REQUEST
    override val length: Int
        get() = headerSize + 1 + idFiled.size + 1 + passwordFiled.size

    internal var idFiled = ByteArray(0)
    internal var passwordFiled = ByteArray(0)

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        val idLength = buffer.get().toIntAsUByte()
        idFiled = ByteArray(idLength).also { buffer.get(it) }

        val passwordLength = buffer.get().toIntAsUByte()
        passwordFiled = ByteArray(passwordLength).also { buffer.get(it) }
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        buffer.put(idFiled.size.toByte())
        buffer.put(idFiled)
        buffer.put(passwordFiled.size.toByte())
        buffer.put(passwordFiled)
    }
}

internal abstract class PAPAuthenticateAcknowledgement : PAPFrame() {
    override val length: Int
        get() = headerSize + (if (message.isEmpty()) 0 else message.size + 1)

    private var message = ByteArray(0)

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        when (val remaining = length - headerSize) {
            0 -> {}
            in 1..Int.MAX_VALUE -> {
                val messageLength = buffer.get().toIntAsUByte()
                assertAlways(messageLength == remaining - 1)
                message = ByteArray(messageLength).also { buffer.get(it) }
            }

            else -> throw ParsingDataUnitException()
        }
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        if (message.isNotEmpty()) {
            buffer.put(message.size.toByte())
            buffer.put(message)
        }
    }
}

internal class PAPAuthenticateAck : PAPAuthenticateAcknowledgement() {
    override val code = PAP_CODE_AUTHENTICATE_ACK
}

internal class PAPAuthenticateNak : PAPAuthenticateAcknowledgement() {
    override val code = PAP_CODE_AUTHENTICATE_NAK
}
