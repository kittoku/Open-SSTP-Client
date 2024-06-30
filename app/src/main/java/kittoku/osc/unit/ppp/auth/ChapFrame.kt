package kittoku.osc.unit.ppp.auth

import kittoku.osc.unit.ppp.Frame
import kittoku.osc.unit.ppp.PPP_PROTOCOL_CHAP
import java.nio.ByteBuffer


internal const val CHAP_CODE_CHALLENGE: Byte = 1
internal const val CHAP_CODE_RESPONSE: Byte = 2
internal const val CHAP_CODE_SUCCESS: Byte = 3
internal const val CHAP_CODE_FAILURE: Byte = 4


internal abstract class ChapFrame : Frame() {
    override val protocol = PPP_PROTOCOL_CHAP
}

internal abstract class ChapValueNameFrame : ChapFrame() {
    internal var valueName = ChapValueNameFiled()
    override val length: Int
        get() = headerSize + valueName.length

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        valueName.givenLength = givenLength - headerSize
        valueName.read(buffer)
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        valueName.write(buffer)
    }
}

internal class ChapChallenge : ChapValueNameFrame() {
    override val code = CHAP_CODE_CHALLENGE
}

internal class ChapResponse : ChapValueNameFrame() {
    override val code = CHAP_CODE_RESPONSE
}

internal abstract class ChapMessageFrame : ChapFrame() {
    internal var message = ChapMessageField()
    override val length: Int
        get() = headerSize + message.length

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        message.givenLength = givenLength - headerSize
        message.read(buffer)
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        message.write(buffer)
    }
}

internal class ChapSuccess : ChapMessageFrame() {
    override val code = CHAP_CODE_SUCCESS
}

internal class ChapFailure : ChapMessageFrame() {
    override val code = CHAP_CODE_FAILURE
}
