package kittoku.osc.unit.ppp

import kittoku.osc.debug.ParsingDataUnitException
import kittoku.osc.debug.assertAlways
import kittoku.osc.extension.move
import kittoku.osc.extension.padZeroByte
import kittoku.osc.extension.toIntAsUByte
import java.nio.ByteBuffer


internal const val CHAP_CODE_CHALLENGE: Byte = 1
internal const val CHAP_CODE_RESPONSE: Byte = 2
internal const val CHAP_CODE_SUCCESS: Byte = 3
internal const val CHAP_CODE_FAILURE: Byte = 4


internal abstract class ChapFrame : Frame() {
    override val protocol = PPP_PROTOCOL_CHAP
}

internal class ChapChallenge : ChapFrame() {
    override val code = CHAP_CODE_CHALLENGE
    override val length: Int
        get() = headerSize + 1 + value.size + name.size

    internal val value = ByteArray(16)

    internal var name = ByteArray(0)

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)
        assertAlways(buffer.get().toIntAsUByte() == value.size)

        buffer.get(value)

        val nameSize = givenLength - length
        assertAlways(nameSize >= 0)

        if (nameSize > 0){
            name = ByteArray(nameSize).also { buffer.get(it) }
        }
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        buffer.put(value.size.toByte())
        buffer.put(value)
        buffer.put(name)
    }
}

internal class ChapResponse : ChapFrame() {
    override val code = CHAP_CODE_RESPONSE
    override val length: Int
        get() = headerSize + 1 + valueSize + name.size

    internal val challenge = ByteArray(16)
    internal val response = ByteArray(24)
    internal var flag: Byte = 0
    private val valueSize = challenge.size + response.size + 9

    internal var name = ByteArray(0)

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)
        assertAlways(buffer.get().toIntAsUByte() == valueSize)

        buffer.get(challenge)
        buffer.move(8)
        buffer.get(response)
        flag = buffer.get()

        val nameSize = givenLength - length
        assertAlways(nameSize >= 0)

        if (nameSize > 0){
            name = ByteArray(nameSize).also { buffer.get(it) }
        }
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        buffer.put(valueSize.toByte())
        buffer.put(challenge)
        buffer.padZeroByte(8)
        buffer.put(response)
        buffer.put(flag)
        buffer.put(name)
    }
}

internal class ChapSuccess : ChapFrame() {
    override val code = CHAP_CODE_SUCCESS
    override val length: Int
        get() = headerSize + response.size + message.size

    internal val response = ByteArray(42)

    internal var message = ByteArray(0)

    private val isValidResponse: Boolean
        get() {
            if (response[0] != 0x53.toByte()) return false

            if (response[1] != 0x3D.toByte()) return false

            response.sliceArray(2..response.lastIndex).forEach {
                if (it !in 0x30..0x39 && it !in 0x41..0x46) return false
            }

            return true
        }

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)
        buffer.get(response)

        val messageSize = givenLength - length
        assertAlways(messageSize >= 0)

        if (messageSize > 0) {
            message = ByteArray(messageSize).also { buffer.get(it) }
        }

        if (!isValidResponse) throw ParsingDataUnitException()
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        buffer.put(response)
        buffer.put(message)
    }
}

internal class ChapFailure : ChapFrame() {
    override val code = CHAP_CODE_FAILURE
    override val length: Int
        get() = headerSize + message.size

    internal var message = ByteArray(0)

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        val messageSize = givenLength - length
        assertAlways(messageSize >= 0)

        if (messageSize > 0) {
            message = ByteArray(messageSize).also { buffer.get(it) }
        }
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        buffer.put(message)
    }
}
