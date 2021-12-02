package kittoku.osc.unit

import kittoku.osc.misc.DataUnitParsingError
import kittoku.osc.misc.IncomingBuffer
import java.nio.ByteBuffer
import kotlin.properties.Delegates


internal const val CHAP_CODE_CHALLENGE: Byte = 1
internal const val CHAP_CODE_RESPONSE: Byte = 2
internal const val CHAP_CODE_SUCCESS: Byte = 3
internal const val CHAP_CODE_FAILURE: Byte = 4

internal abstract class ChapFrame : PppFrame() {
    override val protocol = PPP_PROTOCOL_CHAP
}

internal class ChapChallenge : ChapFrame() {
    override val code = CHAP_CODE_CHALLENGE

    override val validLengthRange = 21..Short.MAX_VALUE

    private var valueLength by Delegates.observable(16) { _, _, new ->
        if (new != 16) throw DataUnitParsingError()
    }

    internal val value = ByteArray(16)

    internal var name = ByteArray(0)

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        valueLength = bytes.getByte().toInt()
        bytes.get(value)
        name = ByteArray(_length - validLengthRange.first).also { bytes.get(it) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.put(valueLength.toByte())
        bytes.put(value)
        bytes.put(name)
    }

    override fun update() {
        _length = validLengthRange.first + name.size
    }
}

internal class ChapResponse : ChapFrame() {
    override val code = CHAP_CODE_RESPONSE

    override val validLengthRange = 54..Short.MAX_VALUE

    internal var valueLength by Delegates.observable(49) { _, _, new ->
        if (new != 49) throw DataUnitParsingError()
    }

    internal val challenge = ByteArray(16)

    internal val response = ByteArray(24)

    internal var flag: Byte = 0

    internal var name = ByteArray(0)

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        valueLength = bytes.getByte().toInt()
        bytes.get(challenge)
        bytes.move(8)
        bytes.get(response)
        flag = bytes.getByte()
        name = ByteArray(_length - validLengthRange.first).also { bytes.get(it) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.put(valueLength.toByte())
        bytes.put(challenge)
        bytes.put(ByteArray(8))
        bytes.put(response)
        bytes.put(flag)
        bytes.put(name)
    }

    override fun update() {
        _length = validLengthRange.first + name.size
    }
}

internal class ChapSuccess : ChapFrame() {
    override val code = CHAP_CODE_SUCCESS

    override val validLengthRange = 46..Short.MAX_VALUE

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

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        bytes.get(response)
        message = ByteArray(_length - validLengthRange.first).also { bytes.get(it) }

        if (!isValidResponse) throw DataUnitParsingError()
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.put(response)
        bytes.put(message)
    }

    override fun update() {
        _length = validLengthRange.first + message.size
    }

}

internal class ChapFailure : ChapFrame() {
    override val code = CHAP_CODE_FAILURE

    override val validLengthRange = 4..Short.MAX_VALUE

    internal var message = ByteArray(0)

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        message = ByteArray(_length - validLengthRange.first).also { bytes.get(it) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.put(message)
    }

    override fun update() {
        _length = validLengthRange.first + message.size
    }
}
