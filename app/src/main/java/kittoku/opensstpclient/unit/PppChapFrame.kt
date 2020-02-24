package kittoku.opensstpclient.unit

import kittoku.opensstpclient.misc.DataUnitParsingError
import kittoku.opensstpclient.misc.IncomingBuffer
import kittoku.opensstpclient.misc.generateResolver
import java.nio.ByteBuffer
import kotlin.properties.Delegates


internal enum class ChapCode(val value: Byte) {
    CHALLENGE(1),
    RESPONSE(2),
    SUCCESS(3),
    FAILURE(4);

    companion object {
        internal val resolve = generateResolver(values(), ChapCode::value)
    }
}

internal abstract class ChapFrame : PppFrame() {
    override val protocol = PppProtocol.CHAP.value
}

internal class ChapChallenge : ChapFrame() {
    override val code = ChapCode.CHALLENGE.value

    override val validLengthRange = 21..Short.MAX_VALUE

    private var valueLength by Delegates.observable(16) { _, _, new ->
        if (new != 16) throw DataUnitParsingError()
    }

    internal val value = ByteArray(16)

    internal val name = mutableListOf<Byte>()

    override fun read(bytes: IncomingBuffer) {
        name.clear()
        readHeader(bytes)
        valueLength = bytes.getByte().toInt()
        repeat(valueLength) { value[it] = bytes.getByte() }
        repeat(_length - validLengthRange.first) { name.add(bytes.getByte()) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.put(valueLength.toByte())
        value.forEach { bytes.put(it) }
        name.forEach { bytes.put(it) }
    }

    override fun update() {
        _length = validLengthRange.first + name.size
    }
}

internal class ChapResponse : ChapFrame() {
    override val code = ChapCode.RESPONSE.value

    override val validLengthRange = 54..Short.MAX_VALUE

    internal var valueLength by Delegates.observable(49) { _, _, new ->
        if (new != 49) throw DataUnitParsingError()
    }

    internal val challenge = ByteArray(16)

    internal val response = ByteArray(24)

    internal var flag: Byte = 0

    internal val name = mutableListOf<Byte>()

    override fun read(bytes: IncomingBuffer) {
        name.clear()
        readHeader(bytes)
        valueLength = bytes.getByte().toInt()
        repeat(challenge.size) { challenge[it] = bytes.getByte() }
        bytes.move(8)
        repeat(response.size) { response[it] = bytes.getByte() }
        flag = bytes.getByte()
        repeat(_length - validLengthRange.first) { name.add(bytes.getByte()) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.put(valueLength.toByte())
        challenge.forEach { bytes.put(it) }
        repeat(8) { bytes.put(0) }
        response.forEach { bytes.put(it) }
        bytes.put(flag)
        name.forEach { bytes.put(it) }
    }

    override fun update() {
        _length = validLengthRange.first + name.size
    }
}

internal class ChapSuccess : ChapFrame() {
    override val code = ChapCode.SUCCESS.value

    override val validLengthRange = 46..Short.MAX_VALUE

    internal val response = ByteArray(42)

    internal val message = mutableListOf<Byte>()

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
        message.clear()
        readHeader(bytes)
        repeat(response.size) { response[it] = bytes.getByte() }
        repeat(_length - validLengthRange.first) { message.add(bytes.getByte()) }

        if (!isValidResponse) throw DataUnitParsingError()
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        response.forEach { bytes.put(it) }
        message.forEach { bytes.put(it) }
    }

    override fun update() {
        _length = validLengthRange.first + message.size
    }

}

internal class ChapFailure : ChapFrame() {
    override val code = ChapCode.FAILURE.value

    override val validLengthRange = 4..Short.MAX_VALUE

    internal val message = mutableListOf<Byte>()

    override fun read(bytes: IncomingBuffer) {
        message.clear()
        readHeader(bytes)
        repeat(_length - validLengthRange.first) { message.add(bytes.getByte()) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        message.forEach { bytes.put(it) }
    }

    override fun update() {
        _length = validLengthRange.first + message.size
    }
}
