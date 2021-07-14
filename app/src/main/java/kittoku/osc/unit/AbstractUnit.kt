package kittoku.osc.unit

import kittoku.osc.misc.DataUnitParsingError
import kittoku.osc.misc.IncomingBuffer
import java.nio.ByteBuffer
import kotlin.properties.Delegates


internal abstract class DataUnit<T : Number> {
    internal var _length by Delegates.observable(0) { _, _, new ->
        if (new !in validLengthRange) throw DataUnitParsingError()
    }

    internal abstract val validLengthRange: IntRange

    internal abstract fun getTypedLength(): T

    internal abstract fun setTypedLength(value: T)

    internal abstract fun read(bytes: IncomingBuffer) // reading start after part which tell data unit's type

    internal abstract fun write(bytes: ByteBuffer) // writing start with header

    internal abstract fun update() // invoke after modifying properties to recorrect header
}

internal abstract class ByteLengthDataUnit : DataUnit<Byte>() {
    override fun getTypedLength() = _length.toByte()

    override fun setTypedLength(value: Byte) {
        _length = value.toInt()
    }
}

internal abstract class ShortLengthDataUnit : DataUnit<Short>() {
    override fun getTypedLength() = _length.toShort()

    override fun setTypedLength(value: Short) {
        _length = value.toInt()
    }
}
