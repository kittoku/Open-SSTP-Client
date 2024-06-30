package kittoku.osc.unit.ppp.auth

import kittoku.osc.extension.toIntAsUByte
import kittoku.osc.unit.DataUnit
import java.nio.ByteBuffer


internal class ChapValueNameFiled : DataUnit() {
    internal var value = ByteArray(0)
    internal var name = ByteArray(0)
    internal var givenLength = 0 // must be given before reading
    override val length: Int
        get() = 1 + value.size + name.size

    override fun read(buffer: ByteBuffer) {
        value = ByteArray(buffer.get().toIntAsUByte())
        buffer.get(value)

        name = ByteArray(givenLength - length)
        buffer.get(name)
    }

    override fun write(buffer: ByteBuffer) {
        buffer.put(value.size.toByte())
        buffer.put(value)
        buffer.put(name)
    }
}

internal class ChapMessageField : DataUnit() {
    internal var message = ByteArray(0)
    internal var givenLength = 0 // must be given before reading
    override val length: Int
        get() = message.size

    override fun read(buffer: ByteBuffer) {
        message = ByteArray(givenLength)
        buffer.get(message)
    }

    override fun write(buffer: ByteBuffer) {
        buffer.put(message)
    }
}
