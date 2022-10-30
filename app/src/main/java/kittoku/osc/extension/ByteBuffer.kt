package kittoku.osc.extension

import java.nio.ByteBuffer


internal fun ByteBuffer.move(diff: Int) {
    position(position() + diff)
}

internal fun ByteBuffer.padZeroByte(size: Int) {
    repeat(size) { put(0) }
}

internal fun ByteBuffer.probeByte(diff: Int): Byte {
    return this.get(this.position() + diff)
}

internal fun ByteBuffer.probeShort(diff: Int): Short {
    return this.getShort(this.position() + diff)
}

internal val ByteBuffer.capacityAfterLimit: Int
    get() = this.capacity() - this.limit()

internal fun ByteBuffer.slide() {
    val remaining = this.remaining()

    this.array().also {
        it.copyInto(it, 0, this.position(), this.limit())
    }

    this.position(0)
    this.limit(remaining)
}
