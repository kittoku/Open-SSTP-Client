package kittoku.osc.unit

import java.nio.ByteBuffer


internal interface DataUnit {
    val length: Int
    fun write(buffer: ByteBuffer)
    fun read(buffer: ByteBuffer)
}
