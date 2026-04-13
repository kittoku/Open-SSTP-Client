package kittoku.osc.debug

import android.util.Log
import kittoku.osc.extension.toHexString
import kittoku.osc.unit.DataUnit
import kotlinx.coroutines.sync.Mutex
import java.nio.ByteBuffer
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale


internal class Capture() {
    private val mutex = Mutex()
    private val currentTime: String
        get() = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault()).format(Date())

    internal suspend fun log(tag: String, buffer: ByteBuffer) {
        mutex.lock()

        val message = mutableListOf<String>()

        message.add("[INFO]")
        message.add("time = $currentTime")
        message.add("size = ${buffer.remaining()}")
        message.add("class = ${ByteBuffer::class.java.simpleName}")
        message.add("")

        message.add("[HEX]")
        message.add(buffer.array().sliceArray(buffer.position() until buffer.limit()).toHexString(true))
        message.add("")

        message.reduce { acc, s -> acc + "\n" + s }.also {
            Log.d(tag, it)
        }

        mutex.unlock()
    }

    internal suspend fun log(tag: String, unit: DataUnit) {
        mutex.lock()
        val buffer = ByteBuffer.allocate(unit.length)
        val message = mutableListOf<String>()

        message.add("[INFO]")
        message.add("time = $currentTime")
        message.add("size = ${buffer.capacity()}")
        message.add("class = ${unit::class.java.simpleName}")
        message.add("")

        message.add("[HEX]")
        unit.write(buffer)
        message.add(buffer.array().toHexString(true))
        message.add("")

        message.reduce { acc, s -> acc + "\n" + s }.also {
            Log.d(tag, it)
        }

        mutex.unlock()
    }
}