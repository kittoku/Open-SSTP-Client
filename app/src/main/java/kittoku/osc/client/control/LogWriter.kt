package kittoku.osc.client.control

import kittoku.osc.client.ClientBridge
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.BufferedOutputStream
import java.text.SimpleDateFormat
import java.util.*


internal class LogWriter(bridge: ClientBridge) {
    private val mutex = Mutex()

    private val outputStream = BufferedOutputStream(
        bridge.service.contentResolver.openOutputStream(bridge.service.logUri!!, "wa")
    )

    private val currentTime: String
        get() = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault()).format(Date())

    internal suspend fun report(message: String) {
        mutex.withLock {
            outputStream.write("[$currentTime] $message\n".toByteArray(Charsets.UTF_8))
        }
    }

    internal fun close() {
        outputStream.flush()
        outputStream.close()
    }
}
