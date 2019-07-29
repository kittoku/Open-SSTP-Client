package kittoku.opensstpclient.misc

import kittoku.opensstpclient.POLLING_TIME_CHANNEL_READ
import kittoku.opensstpclient.POLLING_TIME_CHANNEL_WRITE
import kotlinx.coroutines.delay
import java.nio.ByteBuffer
import java.nio.channels.Pipe


internal class LayerBridge {
    private val flBuffer = ByteBuffer.allocate(4)
    private val fhBuffer = ByteBuffer.allocate(4)
    private val tlBuffer = ByteBuffer.allocate(4)
    private val thBuffer = ByteBuffer.allocate(4)

    internal val fromLower: Pipe.SourceChannel
    internal val fromHigher: Pipe.SourceChannel
    internal val toLower: Pipe.SinkChannel
    internal val toHigher: Pipe.SinkChannel

    init {
        val incoming = Pipe.open()
        val outgoing = Pipe.open()

        fromLower = incoming.source()
        fromHigher = outgoing.source()
        toLower = outgoing.sink()
        toHigher = incoming.sink()

        fromLower.configureBlocking(false)
        fromHigher.configureBlocking(false)
        toLower.configureBlocking(false)
        toHigher.configureBlocking(false)
    }

    suspend fun readUnitFromLower(bytes: ByteBuffer) {
        flBuffer.clear()
        fromLower.completeRead(flBuffer)
        bytes.limit(flBuffer.getInt(0) + bytes.position())
        fromLower.completeRead(bytes)
    }

    suspend fun readUnitFromHigher(bytes: ByteBuffer) {
        fhBuffer.clear()
        fromHigher.completeRead(fhBuffer)
        bytes.limit(fhBuffer.getInt(0) + bytes.position())
        fromHigher.completeRead(bytes)
    }

    @Synchronized
    suspend fun writeUnitToLower(bytes: ByteBuffer) {
        tlBuffer.clear()
        tlBuffer.putInt(0, bytes.remaining())
        toLower.completeWrite(tlBuffer)
        toLower.completeWrite(bytes)
    }

    suspend fun writeUnitToHigher(bytes: ByteBuffer) {
        thBuffer.clear()
        thBuffer.putInt(0, bytes.remaining())
        toHigher.completeWrite(thBuffer)
        toHigher.completeWrite(bytes)
    }
}

internal suspend fun Pipe.SourceChannel.completeRead(bytes: ByteBuffer) {
    while (true) {
        if (read(bytes) == 0) delay(POLLING_TIME_CHANNEL_READ)

        if (!bytes.hasRemaining()) break
    }
}

internal suspend fun Pipe.SinkChannel.completeWrite(bytes: ByteBuffer) {
    while (true) {
        if (write(bytes) == 0) delay(POLLING_TIME_CHANNEL_WRITE)

        if (!bytes.hasRemaining()) break
    }
}