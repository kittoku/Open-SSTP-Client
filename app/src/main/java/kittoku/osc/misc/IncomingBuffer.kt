package kittoku.osc.misc

import kittoku.osc.ControlClient
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import kotlin.math.max


internal class IncomingBuffer(capacity: Int, private val parent: ControlClient) {
    private val buffer = ByteBuffer.allocate(capacity).also {
        it.limit(0)
        it.mark()
    }
    internal var pppLimit = 0

    internal fun position(): Int = buffer.position()
    internal fun position(value: Int) = buffer.position(value)
    internal fun getByte(): Byte = buffer.get()
    internal fun getShort(): Short = buffer.short
    internal fun getInt(): Int = buffer.int
    internal fun get(dst: ByteArray) = buffer.get(dst)

    private fun slide() {
        val currentPosition = buffer.position()
        val currentMark = buffer.reset().position()
        val currentLimit = buffer.limit()
        val currentPppLimit = pppLimit

        buffer.position(0).mark()
        buffer.put(buffer.array(), currentMark, currentLimit - currentMark)

        buffer.position(currentPosition - currentMark)
        buffer.limit(currentLimit - currentMark)
        pppLimit = max(currentPppLimit - currentMark, 0)
    }

    private fun supply() {
        try {
            buffer.limit(
                buffer.limit() + parent.sslTerminal.socket.inputStream.read(
                    buffer.array(),
                    buffer.limit(),
                    buffer.capacity() - buffer.limit()
                )
            )

        } catch (e: SocketTimeoutException) {
        }
    }

    internal fun convey() {
        val length = pppLimit - buffer.position()
        parent.ipTerminal.ipOutput.write(buffer.array(), buffer.position(), length)
        buffer.position(buffer.position() + length)
    }

    internal fun move(length: Int) = buffer.move(length)

    internal fun reset() = buffer.reset()

    internal fun forget() = buffer.mark()

    internal fun challenge(length: Int): Boolean {
        // PPP client doesn't have to challenge because SSTP already challenged
        if (length !in 0..buffer.capacity()) return false

        return if (length <= buffer.remaining()) true
        else {
            if (buffer.position() + length > buffer.capacity()) slide()
            supply()
            length <= buffer.remaining()
        }
    }
}
