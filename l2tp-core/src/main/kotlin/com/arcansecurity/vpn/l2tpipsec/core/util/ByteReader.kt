package com.arcansecurity.vpn.l2tpipsec.core.util

/**
 * Thrown whenever a wire format cannot be decoded. Every parser in the stack uses this so the
 * tunnel can distinguish "peer sent us garbage" from genuine programming errors.
 */
class ProtocolException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Big-endian cursor over a byte array. Network protocols in this project are all big-endian and
 * heavily nested, so bounds-checked sequential reads plus cheap sub-readers keep the parsers
 * short and safe against malformed input.
 */
class ByteReader(
    private val buf: ByteArray,
    private var pos: Int = 0,
    private val limit: Int = buf.size,
) {
    init {
        require(pos in 0..buf.size) { "pos out of range" }
        require(limit in pos..buf.size) { "limit out of range" }
    }

    val position: Int get() = pos
    val remaining: Int get() = limit - pos
    val hasRemaining: Boolean get() = pos < limit

    private fun require(n: Int) {
        if (n < 0) throw ProtocolException("negative length $n")
        if (remaining < n) throw ProtocolException("truncated: need $n bytes, have $remaining")
    }

    fun u8(): Int {
        require(1)
        return buf[pos++].toInt() and 0xFF
    }

    fun u16(): Int {
        require(2)
        val v = ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos + 1].toInt() and 0xFF)
        pos += 2
        return v
    }

    fun u24(): Int {
        require(3)
        val v = ((buf[pos].toInt() and 0xFF) shl 16) or
            ((buf[pos + 1].toInt() and 0xFF) shl 8) or
            (buf[pos + 2].toInt() and 0xFF)
        pos += 3
        return v
    }

    /** 32-bit unsigned value widened to [Long] to avoid sign surprises. */
    fun u32(): Long {
        require(4)
        var v = 0L
        for (i in 0 until 4) v = (v shl 8) or (buf[pos + i].toLong() and 0xFF)
        pos += 4
        return v
    }

    /** 32-bit value kept as a raw [Int]; use for opaque identifiers such as SPIs and magic numbers. */
    fun i32(): Int = u32().toInt()

    fun bytes(n: Int): ByteArray {
        require(n)
        val out = buf.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    /** A reader restricted to the next [n] bytes; the parent cursor advances past them. */
    fun slice(n: Int): ByteReader {
        require(n)
        val r = ByteReader(buf, pos, pos + n)
        pos += n
        return r
    }

    fun skip(n: Int) {
        require(n)
        pos += n
    }

    fun peekU8(): Int {
        require(1)
        return buf[pos].toInt() and 0xFF
    }

    fun rest(): ByteArray = bytes(remaining)

    /** Consumes and validates that nothing is left; parsers call it to catch length mismatches. */
    fun expectEnd(what: String) {
        if (hasRemaining) throw ProtocolException("$what: $remaining trailing byte(s)")
    }
}
