package com.arcansecurity.vpn.l2tpipsec.core.util

/**
 * Growable big-endian byte buffer. Length fields in ISAKMP, L2TP and PPP are only known after the
 * nested payloads have been emitted, so [patchU16]/[patchU32] let callers reserve a slot and fill
 * it in afterwards.
 */
class ByteWriter(initialCapacity: Int = 128) {
    private var buf = ByteArray(initialCapacity.coerceAtLeast(16))
    private var len = 0

    val size: Int get() = len

    /**
     * Makes room for [extra] more bytes, doubling the capacity as needed.
     *
     * The requirement is computed in [Long]: `len + extra` can overflow an `Int`, and the doubling
     * used to wrap past 2^31 to a negative capacity and then to zero, at which point the loop never
     * terminated.
     */
    private fun ensure(extra: Int) {
        require(extra >= 0) { "negative length $extra" }
        val needed = len.toLong() + extra
        require(needed <= MAX_CAPACITY) { "ByteWriter cannot grow to $needed bytes" }
        if (needed <= buf.size) return
        var cap = buf.size.toLong()
        while (cap < needed) cap = cap shl 1
        buf = buf.copyOf(cap.coerceAtMost(MAX_CAPACITY).toInt())
    }

    fun u8(v: Int) = apply {
        ensure(1)
        buf[len++] = v.toByte()
    }

    fun u16(v: Int) = apply {
        ensure(2)
        buf[len++] = (v ushr 8).toByte()
        buf[len++] = v.toByte()
    }

    fun u24(v: Int) = apply {
        ensure(3)
        buf[len++] = (v ushr 16).toByte()
        buf[len++] = (v ushr 8).toByte()
        buf[len++] = v.toByte()
    }

    fun u32(v: Long) = apply {
        ensure(4)
        buf[len++] = (v ushr 24).toByte()
        buf[len++] = (v ushr 16).toByte()
        buf[len++] = (v ushr 8).toByte()
        buf[len++] = v.toByte()
    }

    fun i32(v: Int) = u32(v.toLong() and 0xFFFFFFFFL)

    fun bytes(b: ByteArray) = bytes(b, 0, b.size)

    fun bytes(b: ByteArray, off: Int, count: Int) = apply {
        ensure(count)
        System.arraycopy(b, off, buf, len, count)
        len += count
    }

    fun zeros(n: Int) = apply {
        ensure(n)
        java.util.Arrays.fill(buf, len, len + n, 0)
        len += n
    }

    /** Reserves [n] zero bytes and returns the offset so it can be patched later. */
    fun reserve(n: Int): Int {
        val at = len
        zeros(n)
        return at
    }

    fun patchU16(offset: Int, v: Int) {
        checkPatch(offset, 2)
        buf[offset] = (v ushr 8).toByte()
        buf[offset + 1] = v.toByte()
    }

    fun patchU32(offset: Int, v: Long) {
        checkPatch(offset, 4)
        buf[offset] = (v ushr 24).toByte()
        buf[offset + 1] = (v ushr 16).toByte()
        buf[offset + 2] = (v ushr 8).toByte()
        buf[offset + 3] = v.toByte()
    }

    fun patchU8(offset: Int, v: Int) {
        checkPatch(offset, 1)
        buf[offset] = v.toByte()
    }

    private fun checkPatch(offset: Int, n: Int) {
        // Written as a subtraction so a huge offset cannot wrap the comparison into a pass.
        require(offset >= 0 && offset <= len - n) { "patch out of range at $offset" }
    }

    fun toByteArray(): ByteArray = buf.copyOf(len)

    private companion object {
        /** Largest array most JVMs will hand out; the header words are reserved by the runtime. */
        const val MAX_CAPACITY = Int.MAX_VALUE - 8L
    }
}
