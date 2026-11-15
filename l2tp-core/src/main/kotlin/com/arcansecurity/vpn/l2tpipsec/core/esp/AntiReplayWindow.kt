package com.arcansecurity.vpn.l2tpipsec.core.esp

/**
 * Sliding-window replay check, the bitmap variant of RFC 4303 appendix A1.
 *
 * Bit *i* of the window records the sequence number `highest - i`, so advancing the window is a
 * left shift. Only 32-bit (non-extended) sequence numbers are used: IKEv1 never negotiates ESN.
 *
 * Not thread-safe; the tunnel drives a single receive thread per SA.
 */
class AntiReplayWindow(val size: Int = 64) {

    private val words: LongArray

    init {
        require(size in 1..MAX_SIZE) { "replay window size must be in 1..$MAX_SIZE, got $size" }
        words = LongArray((size + 63) / 64)
    }

    /** Highest sequence number accepted so far; 0 means nothing has been accepted yet. */
    var highest: Long = 0
        private set

    /**
     * True when [seq] is new and inside the window, in which case it is recorded. Sequence number
     * 0 is never valid: RFC 4303 section 3.3.3 makes the first packet on an SA use 1.
     */
    fun accept(seq: Long): Boolean {
        if (seq <= 0 || seq > MAX_SEQ) return false
        if (seq > highest) {
            shiftLeft((seq - highest).coerceAtMost(size.toLong()).toInt())
            highest = seq
            setBit(0)
            return true
        }
        // Compared as a Long: the gap can be close to 2^32 and would overflow an Int.
        val diff = highest - seq
        if (diff >= size) return false // left of the window: unverifiably old, must be dropped
        if (getBit(diff.toInt())) return false
        setBit(diff.toInt())
        return true
    }

    /**
     * Read-only probe: true when [seq] would be rejected, either because it was already seen or
     * because it has fallen out of the left edge of the window (or is simply not a legal value).
     */
    fun isReplay(seq: Long): Boolean {
        if (seq <= 0 || seq > MAX_SEQ) return true
        if (seq > highest) return false
        val diff = highest - seq
        return diff >= size || getBit(diff.toInt())
    }

    private fun getBit(i: Int): Boolean = (words[i ushr 6] ushr (i and 63)) and 1L != 0L

    private fun setBit(i: Int) {
        words[i ushr 6] = words[i ushr 6] or (1L shl (i and 63))
    }

    private fun shiftLeft(n: Int) {
        if (n >= size) {
            words.fill(0L)
            return
        }
        val wordShift = n ushr 6
        val bitShift = n and 63
        for (i in words.indices.reversed()) {
            val hi = i - wordShift
            var v = if (hi >= 0) words[hi] else 0L
            if (bitShift != 0) {
                v = v shl bitShift
                val lo = hi - 1
                if (lo >= 0) v = v or (words[lo] ushr (64 - bitShift))
            }
            words[i] = v
        }
    }

    companion object {
        /** A window wider than this buys nothing and would only slow the shift down. */
        const val MAX_SIZE = 1024

        /** Sequence numbers are 32-bit unsigned; see RFC 4303 section 2.2. */
        const val MAX_SEQ = 0xFFFFFFFFL
    }
}
