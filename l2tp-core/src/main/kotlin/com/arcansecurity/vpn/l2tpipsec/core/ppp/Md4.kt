package com.arcansecurity.vpn.l2tpipsec.core.ppp

/**
 * MD4 (RFC 1320). MS-CHAPv2 needs it for `NtPasswordHash`, and it has been dropped from most
 * JCE providers (Android's Conscrypt has never offered it), so the stack carries its own.
 *
 * This is a straight transcription of RFC 1320 section 3: it is a one-shot digest of an in-memory
 * password, so there is no streaming API and no attempt at constant-time behaviour beyond what the
 * algorithm itself does.
 */
object Md4 {

    private const val BLOCK = 64

    fun digest(input: ByteArray): ByteArray {
        // Step 1/2: append 0x80, pad with zeros to 56 mod 64, then the 64-bit little-endian bit count.
        val padded = ByteArray(((input.size + 8) / BLOCK + 1) * BLOCK)
        System.arraycopy(input, 0, padded, 0, input.size)
        padded[input.size] = 0x80.toByte()
        val bits = input.size.toLong() * 8
        for (i in 0 until 8) padded[padded.size - 8 + i] = (bits ushr (8 * i)).toByte()

        // Step 3: the four-word buffer, little-endian throughout.
        var a = 0x67452301
        var b = 0xEFCDAB89.toInt()
        var c = 0x98BADCFE.toInt()
        var d = 0x10325476

        val x = IntArray(16)
        var offset = 0
        while (offset < padded.size) {
            for (i in 0 until 16) {
                val j = offset + i * 4
                x[i] = (padded[j].toInt() and 0xFF) or
                    ((padded[j + 1].toInt() and 0xFF) shl 8) or
                    ((padded[j + 2].toInt() and 0xFF) shl 16) or
                    ((padded[j + 3].toInt() and 0xFF) shl 24)
            }
            val aa = a
            val bb = b
            val cc = c
            val dd = d

            // Round 1: a = (a + F(b,c,d) + X[k]) <<< s
            a = ff(a, b, c, d, x[0], 3); d = ff(d, a, b, c, x[1], 7)
            c = ff(c, d, a, b, x[2], 11); b = ff(b, c, d, a, x[3], 19)
            a = ff(a, b, c, d, x[4], 3); d = ff(d, a, b, c, x[5], 7)
            c = ff(c, d, a, b, x[6], 11); b = ff(b, c, d, a, x[7], 19)
            a = ff(a, b, c, d, x[8], 3); d = ff(d, a, b, c, x[9], 7)
            c = ff(c, d, a, b, x[10], 11); b = ff(b, c, d, a, x[11], 19)
            a = ff(a, b, c, d, x[12], 3); d = ff(d, a, b, c, x[13], 7)
            c = ff(c, d, a, b, x[14], 11); b = ff(b, c, d, a, x[15], 19)

            // Round 2: a = (a + G(b,c,d) + X[k] + 0x5A827999) <<< s
            a = gg(a, b, c, d, x[0], 3); d = gg(d, a, b, c, x[4], 5)
            c = gg(c, d, a, b, x[8], 9); b = gg(b, c, d, a, x[12], 13)
            a = gg(a, b, c, d, x[1], 3); d = gg(d, a, b, c, x[5], 5)
            c = gg(c, d, a, b, x[9], 9); b = gg(b, c, d, a, x[13], 13)
            a = gg(a, b, c, d, x[2], 3); d = gg(d, a, b, c, x[6], 5)
            c = gg(c, d, a, b, x[10], 9); b = gg(b, c, d, a, x[14], 13)
            a = gg(a, b, c, d, x[3], 3); d = gg(d, a, b, c, x[7], 5)
            c = gg(c, d, a, b, x[11], 9); b = gg(b, c, d, a, x[15], 13)

            // Round 3: a = (a + H(b,c,d) + X[k] + 0x6ED9EBA1) <<< s
            a = hh(a, b, c, d, x[0], 3); d = hh(d, a, b, c, x[8], 9)
            c = hh(c, d, a, b, x[4], 11); b = hh(b, c, d, a, x[12], 15)
            a = hh(a, b, c, d, x[2], 3); d = hh(d, a, b, c, x[10], 9)
            c = hh(c, d, a, b, x[6], 11); b = hh(b, c, d, a, x[14], 15)
            a = hh(a, b, c, d, x[1], 3); d = hh(d, a, b, c, x[9], 9)
            c = hh(c, d, a, b, x[5], 11); b = hh(b, c, d, a, x[13], 15)
            a = hh(a, b, c, d, x[3], 3); d = hh(d, a, b, c, x[11], 9)
            c = hh(c, d, a, b, x[7], 11); b = hh(b, c, d, a, x[15], 15)

            a += aa; b += bb; c += cc; d += dd
            offset += BLOCK
        }

        val out = ByteArray(16)
        writeLe(out, 0, a); writeLe(out, 4, b); writeLe(out, 8, c); writeLe(out, 12, d)
        return out
    }

    private fun ff(a: Int, b: Int, c: Int, d: Int, xk: Int, s: Int): Int =
        Integer.rotateLeft(a + ((b and c) or (b.inv() and d)) + xk, s)

    private fun gg(a: Int, b: Int, c: Int, d: Int, xk: Int, s: Int): Int =
        Integer.rotateLeft(a + ((b and c) or (b and d) or (c and d)) + xk + 0x5A827999, s)

    private fun hh(a: Int, b: Int, c: Int, d: Int, xk: Int, s: Int): Int =
        Integer.rotateLeft(a + (b xor c xor d) + xk + 0x6ED9EBA1, s)

    private fun writeLe(out: ByteArray, at: Int, v: Int) {
        out[at] = v.toByte()
        out[at + 1] = (v ushr 8).toByte()
        out[at + 2] = (v ushr 16).toByte()
        out[at + 3] = (v ushr 24).toByte()
    }
}
