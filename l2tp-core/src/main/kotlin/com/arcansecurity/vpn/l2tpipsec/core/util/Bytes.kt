package com.arcansecurity.vpn.l2tpipsec.core.util

import java.security.SecureRandom

/** Small byte-array helpers shared by every protocol layer. */
object Bytes {

    private val HEX = "0123456789abcdef".toCharArray()
    private val random = SecureRandom()

    fun toHex(b: ByteArray): String {
        val out = CharArray(b.size * 2)
        for (i in b.indices) {
            val v = b[i].toInt() and 0xFF
            out[i * 2] = HEX[v ushr 4]
            out[i * 2 + 1] = HEX[v and 0x0F]
        }
        return String(out)
    }

    /** Parses hex, ignoring whitespace, ':' and '-' so RFC test vectors can be pasted as-is. */
    fun fromHex(s: String): ByteArray {
        val clean = StringBuilder(s.length)
        for (c in s) if (!c.isWhitespace() && c != ':' && c != '-') clean.append(c)
        require(clean.length % 2 == 0) { "odd hex length" }
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            out[i] = ((hexVal(clean[i * 2]) shl 4) or hexVal(clean[i * 2 + 1])).toByte()
        }
        return out
    }

    private fun hexVal(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> throw IllegalArgumentException("bad hex char '$c'")
    }

    fun concat(vararg parts: ByteArray): ByteArray {
        var total = 0
        for (p in parts) total += p.size
        val out = ByteArray(total)
        var off = 0
        for (p in parts) {
            System.arraycopy(p, 0, out, off, p.size)
            off += p.size
        }
        return out
    }

    fun xor(a: ByteArray, b: ByteArray): ByteArray {
        require(a.size == b.size) { "xor length mismatch ${a.size} != ${b.size}" }
        val out = ByteArray(a.size)
        for (i in a.indices) out[i] = (a[i].toInt() xor b[i].toInt()).toByte()
        return out
    }

    fun random(n: Int): ByteArray = ByteArray(n).also { random.nextBytes(it) }

    /** Non-zero random used for ISAKMP cookies and L2TP tunnel ids, which must not be 0. */
    fun randomNonZero(n: Int): ByteArray {
        while (true) {
            val b = random(n)
            if (b.any { it.toInt() != 0 }) return b
        }
    }

    /** Constant-time comparison; used for every MAC/ICV/hash check in the stack. */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    /** Left-most [n] bytes; used for MAC truncation (HMAC-SHA-256-128, HMAC-SHA1-96, ...). */
    fun truncate(b: ByteArray, n: Int): ByteArray {
        require(b.size >= n) { "cannot truncate ${b.size} bytes to $n" }
        return b.copyOf(n)
    }

    /**
     * Left-pads with zeroes to [n] bytes. Diffie-Hellman public values and shared secrets must be
     * transmitted with the full modulus length even when the leading bytes happen to be zero.
     *
     * Always a fresh array, like [truncate]: the callers are key-derivation paths that go on to
     * wipe or reuse what they get back, and handing [b] itself over when it already has the right
     * length would make that reach into the caller's buffer.
     */
    fun leftPad(b: ByteArray, n: Int): ByteArray {
        require(b.size <= n) { "value of ${b.size} bytes is longer than target $n" }
        val out = ByteArray(n)
        System.arraycopy(b, 0, out, n - b.size, b.size)
        return out
    }

    fun ipv4ToBytes(dotted: String): ByteArray {
        val parts = dotted.split('.')
        require(parts.size == 4) { "not an IPv4 literal: $dotted" }
        val out = ByteArray(4)
        for (i in 0 until 4) {
            val v = parts[i].toIntOrNull() ?: throw IllegalArgumentException("not an IPv4 literal: $dotted")
            require(v in 0..255) { "not an IPv4 literal: $dotted" }
            out[i] = v.toByte()
        }
        return out
    }

    fun ipv4ToString(b: ByteArray, off: Int = 0): String =
        "${b[off].toInt() and 0xFF}.${b[off + 1].toInt() and 0xFF}." +
            "${b[off + 2].toInt() and 0xFF}.${b[off + 3].toInt() and 0xFF}"
}
