package kittoku.osc.misc

import java.nio.ByteBuffer
import java.nio.IntBuffer


private fun Int.reversed(): Int {
    val bytes = ByteBuffer.allocate(4)
    bytes.putInt(this)
    bytes.array().reverse()
    return bytes.getInt(0)
}

private fun Long.reversed(): Long {
    val bytes = ByteBuffer.allocate(8)
    bytes.putLong(this)
    bytes.array().reverse()
    return bytes.getLong(0)
}

internal fun hashMd4(input: ByteArray): ByteArray {
    val inputLength = input.size
    val remainder = inputLength % 64
    val padLength = if (remainder >= 56) 64 - (remainder - 56) else (56 - remainder)
    val bytesLength = inputLength + padLength + 8

    val bytes = ByteBuffer.allocate(bytesLength)
    bytes.put(input)
    bytes.put(0b1000_0000.toByte())
    bytes.position(bytesLength - 8)
    bytes.putLong((8 * inputLength).toLong().reversed())
    bytes.clear()

    var A = 0x01234567.reversed()
    var B = 0x89ABCDEF.toInt().reversed()
    var C = 0xFEDCBA98.toInt().reversed()
    var D = 0x76543210.reversed()

    val F = { X: Int, Y: Int, Z: Int -> (X and Y) or (X.inv() and Z) }
    val G = { X: Int, Y: Int, Z: Int -> (X and Y) or (Y and Z) or (Z and X) }
    val H = { X: Int, Y: Int, Z: Int -> X xor Y xor Z }
    val rotate = { X: Int, s: Int -> X.shl(s) or X.ushr(32 - s) }

    val ints = IntBuffer.allocate(16)

    val nl_1 = { a: Int, b: Int, c: Int, d: Int, k: Int, s: Int ->
        rotate(a + F(b, c, d) + ints.get(k), s)
    }
    val nl_2 = { a: Int, b: Int, c: Int, d: Int, k: Int, s: Int ->
        rotate(a + G(b, c, d) + ints.get(k) + 0x5A827999, s)
    }
    val nl_3 = { a: Int, b: Int, c: Int, d: Int, k: Int, s: Int ->
        rotate(a + H(b, c, d) + ints.get(k) + 0x6ED9EBA1, s)
    }

    repeat(bytesLength / 64) {
        val AA = A
        val BB = B
        val CC = C
        val DD = D

        ints.clear()
        repeat(16) { ints.put(bytes.int.reversed()) }

        // round 1
        A = nl_1(A, B, C, D, 0, 3)
        D = nl_1(D, A, B, C, 1, 7)
        C = nl_1(C, D, A, B, 2, 11)
        B = nl_1(B, C, D, A, 3, 19)
        A = nl_1(A, B, C, D, 4, 3)
        D = nl_1(D, A, B, C, 5, 7)
        C = nl_1(C, D, A, B, 6, 11)
        B = nl_1(B, C, D, A, 7, 19)
        A = nl_1(A, B, C, D, 8, 3)
        D = nl_1(D, A, B, C, 9, 7)
        C = nl_1(C, D, A, B, 10, 11)
        B = nl_1(B, C, D, A, 11, 19)
        A = nl_1(A, B, C, D, 12, 3)
        D = nl_1(D, A, B, C, 13, 7)
        C = nl_1(C, D, A, B, 14, 11)
        B = nl_1(B, C, D, A, 15, 19)

        // round 2
        A = nl_2(A, B, C, D, 0, 3)
        D = nl_2(D, A, B, C, 4, 5)
        C = nl_2(C, D, A, B, 8, 9)
        B = nl_2(B, C, D, A, 12, 13)
        A = nl_2(A, B, C, D, 1, 3)
        D = nl_2(D, A, B, C, 5, 5)
        C = nl_2(C, D, A, B, 9, 9)
        B = nl_2(B, C, D, A, 13, 13)
        A = nl_2(A, B, C, D, 2, 3)
        D = nl_2(D, A, B, C, 6, 5)
        C = nl_2(C, D, A, B, 10, 9)
        B = nl_2(B, C, D, A, 14, 13)
        A = nl_2(A, B, C, D, 3, 3)
        D = nl_2(D, A, B, C, 7, 5)
        C = nl_2(C, D, A, B, 11, 9)
        B = nl_2(B, C, D, A, 15, 13)

        // round 3
        A = nl_3(A, B, C, D, 0, 3)
        D = nl_3(D, A, B, C, 8, 9)
        C = nl_3(C, D, A, B, 4, 11)
        B = nl_3(B, C, D, A, 12, 15)
        A = nl_3(A, B, C, D, 2, 3)
        D = nl_3(D, A, B, C, 10, 9)
        C = nl_3(C, D, A, B, 6, 11)
        B = nl_3(B, C, D, A, 14, 15)
        A = nl_3(A, B, C, D, 1, 3)
        D = nl_3(D, A, B, C, 9, 9)
        C = nl_3(C, D, A, B, 5, 11)
        B = nl_3(B, C, D, A, 13, 15)
        A = nl_3(A, B, C, D, 3, 3)
        D = nl_3(D, A, B, C, 11, 9)
        C = nl_3(C, D, A, B, 7, 11)
        B = nl_3(B, C, D, A, 15, 15)


        A += AA
        B += BB
        C += CC
        D += DD
    }

    bytes.clear()
    bytes.putInt(A.reversed())
    bytes.putInt(B.reversed())
    bytes.putInt(C.reversed())
    bytes.putInt(D.reversed())

    return bytes.array().sliceArray(0..15)
}
