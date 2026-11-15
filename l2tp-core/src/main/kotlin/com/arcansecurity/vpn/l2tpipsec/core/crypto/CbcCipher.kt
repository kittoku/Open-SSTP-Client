package com.arcansecurity.vpn.l2tpipsec.core.crypto

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A raw CBC block cipher with no padding scheme of its own.
 *
 * Both ISAKMP (RFC 2409 appendix B) and ESP (RFC 4303) do their own padding and manage the IV
 * explicitly — ISAKMP chains it from the previous ciphertext block, ESP carries it in the packet —
 * so the JCE must never be allowed to add PKCS#7 padding or generate an IV.
 *
 * Instances are cheap, immutable and safe to share between threads, which the ESP layer relies on:
 * one outbound SA is encrypted from the uplink thread, from the maintenance thread's L2TP HELLOs
 * and from the control path.
 */
class CbcCipher(
    val transformation: String,
    val keyAlgorithm: String,
    val blockBytes: Int,
) {

    fun encrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray =
        crypt(Cipher.ENCRYPT_MODE, key, iv, plaintext)

    fun decrypt(key: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray =
        crypt(Cipher.DECRYPT_MODE, key, iv, ciphertext)

    private fun crypt(mode: Int, key: ByteArray, iv: ByteArray, input: ByteArray): ByteArray {
        require(iv.size == blockBytes) { "IV must be $blockBytes bytes, got ${iv.size}" }
        require(input.size % blockBytes == 0) {
            "input of ${input.size} bytes is not a multiple of the $blockBytes-byte block"
        }
        val cipher = borrow(transformation)
        cipher.init(mode, SecretKeySpec(key, keyAlgorithm), IvParameterSpec(iv))
        return cipher.doFinal(input)
    }

    companion object {
        /**
         * One [Cipher] per calling thread and transformation.
         *
         * `Cipher.getInstance` parses the transformation and walks the provider list on every call,
         * which on the ESP data path means a provider lookup and a fresh object graph for every
         * packet in both directions. The object itself is reusable — `init` re-keys it completely,
         * and every caller here re-inits with a new IV for every message anyway — but
         * `javax.crypto.Cipher` is *not* thread-safe and a [CbcCipher] is shared across threads, so
         * a single cached instance would silently interleave two packets' state under load.
         *
         * The cache is keyed by transformation and held in one class-level [ThreadLocal] rather
         * than a field, because [CbcCipher] instances are created per informational exchange in the
         * IKE layer; a per-instance ThreadLocal would leave a stale entry in every thread's map for
         * each of them. Only the handful of transformations this stack knows can ever be cached,
         * and they are released when the thread that used them dies with its tunnel.
         */
        private val perThreadCiphers: ThreadLocal<MutableMap<String, Cipher>> =
            ThreadLocal.withInitial { HashMap(4) }

        private fun borrow(transformation: String): Cipher =
            perThreadCiphers.get().getOrPut(transformation) { Cipher.getInstance(transformation) }

        fun forIke(alg: IkeEncryption): CbcCipher =
            CbcCipher(alg.jceTransformation, alg.jceKeyAlgorithm, alg.blockBytes)

        fun forEsp(alg: EspEncryption): CbcCipher =
            CbcCipher(alg.jceTransformation, alg.jceKeyAlgorithm, alg.blockBytes)
    }
}
