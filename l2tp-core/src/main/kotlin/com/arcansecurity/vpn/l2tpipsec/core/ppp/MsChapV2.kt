package com.arcansecurity.vpn.l2tpipsec.core.ppp

import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/** MS-CHAPv2 primitives, exposed separately because they are worth testing against RFC 2759's vectors. */
object MsChapV2 {

    /** RFC 2759 section 8.7, `Magic1`. */
    private val MAGIC_SERVER_SIGNING = "Magic server to client signing constant".toByteArray(Charsets.US_ASCII)

    /** RFC 2759 section 8.7, `Magic2`. */
    private val MAGIC_SERVER_PAD = "Pad to make it do more than one iteration".toByteArray(Charsets.US_ASCII)

    /** Length of the Response value carried in the CHAP packet: peer challenge, reserved, NT-Response, flags. */
    const val RESPONSE_SIZE = 49

    const val CHALLENGE_SIZE = 16

    /**
     * RFC 2759 section 8.1 `GenerateNTResponse`. Returns the 24-byte NT-Response that goes into
     * bytes 24..47 of the CHAP Response value.
     */
    fun generateNtResponse(
        authenticatorChallenge: ByteArray,
        peerChallenge: ByteArray,
        userName: String,
        password: String,
    ): ByteArray {
        val challenge = challengeHash(peerChallenge, authenticatorChallenge, userName)
        return challengeResponse(challenge, ntPasswordHash(password))
    }

    /**
     * RFC 2759 section 8.7 `GenerateAuthenticatorResponse`. The returned `S=<40 hex digits>` string
     * is what the authenticator puts in its CHAP Success message; comparing it proves the server
     * also knows the password, so it must never be skipped.
     */
    fun generateAuthenticatorResponse(
        password: String,
        ntResponse: ByteArray,
        peerChallenge: ByteArray,
        authenticatorChallenge: ByteArray,
        userName: String,
    ): String {
        require(ntResponse.size == 24) { "NT-Response must be 24 bytes, got ${ntResponse.size}" }
        val passwordHashHash = hashNtPasswordHash(ntPasswordHash(password))
        val sha = MessageDigest.getInstance("SHA-1")
        sha.update(passwordHashHash)
        sha.update(ntResponse)
        sha.update(MAGIC_SERVER_SIGNING)
        val digest = sha.digest()

        val challenge = challengeHash(peerChallenge, authenticatorChallenge, userName)
        sha.reset()
        sha.update(digest)
        sha.update(challenge)
        sha.update(MAGIC_SERVER_PAD)
        return "S=" + Bytes.toHex(sha.digest()).uppercase()
    }

    /** RFC 2759 section 8.4 `NtPasswordHash`: MD4 over the password encoded as UTF-16LE. */
    fun ntPasswordHash(password: String): ByteArray = Md4.digest(password.toByteArray(Charsets.UTF_16LE))

    /** RFC 2759 section 8.5 `HashNtPasswordHash`. */
    fun hashNtPasswordHash(passwordHash: ByteArray): ByteArray = Md4.digest(passwordHash)

    /**
     * RFC 2759 section 8.2 `ChallengeHash`: the first 8 bytes of
     * `SHA1(peerChallenge | authenticatorChallenge | userName)`. The user name is used verbatim as
     * ASCII, without any domain prefix stripping (that is the caller's business).
     */
    fun challengeHash(
        peerChallenge: ByteArray,
        authenticatorChallenge: ByteArray,
        userName: String,
    ): ByteArray {
        require(peerChallenge.size == CHALLENGE_SIZE) { "peer challenge must be 16 bytes" }
        require(authenticatorChallenge.size == CHALLENGE_SIZE) { "authenticator challenge must be 16 bytes" }
        val sha = MessageDigest.getInstance("SHA-1")
        sha.update(peerChallenge)
        sha.update(authenticatorChallenge)
        sha.update(userName.toByteArray(Charsets.US_ASCII))
        return Bytes.truncate(sha.digest(), 8)
    }

    /**
     * RFC 2759 section 8.5 `ChallengeResponse`: the 16-byte hash is zero-padded to 21 bytes, split
     * into three 7-byte DES keys and each key encrypts the 8-byte challenge.
     */
    fun challengeResponse(challenge: ByteArray, passwordHash: ByteArray): ByteArray {
        require(challenge.size == 8) { "challenge must be 8 bytes" }
        require(passwordHash.size == 16) { "password hash must be 16 bytes" }
        val z = passwordHash.copyOf(21)
        val out = ByteArray(24)
        for (i in 0 until 3) {
            val block = desEncrypt(challenge, z, i * 7)
            System.arraycopy(block, 0, out, i * 8, 8)
        }
        return out
    }

    /** DES-ECB with a key derived from 7 key bytes at [keyOffset] (RFC 2759 section 8.6, `DesEncrypt`). */
    private fun desEncrypt(block: ByteArray, keyMaterial: ByteArray, keyOffset: Int): ByteArray {
        val cipher = Cipher.getInstance("DES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(expandDesKey(keyMaterial, keyOffset), "DES"))
        return cipher.doFinal(block)
    }

    /**
     * Spreads 7 key bytes over 8 bytes, leaving the low bit of each byte free for parity
     * (RFC 2759 section 8.6). The cipher ignores the parity bits, but they are set correctly so
     * that providers which validate them stay happy.
     */
    internal fun expandDesKey(key: ByteArray, offset: Int): ByteArray {
        require(offset + 7 <= key.size) { "need 7 key bytes at $offset" }
        fun k(i: Int) = key[offset + i].toInt() and 0xFF
        val out = ByteArray(8)
        out[0] = (k(0) and 0xFE).toByte()
        out[1] = (((k(0) and 0x01) shl 7) or ((k(1) and 0xFC) ushr 1)).toByte()
        out[2] = (((k(1) and 0x03) shl 6) or ((k(2) and 0xF8) ushr 2)).toByte()
        out[3] = (((k(2) and 0x07) shl 5) or ((k(3) and 0xF0) ushr 3)).toByte()
        out[4] = (((k(3) and 0x0F) shl 4) or ((k(4) and 0xE0) ushr 4)).toByte()
        out[5] = (((k(4) and 0x1F) shl 3) or ((k(5) and 0xC0) ushr 5)).toByte()
        out[6] = (((k(5) and 0x3F) shl 2) or ((k(6) and 0x80) ushr 6)).toByte()
        out[7] = ((k(6) and 0x7F) shl 1).toByte()
        for (i in 0 until 8) {
            val v = out[i].toInt() and 0xFE
            out[i] = (v or (1 - (Integer.bitCount(v) and 1))).toByte()
        }
        return out
    }
}
