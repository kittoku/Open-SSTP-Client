package com.arcansecurity.vpn.l2tpipsec.core.crypto

import java.math.BigInteger

/**
 * IKEv1 phase-1 encryption algorithms (RFC 2409 appendix A, "Encryption Algorithm" attribute).
 * [keyBits] is carried separately in the Key Length attribute for the variable-length ciphers.
 */
enum class IkeEncryption(
    val transformId: Int,
    val keyBits: Int,
    val blockBytes: Int,
    val jceTransformation: String,
    val jceKeyAlgorithm: String,
    /** AES needs an explicit Key Length attribute; 3DES must not carry one. */
    val needsKeyLengthAttribute: Boolean,
) {
    TRIPLE_DES_CBC(5, 192, 8, "DESede/CBC/NoPadding", "DESede", false),
    AES_CBC_128(7, 128, 16, "AES/CBC/NoPadding", "AES", true),
    AES_CBC_192(7, 192, 16, "AES/CBC/NoPadding", "AES", true),
    AES_CBC_256(7, 256, 16, "AES/CBC/NoPadding", "AES", true),
    ;

    val keyBytes: Int get() = keyBits / 8

    companion object {
        fun find(transformId: Int, keyBits: Int?): IkeEncryption? = entries.firstOrNull {
            it.transformId == transformId && (keyBits == null || it.keyBits == keyBits)
        }
    }
}

/**
 * IKEv1 phase-1 hash algorithms ("Hash Algorithm" attribute). The same primitive is used as the
 * PRF for SKEYID derivation, as IKEv1 has no separate PRF negotiation.
 */
enum class IkeHash(
    val transformId: Int,
    val jceDigest: String,
    val jceMac: String,
    val outputBytes: Int,
) {
    MD5(1, "MD5", "HmacMD5", 16),
    SHA1(2, "SHA-1", "HmacSHA1", 20),
    SHA2_256(4, "SHA-256", "HmacSHA256", 32),
    SHA2_384(5, "SHA-384", "HmacSHA384", 48),
    SHA2_512(6, "SHA-512", "HmacSHA512", 64),
    ;

    companion object {
        fun find(transformId: Int): IkeHash? = entries.firstOrNull { it.transformId == transformId }
    }
}

/** IKEv1 phase-1 authentication method attribute (RFC 2409). Only PSK is implemented. */
object IkeAuthMethod {
    const val PRE_SHARED_KEY = 1
}

/**
 * Diffie-Hellman MODP groups. Primes are the verbatim RFC values; [PrimeSanityTest] checks their
 * bit lengths and primality so a transcription slip cannot silently break key agreement.
 */
enum class DhGroup(val groupId: Int, private val primeHex: String, val generator: Int) {
    MODP_1024(
        2,
        """
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
        E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
        EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
        FFFFFFFF FFFFFFFF
        """,
        2,
    ),
    MODP_1536(
        5,
        """
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
        E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
        EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
        C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
        83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
        670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF
        """,
        2,
    ),
    MODP_2048(
        14,
        """
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
        E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
        EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
        C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
        83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
        670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
        E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
        DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
        15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
        """,
        2,
    ),
    ;

    val prime: BigInteger by lazy {
        BigInteger(primeHex.filterNot { it.isWhitespace() }, 16)
    }

    /** Size in bytes of a public value / shared secret in this group; values are zero-padded to it. */
    val valueBytes: Int get() = (prime.bitLength() + 7) / 8

    companion object {
        fun find(groupId: Int): DhGroup? = entries.firstOrNull { it.groupId == groupId }
    }
}

/**
 * IPsec ESP transform identifiers (RFC 2407 section 4.4.4). Only CBC ciphers are supported: the
 * combined-mode ciphers would require a different ESP layout and are not offered by the target
 * hardware.
 */
enum class EspEncryption(
    val transformId: Int,
    val keyBits: Int,
    val blockBytes: Int,
    val jceTransformation: String,
    val jceKeyAlgorithm: String,
    val needsKeyLengthAttribute: Boolean,
) {
    ESP_3DES(3, 192, 8, "DESede/CBC/NoPadding", "DESede", false),
    ESP_AES_CBC_128(12, 128, 16, "AES/CBC/NoPadding", "AES", true),
    ESP_AES_CBC_192(12, 192, 16, "AES/CBC/NoPadding", "AES", true),
    ESP_AES_CBC_256(12, 256, 16, "AES/CBC/NoPadding", "AES", true),
    ;

    val keyBytes: Int get() = keyBits / 8

    companion object {
        fun find(transformId: Int, keyBits: Int?): EspEncryption? = entries.firstOrNull {
            it.transformId == transformId && (keyBits == null || it.keyBits == keyBits)
        }
    }
}

/**
 * ESP authentication algorithms (the "Authentication Algorithm" SA attribute, RFC 2407 section
 * 4.5; the SHA-2 values come from RFC 4868 section 5.1).
 */
enum class EspIntegrity(
    val attributeValue: Int,
    val jceMac: String,
    val keyBytes: Int,
    val icvBytes: Int,
) {
    HMAC_MD5_96(1, "HmacMD5", 16, 12),
    HMAC_SHA1_96(2, "HmacSHA1", 20, 12),
    HMAC_SHA2_256_128(5, "HmacSHA256", 32, 16),
    HMAC_SHA2_384_192(6, "HmacSHA384", 48, 24),
    HMAC_SHA2_512_256(7, "HmacSHA512", 64, 32),
    ;

    companion object {
        fun find(attributeValue: Int): EspIntegrity? =
            entries.firstOrNull { it.attributeValue == attributeValue }
    }
}
