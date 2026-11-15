package com.arcansecurity.vpn.l2tpipsec.core.crypto

import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException
import java.math.BigInteger
import java.security.SecureRandom

/**
 * Ephemeral Diffie-Hellman over one of the fixed MODP groups of [DhGroup].
 *
 * IKEv1 (RFC 2409 section 5) transmits public values and consumes the shared secret as fixed-width
 * big-endian integers of exactly the modulus length, so every value leaving this class is
 * left-padded: a shared secret whose leading byte happens to be zero would otherwise change the
 * length of the SKEYID input and break interoperability roughly one time in 256.
 */
class DiffieHellman private constructor(
    val group: DhGroup,
    private val privateValue: BigInteger,
) {

    /** `g^x mod p`, padded to [DhGroup.valueBytes]; goes on the wire in the KE payload. */
    val publicValue: ByteArray =
        encode(BigInteger.valueOf(group.generator.toLong()).modPow(privateValue, group.prime))

    /**
     * `g^xy mod p` from the peer's KE payload, padded to [DhGroup.valueBytes].
     *
     * @throws ProtocolException if the peer's value is outside `[2, p-2]`. Values of 0, 1 and p-1
     *   generate a subgroup of order at most 2, which would let a hostile peer force a shared
     *   secret it already knows.
     */
    fun computeSharedSecret(peerPublicValue: ByteArray): ByteArray {
        val peer = BigInteger(1, peerPublicValue)
        if (peer < TWO || peer > group.prime - TWO) {
            throw ProtocolException("peer DH public value is out of range for group ${group.groupId}")
        }
        return encode(peer.modPow(privateValue, group.prime))
    }

    private fun encode(value: BigInteger): ByteArray {
        val raw = value.toByteArray()
        // BigInteger emits a leading 0x00 whenever the top bit is set, to keep the value positive.
        val magnitude = if (raw.size > 1 && raw[0].toInt() == 0) raw.copyOfRange(1, raw.size) else raw
        return Bytes.leftPad(magnitude, group.valueBytes)
    }

    companion object {
        private val TWO: BigInteger = BigInteger.valueOf(2)
        private val random = SecureRandom()

        /** Fresh key pair with a full-length private exponent drawn from [SecureRandom]. */
        fun generate(group: DhGroup): DiffieHellman {
            val upperBound = group.prime - TWO
            while (true) {
                val candidate = BigInteger(group.prime.bitLength(), random)
                if (candidate >= TWO && candidate <= upperBound) return DiffieHellman(group, candidate)
            }
        }

        /** Deterministic construction, so tests can pin public values and shared secrets. */
        fun fromPrivateValue(group: DhGroup, priv: BigInteger): DiffieHellman {
            require(priv >= TWO && priv <= group.prime - TWO) {
                "private value out of range for group ${group.groupId}"
            }
            return DiffieHellman(group, priv)
        }
    }
}
