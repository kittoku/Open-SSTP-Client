package com.arcansecurity.vpn.l2tpipsec.core.crypto

import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.ByteWriter
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The pseudo-random function of an IKEv1 exchange.
 *
 * IKEv1 has no separate PRF negotiation (RFC 2409 section 5): the negotiated hash algorithm is used
 * both as an HMAC — for SKEYID, the authentication hashes and KEYMAT — and as a plain digest, for
 * the initial CBC IV and the NAT-D payloads of RFC 3947.
 */
class Prf(val hash: IkeHash) {

    val outputBytes: Int get() = hash.outputBytes

    /** `HMAC-hash(key, data[0] | data[1] | ...)`. */
    fun mac(key: ByteArray, vararg data: ByteArray): ByteArray {
        // A zero-length key is rejected by the JCE with an opaque error; catch it here instead.
        require(key.isNotEmpty()) { "PRF key must not be empty" }
        val mac = Mac.getInstance(hash.jceMac)
        mac.init(SecretKeySpec(key, hash.jceMac))
        for (part in data) mac.update(part)
        return mac.doFinal()
    }

    /** `hash(data[0] | data[1] | ...)` with no key; used for the phase-1 IV and NAT-D hashes. */
    fun digest(vararg data: ByteArray): ByteArray {
        val md = MessageDigest.getInstance(hash.jceDigest)
        for (part in data) md.update(part)
        return md.digest()
    }

    /**
     * The IKEv1 key expansion of RFC 2409 section 5.5: `K1 = mac(key, seed)`,
     * `Kn = mac(key, K(n-1) | seed)`, and the result is `K1 | K2 | ...` truncated to [length].
     * Used to stretch SKEYID_d into as much KEYMAT as the ESP transforms need.
     */
    fun expand(key: ByteArray, seed: ByteArray, length: Int): ByteArray {
        require(length >= 0) { "negative expansion length $length" }
        if (length == 0) return ByteArray(0)
        val out = ByteWriter(length + outputBytes)
        var block = mac(key, seed)
        out.bytes(block)
        while (out.size < length) {
            block = mac(key, block, seed)
            out.bytes(block)
        }
        return Bytes.truncate(out.toByteArray(), length)
    }
}
