package com.arcansecurity.vpn.l2tpipsec.core.ike

import com.arcansecurity.vpn.l2tpipsec.core.crypto.Prf
import com.arcansecurity.vpn.l2tpipsec.core.util.ByteWriter
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes

/**
 * The IKEv1 key schedule (RFC 2409 section 5) and the NAT-D hash of RFC 3947, as pure functions.
 *
 * They are deliberately free of any negotiator state so unit tests can pin every derived value:
 * a silent change here produces a tunnel that negotiates happily and then drops every packet,
 * which is close to undebuggable from the client side.
 */
object IkeKeyDerivation {

    class Phase1Keys(
        val skeyid: ByteArray,
        val skeyidD: ByteArray,
        val skeyidA: ByteArray,
        val skeyidE: ByteArray,
        /** SKEYID_e stretched or truncated to the negotiated cipher's key length. */
        val encryptionKey: ByteArray,
    )

    /**
     * ```
     * SKEYID   = prf(psk, Ni_b | Nr_b)
     * SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0)
     * SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)
     * SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)
     * ```
     */
    fun phase1(
        prf: Prf,
        presharedKey: ByteArray,
        ni: ByteArray,
        nr: ByteArray,
        gxy: ByteArray,
        initiatorCookie: ByteArray,
        responderCookie: ByteArray,
        cipherKeyBytes: Int,
    ): Phase1Keys {
        val skeyid = prf.mac(presharedKey, ni, nr)
        val skeyidD = prf.mac(skeyid, gxy, initiatorCookie, responderCookie, byteArrayOf(0))
        val skeyidA = prf.mac(skeyid, skeyidD, gxy, initiatorCookie, responderCookie, byteArrayOf(1))
        val skeyidE = prf.mac(skeyid, skeyidA, gxy, initiatorCookie, responderCookie, byteArrayOf(2))
        return Phase1Keys(skeyid, skeyidD, skeyidA, skeyidE, cipherKey(prf, skeyidE, cipherKeyBytes))
    }

    /**
     * RFC 2409 appendix B: a SKEYID_e that is already long enough is simply truncated, otherwise it
     * is stretched with `K1 = prf(SKEYID_e, 0x00)` and `Kn = prf(SKEYID_e, K(n-1))`. The seed is
     * *not* repeated in later blocks, which is what distinguishes this from [Prf.expand].
     */
    fun cipherKey(prf: Prf, skeyidE: ByteArray, length: Int): ByteArray {
        if (skeyidE.size >= length) return Bytes.truncate(skeyidE, length)
        val out = ByteWriter(length + prf.outputBytes)
        var block = prf.mac(skeyidE, ByteArray(1))
        out.bytes(block)
        while (out.size < length) {
            block = prf.mac(skeyidE, block)
            out.bytes(block)
        }
        return Bytes.truncate(out.toByteArray(), length)
    }

    /**
     * The phase-1 authentication hash. Seen from the initiator it is
     * `HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b)`; the responder computes
     * `HASH_R` with the two public values, the two cookies and its own identity swapped in, so the
     * same function serves both by naming the arguments "own" and "peer". [saBody] is always the
     * *initiator's* SA payload body.
     */
    fun phase1AuthHash(
        prf: Prf,
        skeyid: ByteArray,
        ownPublicValue: ByteArray,
        peerPublicValue: ByteArray,
        ownCookie: ByteArray,
        peerCookie: ByteArray,
        saBody: ByteArray,
        idBody: ByteArray,
    ): ByteArray = prf.mac(skeyid, ownPublicValue, peerPublicValue, ownCookie, peerCookie, saBody, idBody)

    /**
     * RFC 2409 section 5.5:
     * `KEYMAT = prf+(SKEYID_d, [g(qm)^xy |] protocol | SPI | Ni_b | Nr_b)`.
     *
     * [spi] identifies the SA whose keys are being derived, so the caller must run this once per
     * direction: our own SPI yields the keys the peer encrypts with, the peer's SPI yields ours.
     */
    fun keymat(
        prf: Prf,
        skeyidD: ByteArray,
        quickModeSecret: ByteArray,
        protocolId: Int,
        spi: Int,
        ni: ByteArray,
        nr: ByteArray,
        length: Int,
    ): ByteArray {
        val seed = ByteWriter(16 + quickModeSecret.size + ni.size + nr.size)
            .bytes(quickModeSecret)
            .u8(protocolId)
            .i32(spi)
            .bytes(ni)
            .bytes(nr)
            .toByteArray()
        return prf.expand(skeyidD, seed, length)
    }

    /** RFC 3947 section 3.2: `HASH = hash(CKY-I | CKY-R | address | port)`, a plain digest. */
    fun natDiscoveryHash(
        prf: Prf,
        initiatorCookie: ByteArray,
        responderCookie: ByteArray,
        address: ByteArray,
        port: Int,
    ): ByteArray = prf.digest(
        initiatorCookie, responderCookie, address, ByteWriter(2).u16(port).toByteArray(),
    )
}
