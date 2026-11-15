package com.arcansecurity.vpn.l2tpipsec.core.esp

import com.arcansecurity.vpn.l2tpipsec.core.crypto.CbcCipher
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspIntegrity
import com.arcansecurity.vpn.l2tpipsec.core.net.Ipv4Header
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Outbound half of an IPsec SA: encrypt-then-MAC ESP in **transport mode**, as negotiated by IKEv1
 * quick mode and carried inside UDP/4500 (RFC 3948).
 *
 * Because the SA is a transport-mode one, [encapsulate] takes a complete *transport-layer*
 * datagram - the inner UDP/1701 datagram carrying L2TP - and [nextHeader] is therefore 17 (UDP).
 * No inner IP header is built or expected; see [EspLayout] for the full rationale and the wire
 * layout.
 *
 * The ICV covers `SPI | Seq | IV | ciphertext` only, never the outer IP/UDP headers, which is
 * exactly why a NAT on the path may rewrite the outer addresses and ports without breaking the
 * integrity check.
 *
 * Not thread-safe on its own: the sequence number is atomic, so numbers are never reused, but the
 * [Mac] instance is shared. Drive one SA from one sender thread.
 */
class EspOutboundSa(
    val spi: Int,
    val encryption: EspEncryption,
    val integrity: EspIntegrity,
    encryptionKey: ByteArray,
    integrityKey: ByteArray,
) {

    private val encKey = encryptionKey.copyOf()
    private val cipher = CbcCipher.forEsp(encryption)
    private val mac: Mac = Mac.getInstance(integrity.jceMac)
    private val seq = AtomicLong(0)

    /**
     * Source of the per-packet IV. RFC 4303 section 3.3.2.1 requires it to be unpredictable, hence
     * the CSPRNG; tests replace it to pin a known-answer vector.
     */
    internal var ivSource: (Int) -> ByteArray = { Bytes.random(it) }

    init {
        require(encryptionKey.size == encryption.keyBytes) {
            "${encryption.name} needs a ${encryption.keyBytes}-byte key, got ${encryptionKey.size}"
        }
        require(integrityKey.size == integrity.keyBytes) {
            "${integrity.name} needs a ${integrity.keyBytes}-byte key, got ${integrityKey.size}"
        }
        mac.init(SecretKeySpec(integrityKey, integrity.jceMac))
    }

    /** Sequence number of the most recently emitted packet; 0 before the first one. */
    val sequenceNumber: Long get() = seq.get()

    /**
     * True once the counter is close enough to 2^32 that the SA must be rekeyed. RFC 4303 section
     * 3.3.3 forbids reusing a sequence number, so the SA has to be replaced *before* the wrap; the
     * margin leaves room for the packets already in flight.
     */
    val exhausted: Boolean get() = seq.get() >= REKEY_THRESHOLD

    /** Bytes of ESP overhead added to a payload of [payloadLength] bytes. */
    fun overheadFor(payloadLength: Int): Int = packetLength(payloadLength) - payloadLength

    /** Total on-the-wire size of the ESP packet produced for a payload of [payloadLength] bytes. */
    fun packetLength(payloadLength: Int): Int =
        EspLayout.HEADER_SIZE + encryption.blockBytes +
            EspLayout.ciphertextLengthFor(payloadLength, encryption.blockBytes) + integrity.icvBytes

    /**
     * Wraps [payload] (a complete transport-layer datagram, since we run ESP in transport mode).
     *
     * @param nextHeader IP protocol number of [payload]; 17 (UDP) for the L2TP datagram.
     */
    fun encapsulate(
        payload: ByteArray,
        payloadOffset: Int = 0,
        payloadLength: Int = payload.size - payloadOffset,
        nextHeader: Int = Ipv4Header.PROTO_UDP,
    ): ByteArray {
        // Checked here as well as in encapsulateInto: a negative length would otherwise blow up in
        // the array allocation below, before the message that says what is actually wrong.
        require(payloadLength >= 0) { "negative payload length $payloadLength" }
        val out = ByteArray(packetLength(payloadLength))
        encapsulateInto(out, 0, payload, payloadOffset, payloadLength, nextHeader)
        return out
    }

    /**
     * Encodes straight into [out] at [outOffset] and returns the byte count. For callers that own
     * a big enough buffer - a reusable socket buffer, say - and want to skip the allocation
     * [encapsulate] makes per packet.
     *
     * [out] may be the same array as [payload]: the plaintext is assembled in a scratch buffer
     * before anything is written back.
     *
     * @throws EspException when the 32-bit sequence number space is used up; see [exhausted].
     */
    fun encapsulateInto(
        out: ByteArray,
        outOffset: Int,
        payload: ByteArray,
        payloadOffset: Int,
        payloadLength: Int,
        nextHeader: Int = Ipv4Header.PROTO_UDP,
    ): Int {
        require(payloadLength >= 0) { "negative payload length $payloadLength" }
        require(nextHeader in 0..0xFF) { "next header $nextHeader does not fit in a byte" }
        // Every range check here is a subtraction, never a sum: the sums can overflow an `Int` and
        // a wrapped comparison would pass.
        require(payloadOffset >= 0 && payloadLength <= payload.size - payloadOffset) {
            "payload range of $payloadLength bytes at $payloadOffset outside ${payload.size} bytes"
        }
        val blockBytes = encryption.blockBytes
        val total = packetLength(payloadLength)
        require(outOffset >= 0 && total <= out.size - outOffset) {
            "output buffer too small: need $total bytes at $outOffset, have ${out.size}"
        }

        val sequence = seq.incrementAndGet()
        if (sequence > EspLayout.MAX_SEQ) {
            throw EspException("ESP sequence number space exhausted on SPI ${spiHex()}; SA must be rekeyed")
        }

        // plaintext = payload | padding | padLength | nextHeader (RFC 4303 section 2.4). The
        // default pad pattern is the monotonically increasing sequence 1, 2, 3, ...
        val padLength = EspLayout.padLengthFor(payloadLength, blockBytes)
        val plaintext = ByteArray(payloadLength + padLength + EspLayout.TRAILER_SIZE)
        System.arraycopy(payload, payloadOffset, plaintext, 0, payloadLength)
        for (i in 0 until padLength) plaintext[payloadLength + i] = (i + 1).toByte()
        plaintext[plaintext.size - 2] = padLength.toByte()
        plaintext[plaintext.size - 1] = nextHeader.toByte()

        val iv = ivSource(blockBytes)
        val ciphertext = cipher.encrypt(encKey, iv, plaintext)

        var p = outOffset
        out[p++] = (spi ushr 24).toByte()
        out[p++] = (spi ushr 16).toByte()
        out[p++] = (spi ushr 8).toByte()
        out[p++] = spi.toByte()
        out[p++] = (sequence ushr 24).toByte()
        out[p++] = (sequence ushr 16).toByte()
        out[p++] = (sequence ushr 8).toByte()
        out[p++] = sequence.toByte()
        System.arraycopy(iv, 0, out, p, blockBytes)
        p += blockBytes
        System.arraycopy(ciphertext, 0, out, p, ciphertext.size)
        p += ciphertext.size

        // ICV = truncate(HMAC(key, SPI | Seq | IV | ciphertext)). The outer IP/UDP headers are
        // deliberately not covered, so NAT rewriting on the path is harmless.
        mac.reset()
        mac.update(out, outOffset, p - outOffset)
        val icv = mac.doFinal()
        System.arraycopy(icv, 0, out, p, integrity.icvBytes)
        return total
    }

    /**
     * Maximum plaintext that still fits in [espPacketBudget] bytes on the wire, i.e. the largest
     * `n` with `8 + blockBytes + roundUp(n + 2, blockBytes) + icvBytes <= budget`. Returns 0 when
     * not even an empty payload fits, which the caller must read as "cannot send".
     */
    fun maxPayloadFor(espPacketBudget: Int): Int {
        val blockBytes = encryption.blockBytes
        val available = espPacketBudget - EspLayout.HEADER_SIZE - blockBytes - integrity.icvBytes
        if (available < blockBytes) return 0
        // The ciphertext is a whole number of blocks, so rounding the budget down to a block
        // boundary and subtracting the 2 trailer bytes is exact.
        val ciphertext = (available / blockBytes) * blockBytes
        return (ciphertext - EspLayout.TRAILER_SIZE).coerceAtLeast(0)
    }

    /** Test hook: forces the counter so the wrap and known-answer paths can be exercised. */
    internal fun setSequenceNumber(value: Long) = seq.set(value)

    private fun spiHex(): String = "0x%08x".format(spi)

    companion object {
        /**
         * The SA reports itself [exhausted] once it reaches this number, reserving the top 16
         * values of the space. Rekeying takes a round trip, and the 15 numbers still left after
         * the flag goes up are what the packets already queued behind it get to use.
         */
        const val REKEY_THRESHOLD = 0xFFFFFFF0L
    }
}
