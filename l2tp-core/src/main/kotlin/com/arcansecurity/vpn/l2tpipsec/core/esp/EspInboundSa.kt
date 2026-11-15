package com.arcansecurity.vpn.l2tpipsec.core.esp

import com.arcansecurity.vpn.l2tpipsec.core.crypto.CbcCipher
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspIntegrity
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Inbound half of an IPsec SA: verify, replay-check, decrypt and strip the ESP trailer.
 *
 * Mirror image of [EspOutboundSa], so the recovered payload is again a complete transport-layer
 * datagram (transport mode, RFC 3948 section 2.1) and never an inner IP packet.
 *
 * Not thread-safe: the replay window and the [Mac] instance are mutable. Drive one SA from one
 * receive thread.
 */
class EspInboundSa(
    val spi: Int,
    val encryption: EspEncryption,
    val integrity: EspIntegrity,
    encryptionKey: ByteArray,
    integrityKey: ByteArray,
    replayWindowSize: Int = 64,
) {

    private val encKey = encryptionKey.copyOf()
    private val cipher = CbcCipher.forEsp(encryption)
    private val mac: Mac = Mac.getInstance(integrity.jceMac)
    private val replayWindow = AntiReplayWindow(replayWindowSize)

    init {
        require(encryptionKey.size == encryption.keyBytes) {
            "${encryption.name} needs a ${encryption.keyBytes}-byte key, got ${encryptionKey.size}"
        }
        require(integrityKey.size == integrity.keyBytes) {
            "${integrity.name} needs a ${integrity.keyBytes}-byte key, got ${integrityKey.size}"
        }
        mac.init(SecretKeySpec(integrityKey, integrity.jceMac))
    }

    /** Recovered transport-layer datagram plus the two fields the ESP trailer carried. */
    data class Decapsulated(val payload: ByteArray, val nextHeader: Int, val sequenceNumber: Long) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Decapsulated) return false
            return nextHeader == other.nextHeader && sequenceNumber == other.sequenceNumber &&
                payload.contentEquals(other.payload)
        }

        override fun hashCode(): Int =
            (payload.contentHashCode() * 31 + nextHeader) * 31 + sequenceNumber.hashCode()
    }

    private var accepted = 0L
    private var dropped = 0L

    val packetsAccepted: Long get() = accepted
    val packetsDropped: Long get() = dropped

    /** Highest sequence number accepted so far, for diagnostics. */
    val highestSequenceNumber: Long get() = replayWindow.highest

    /**
     * Verifies the ICV, checks the replay window, decrypts and strips the trailer.
     *
     * The order matters and follows RFC 4303 section 3.4.4: the ICV is checked *first* and in
     * constant time, so a forged packet can neither advance the replay window nor reach the
     * cipher. Only the length and the SPI - the demultiplexing fields, which carry no secret - are
     * looked at before it.
     *
     * That ordering is what closes the padding oracle. Reaching the cipher at all takes a valid
     * ICV, which takes the integrity key, so an attacker never gets to tell a well-padded
     * plaintext from a badly padded one: everything they can produce fails the same comparison,
     * over the same number of bytes, before any of the decrypt path runs.
     *
     * Every failure raises [EspException] and bumps [packetsDropped]. The message names the
     * failing check, for the log only.
     */
    fun decapsulate(packet: ByteArray, offset: Int = 0, length: Int = packet.size - offset): Decapsulated {
        try {
            val result = decapsulateOrThrow(packet, offset, length)
            accepted++
            return result
        } catch (e: EspException) {
            dropped++
            throw e
        } catch (e: Exception) {
            // A provider-level failure (bad key material, unusable transformation) is still just a
            // dropped packet as far as the tunnel is concerned.
            dropped++
            throw EspException("ESP decapsulation failed: ${e.message}")
        }
    }

    private fun decapsulateOrThrow(packet: ByteArray, offset: Int, length: Int): Decapsulated {
        val blockBytes = encryption.blockBytes
        val icvBytes = integrity.icvBytes
        // A subtraction, not a sum: `offset + length` can overflow an `Int` and a wrapped
        // comparison would let a range that is not in the buffer through to the MAC and the cipher.
        if (offset < 0 || length < 0 || length > packet.size - offset) {
            throw EspException("ESP range of $length bytes at $offset outside a ${packet.size}-byte buffer")
        }
        // Header + IV + at least one ciphertext block + ICV.
        val minimum = EspLayout.HEADER_SIZE + blockBytes + blockBytes + icvBytes
        if (length < minimum) throw EspException("ESP packet too short: $length < $minimum")
        val ciphertextLength = length - EspLayout.HEADER_SIZE - blockBytes - icvBytes
        if (ciphertextLength % blockBytes != 0) {
            throw EspException("ESP ciphertext of $ciphertextLength bytes is not a multiple of $blockBytes")
        }

        val receivedSpi = readInt(packet, offset)
        if (receivedSpi != spi) {
            throw EspException(
                "ESP SPI mismatch: got ${"0x%08x".format(receivedSpi)}, expected ${"0x%08x".format(spi)}",
            )
        }
        val sequence = readInt(packet, offset + EspLayout.SPI_SIZE).toLong() and 0xFFFFFFFFL

        // 1. Integrity first: the ICV covers SPI | Seq | IV | ciphertext, never the outer headers.
        val icvOffset = offset + length - icvBytes
        mac.reset()
        mac.update(packet, offset, length - icvBytes)
        val expected = Bytes.truncate(mac.doFinal(), icvBytes)
        val received = packet.copyOfRange(icvOffset, icvOffset + icvBytes)
        if (!Bytes.constantTimeEquals(expected, received)) {
            throw EspException("ESP ICV check failed on sequence $sequence")
        }

        // 2. Replay window, updated only now that the packet is known to be authentic.
        if (!replayWindow.accept(sequence)) {
            throw EspException("ESP replay detected: sequence $sequence (highest ${replayWindow.highest})")
        }

        // 3. Decrypt, then strip padding | padLength | nextHeader.
        val ivOffset = offset + EspLayout.HEADER_SIZE
        val iv = packet.copyOfRange(ivOffset, ivOffset + blockBytes)
        val ciphertextOffset = ivOffset + blockBytes
        val ciphertext = packet.copyOfRange(ciphertextOffset, ciphertextOffset + ciphertextLength)
        val plaintext = cipher.decrypt(encKey, iv, ciphertext)

        val padLength = plaintext[plaintext.size - 2].toInt() and 0xFF
        val nextHeader = plaintext[plaintext.size - 1].toInt() and 0xFF
        val payloadLength = plaintext.size - EspLayout.TRAILER_SIZE - padLength
        if (payloadLength < 0) {
            throw EspException("ESP pad length $padLength exceeds the ${plaintext.size}-byte plaintext")
        }
        // RFC 4303 section 2.4 lets the sender choose the pad bytes, so their value is not checked.
        return Decapsulated(plaintext.copyOf(payloadLength), nextHeader, sequence)
    }

    /** True when [sequence] would be rejected by the replay window; used by the tunnel's stats. */
    fun isReplay(sequence: Long): Boolean = replayWindow.isReplay(sequence)

    private fun readInt(b: ByteArray, at: Int): Int =
        ((b[at].toInt() and 0xFF) shl 24) or ((b[at + 1].toInt() and 0xFF) shl 16) or
            ((b[at + 2].toInt() and 0xFF) shl 8) or (b[at + 3].toInt() and 0xFF)
}
