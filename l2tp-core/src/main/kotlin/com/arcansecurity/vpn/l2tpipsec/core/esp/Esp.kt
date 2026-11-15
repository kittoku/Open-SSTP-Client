package com.arcansecurity.vpn.l2tpipsec.core.esp

/**
 * Thrown on ICV failure, replay, or malformed ESP. Callers drop the offending packet and keep the
 * tunnel running: a single bad datagram on a UDP-encapsulated SA is normal on a lossy link and
 * must never tear down the session (RFC 4303 section 3.4.2).
 */
class EspException(message: String) : Exception(message)

/**
 * Wire layout of an ESP packet as this client uses it (RFC 4303 section 2, CBC cipher + HMAC):
 *
 * ```
 * SPI (4) | Sequence Number (4) | IV (blockBytes) | ciphertext | ICV (icvBytes)
 * ciphertext = E(key, IV, plaintext | padding | padLength (1) | nextHeader (1))
 * ```
 *
 * We always run **transport mode**: the protected `plaintext` is a complete transport-layer
 * datagram - our inner UDP/1701 datagram carrying L2TP - and never an inner IP packet. There is no
 * inner IP header at all; the only IP header on the wire is the outer one of the UDP/4500 datagram
 * the ESP packet travels in (RFC 3948 section 2.1). This is the single most misunderstood point of
 * the design: tunnel mode would put a second IP header inside the ciphertext and set
 * `nextHeader = 4`, which is *not* what an L2TP/IPsec peer expects.
 */
internal object EspLayout {
    const val SPI_SIZE = 4
    const val SEQ_SIZE = 4
    const val HEADER_SIZE = SPI_SIZE + SEQ_SIZE

    /** Trailer bytes that always follow the padding: pad length and next header. */
    const val TRAILER_SIZE = 2

    /**
     * Last usable sequence number. They are 32-bit unsigned and start at 1, and RFC 4303 section
     * 3.3.3 forbids reusing one, so the SA has to be rekeyed rather than wrapped past this.
     */
    const val MAX_SEQ = 0xFFFFFFFFL

    /**
     * Number of pad bytes needed so that `payload | pad | padLength | nextHeader` is a whole
     * number of cipher blocks (RFC 4303 section 2.4).
     */
    fun padLengthFor(payloadLength: Int, blockBytes: Int): Int =
        (blockBytes - ((payloadLength + TRAILER_SIZE) % blockBytes)) % blockBytes

    fun ciphertextLengthFor(payloadLength: Int, blockBytes: Int): Int =
        payloadLength + TRAILER_SIZE + padLengthFor(payloadLength, blockBytes)
}
