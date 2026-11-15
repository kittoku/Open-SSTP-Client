package com.arcansecurity.vpn.l2tpipsec.core.ike

import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import java.security.MessageDigest

/**
 * The vendor IDs this client advertises and recognises.
 *
 * A NAT-T vendor ID is the MD5 of a literal marker string (RFC 3947 section 3.1 and the drafts it
 * grew out of). They are computed at runtime from those strings rather than pasted as hex so the
 * mapping stays auditable.
 */
object VendorIds {

    /** RFC 3947, the final NAT traversal specification. */
    val RFC_3947: ByteArray = md5("RFC 3947")

    /**
     * draft-02 with the trailing newline. The draft text accidentally included it and several
     * widely deployed stacks hash the string with it, so both variants are offered and accepted.
     */
    val DRAFT_02_NEWLINE: ByteArray = md5("draft-ietf-ipsec-nat-t-ike-02\n")

    val DRAFT_02: ByteArray = md5("draft-ietf-ipsec-nat-t-ike-02")

    val DRAFT_03: ByteArray = md5("draft-ietf-ipsec-nat-t-ike-03")

    /** RFC 3706 dead peer detection, version 1.0; a fixed constant rather than a hash. */
    val DPD_1_0: ByteArray = Bytes.fromHex("AFCAD71368A1F1C96B8696FC77570100")

    /** The vendor IDs sent in the first message, in the order they go on the wire. */
    val OFFERED: List<ByteArray> = listOf(RFC_3947, DRAFT_02_NEWLINE, DRAFT_02, DRAFT_03, DPD_1_0)

    /**
     * Picks the best NAT traversal dialect the peer advertised. RFC 3947 wins over the drafts, and
     * draft-03 over draft-02, because a peer offering several will always prefer the newest.
     */
    fun selectNatTraversalFlavor(peerVendorIds: List<ByteArray>): NatTraversalFlavor = when {
        peerVendorIds.any { it.contentEquals(RFC_3947) } -> NatTraversalFlavor.RFC_3947
        peerVendorIds.any { it.contentEquals(DRAFT_03) } -> NatTraversalFlavor.DRAFT_03
        peerVendorIds.any {
            it.contentEquals(DRAFT_02) || it.contentEquals(DRAFT_02_NEWLINE)
        } -> NatTraversalFlavor.DRAFT_02
        else -> NatTraversalFlavor.NONE
    }

    fun supportsDpd(peerVendorIds: List<ByteArray>): Boolean =
        peerVendorIds.any { it.contentEquals(DPD_1_0) }

    private fun md5(marker: String): ByteArray =
        MessageDigest.getInstance("MD5").digest(marker.toByteArray(Charsets.US_ASCII))
}
