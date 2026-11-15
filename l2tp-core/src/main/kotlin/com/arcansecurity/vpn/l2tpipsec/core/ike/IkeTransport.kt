package com.arcansecurity.vpn.l2tpipsec.core.ike

import com.arcansecurity.vpn.l2tpipsec.core.crypto.DhGroup
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspIntegrity
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeHash
import java.net.InetAddress

/**
 * The two UDP endpoints the negotiator talks through. Implemented by the tunnel layer.
 *
 * The negotiator never sees sockets: it hands over complete ISAKMP datagrams and the transport
 * decides whether they leave on UDP/500 or on UDP/4500 behind the four-byte non-ESP marker of
 * RFC 3948 section 2.2.
 */
interface IkeTransport {
    val localAddress: InetAddress
    val localPort: Int
    val remoteAddress: InetAddress

    /** true once messages must go to UDP/4500 with the 4-byte non-ESP marker. */
    val natTraversalActive: Boolean

    fun enableNatTraversal()

    /** Sends one raw ISAKMP message (you supply header+payloads; the transport adds the marker). */
    fun sendIsakmp(message: ByteArray)

    /** Next raw ISAKMP message (marker already stripped), or null on timeout. */
    fun receiveIsakmp(timeoutMs: Int): ByteArray?

    /**
     * Hands back a datagram addressed to an ISAKMP SA this negotiator does not own.
     *
     * A phase-1 rekey builds a second negotiator that reads the very same inbound stream while the
     * SA being replaced is still live, so everything the peer sends on that older SA — a DPD
     * R-U-THERE, a Delete, a Quick Mode it started — arrives at a negotiator holding none of the
     * keys it was encrypted under. Dropping it is what makes a peer conclude the tunnel is dead, so
     * it is parked here for whoever does own that SA.
     *
     * Implementations must never hand the message back through [receiveIsakmp]: the negotiator
     * would read it, fail to own it again, and spin. They must also bound whatever they park it in,
     * because a peer can keep sending for as long as the rekey lasts.
     */
    fun deferForeignMessage(message: ByteArray)
}

/**
 * Everything phase 2, the ESP layer and the informational exchanges need from a completed
 * ISAKMP SA.
 */
data class Phase1Result(
    val initiatorCookie: ByteArray,
    val responderCookie: ByteArray,
    val encryption: IkeEncryption,
    val hash: IkeHash,
    val dhGroup: DhGroup,
    val skeyid: ByteArray,
    val skeyidD: ByteArray,
    val skeyidA: ByteArray,
    val skeyidE: ByteArray,
    val encryptionKey: ByteArray,
    /** Final phase-1 CBC block; seeds every Quick Mode IV. */
    val phase1Iv: ByteArray,
    val localBehindNat: Boolean,
    val remoteBehindNat: Boolean,
    val natTraversalFlavor: NatTraversalFlavor,
    val localIdentity: ByteArray,
    val remoteIdentity: ByteArray,
    /** The lifetime the responder settled on, which is what the rekey schedule must follow. */
    val lifetimeSeconds: Int,
)

/**
 * What a received Informational exchange asked for.
 *
 * Deletes have to be reported rather than acted on here, because only the tunnel knows which SAs
 * are still in use: once rekeying is in play the peer routinely deletes the *previous* IPsec SA,
 * and treating that as "the tunnel is gone" would tear down a perfectly healthy connection.
 */
data class InformationalResult(
    /**
     * SPIs the peer is tearing down. RFC 2408 section 3.15 says these are the sender's own inbound
     * SPIs, so they are the SPIs *we* send on.
     */
    val deletedEspSpis: List<Int> = emptyList(),
    val isakmpDeleted: Boolean = false,
)

/** One negotiated pair of ESP SAs, one per direction. */
data class Phase2Result(
    /** SPI we chose; the peer sends ESP to us with this SPI. */
    val inboundSpi: Int,
    /** SPI the peer chose; we send ESP with this SPI. */
    val outboundSpi: Int,
    val inboundEncryptionKey: ByteArray,
    val inboundIntegrityKey: ByteArray,
    val outboundEncryptionKey: ByteArray,
    val outboundIntegrityKey: ByteArray,
    val encryption: EspEncryption,
    val integrity: EspIntegrity,
    val lifetimeSeconds: Int,
    val udpEncapsulated: Boolean,
)
