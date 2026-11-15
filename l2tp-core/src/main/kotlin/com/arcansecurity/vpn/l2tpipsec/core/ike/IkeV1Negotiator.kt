package com.arcansecurity.vpn.l2tpipsec.core.ike

import com.arcansecurity.vpn.l2tpipsec.core.crypto.CbcCipher
import com.arcansecurity.vpn.l2tpipsec.core.crypto.DhGroup
import com.arcansecurity.vpn.l2tpipsec.core.crypto.DiffieHellman
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspIntegrity
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeAuthMethod
import com.arcansecurity.vpn.l2tpipsec.core.crypto.Prf
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.Clock
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeExchangeMode
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeIdentityType
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelErrorKind
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelException
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.VpnConfig
import com.arcansecurity.vpn.l2tpipsec.core.util.ByteReader
import com.arcansecurity.vpn.l2tpipsec.core.util.ByteWriter
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.Log
import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import java.net.InetAddress

/**
 * The IKEv1 initiator: Main or Aggressive Mode with a pre-shared key, Quick Mode for the IPsec SA,
 * NAT traversal per RFC 3947, and the informational exchanges (DPD, Delete) that keep the SA
 * observable and tear it down cleanly.
 *
 * The class is stateful and not thread-safe: it owns the initiator cookie, the responder cookie and
 * the negotiated NAT-T dialect for the whole life of one ISAKMP SA, and every exchange it drives
 * reads and writes those while blocked on the transport. Callers must serialise it — the tunnel
 * rekeys from its maintenance thread while a teardown may arrive from another, and holds a lock
 * across every call for exactly that reason. Everything phase 2 and the ESP layer need is handed
 * back in [Phase1Result] and [Phase2Result].
 */
class IkeV1Negotiator(
    private val config: VpnConfig,
    private val transport: IkeTransport,
    private val clock: Clock = Clock.SYSTEM,
    private val logger: VpnLogger = VpnLogger.NONE,
) {

    private val log = Log(TAG, logger)
    private val prf = Prf(config.phase1.hash)
    private val cipher = CbcCipher.forIke(config.phase1.encryption)
    private val psk = config.presharedKey.toByteArray(Charsets.UTF_8)

    private val initiatorCookie = Bytes.randomNonZero(IsakmpCodec.COOKIE_SIZE)
    private var responderCookie = ByteArray(IsakmpCodec.COOKIE_SIZE)
    private var flavor = NatTraversalFlavor.NONE

    /** Set as soon as phase 1 completes so informational exchanges can be decrypted mid-flight. */
    private var activePhase1: Phase1Result? = null

    /** Kept positive so the counter, and the logs that print it, stay readable for 2^31 probes. */
    private var dpdSequence: Int = randomNonZeroInt() and 0x7FFFFFFF

    /**
     * Answers we already sent to peer-initiated Quick Modes, keyed by message id. A lost message 2
     * makes the peer repeat message 1; replaying the same answer keeps both sides on one SA pair
     * instead of negotiating a second one.
     */
    private val answeredQuickModes = LinkedHashMap<Int, ByteArray>()

    // ---------------------------------------------------------------------------------------
    // Phase 1
    // ---------------------------------------------------------------------------------------

    fun establishPhase1(): Phase1Result {
        val result = when (config.exchangeMode) {
            IkeExchangeMode.MAIN -> mainMode()
            IkeExchangeMode.AGGRESSIVE -> aggressiveMode()
        }
        activePhase1 = result
        log.i(
            "phase 1 established: ${result.encryption}/${result.hash}/${result.dhGroup}, " +
                "NAT-T=${result.natTraversalFlavor}, localNat=${result.localBehindNat}, " +
                "remoteNat=${result.remoteBehindNat}",
        )
        return result
    }

    /**
     * RFC 2409 section 5.4:
     * ```
     * HDR, SA               -->   <-- HDR, SA
     * HDR, KE, Ni           -->   <-- HDR, KE, Nr
     * HDR*, IDii, HASH_I    -->   <-- HDR*, IDir, HASH_R
     * ```
     * with the NAT-D payloads of RFC 3947 riding along in the second pair.
     */
    private fun mainMode(): Phase1Result {
        val saPayload = buildPhase1Sa()
        val saBody = saPayload.encodeBody()

        val message1 = IsakmpCodec.buildMessage(
            initiatorCookie, responderCookie, ExchangeType.IDENTITY_PROTECTION, 0, 0,
            listOf(saPayload) + VendorIds.OFFERED.map { VendorIdPayload(it) },
        )
        val raw2 = request(message1, "main mode message 1") {
            it.exchangeType == ExchangeType.IDENTITY_PROTECTION && it.messageId == 0 &&
                !it.isEncrypted && it.nextPayload == PayloadType.SA
        }
        val header2 = IsakmpHeader.decode(raw2)
        responderCookie = header2.responderCookie
        val chain2 = IsakmpCodec.decodeMessage(raw2, header2)
        val lifetimeSeconds = checkResponderPhase1Sa(chain2)
        selectNatTraversalFlavor(chain2)

        val dh = DiffieHellman.generate(config.phase1.dhGroup)
        val ni = Bytes.random(NONCE_BYTES)
        val message3 = IsakmpCodec.buildMessage(
            initiatorCookie, responderCookie, ExchangeType.IDENTITY_PROTECTION, 0, 0,
            listOf(KeyExchangePayload(dh.publicValue), NoncePayload(ni)) + natDiscoveryPayloads(),
        )
        val raw4 = request(message3, "main mode message 3") {
            it.exchangeType == ExchangeType.IDENTITY_PROTECTION && it.messageId == 0 &&
                !it.isEncrypted && it.nextPayload == PayloadType.KE
        }
        val chain4 = IsakmpCodec.decodeMessage(raw4)
        val gxr = requirePayload(chain4.find<KeyExchangePayload>(), "responder key exchange").data
        val nr = requirePayload(chain4.find<NoncePayload>(), "responder nonce").data
        val keys = derivePhase1Keys(ni, nr, dh.computeSharedSecret(gxr))

        val nat = evaluateNatDiscovery(chain4)
        if (nat.local || nat.remote) floatToNatTraversalPort(nat)

        val crypto = SaCrypto(prf, cipher, keys.encryptionKey)
        // RFC 2409 appendix B: the phase-1 IV starts as hash(g^xi | g^xr).
        var iv = Bytes.truncate(prf.digest(dh.publicValue, gxr), cipher.blockBytes)

        val idPayload = localIdPayload()
        val idBody = idPayload.encodeBody()
        val hashI = IkeKeyDerivation.phase1AuthHash(
            prf, keys.skeyid, dh.publicValue, gxr, initiatorCookie, responderCookie, saBody, idBody,
        )
        val ciphertext5 = crypto.encrypt(
            IsakmpCodec.encodeChain(listOf(idPayload, HashPayload(hashI))), iv,
        )
        val message5 = IsakmpCodec.buildMessage(
            initiatorCookie, responderCookie, ExchangeType.IDENTITY_PROTECTION,
            IsakmpFlags.ENCRYPTION, 0, PayloadType.ID, ciphertext5,
        )
        iv = crypto.lastBlock(ciphertext5)

        val raw6 = request(message5, "main mode message 5") {
            it.exchangeType == ExchangeType.IDENTITY_PROTECTION && it.messageId == 0 && it.isEncrypted
        }
        val header6 = IsakmpHeader.decode(raw6)
        val ciphertext6 = payloadBlockOf(raw6)
        val chain6 = IsakmpCodec.decodeBlock(crypto.decrypt(ciphertext6, iv), header6.nextPayload)
        val finalIv = crypto.lastBlock(ciphertext6)

        val remoteId = remoteIdBody(chain6)
        val hashR = requirePayload(chain6.find<HashPayload>(), "HASH_R").data
        verifyHashR(keys.skeyid, gxr, dh.publicValue, saBody, remoteId, hashR)

        return buildPhase1Result(keys, finalIv, nat, idBody, remoteId, lifetimeSeconds)
    }

    /**
     * RFC 2409 section 5.4 aggressive variant:
     * ```
     * HDR, SA, KE, Ni, IDii  -->   <-- HDR, SA, KE, Nr, IDir, HASH_R
     * HDR*, HASH_I           -->
     * ```
     * RFC 3947 section 4 puts the NAT-D payloads in the last two messages here, so the port float
     * happens before message 3 rather than before message 5.
     */
    private fun aggressiveMode(): Phase1Result {
        val saPayload = buildPhase1Sa()
        val saBody = saPayload.encodeBody()
        val dh = DiffieHellman.generate(config.phase1.dhGroup)
        val ni = Bytes.random(NONCE_BYTES)
        val idPayload = localIdPayload()
        val idBody = idPayload.encodeBody()

        val message1 = IsakmpCodec.buildMessage(
            initiatorCookie, responderCookie, ExchangeType.AGGRESSIVE, 0, 0,
            listOf(saPayload, KeyExchangePayload(dh.publicValue), NoncePayload(ni), idPayload) +
                VendorIds.OFFERED.map { VendorIdPayload(it) },
        )
        val raw2 = request(message1, "aggressive mode message 1") {
            it.exchangeType == ExchangeType.AGGRESSIVE && it.messageId == 0 &&
                !it.isEncrypted && it.nextPayload == PayloadType.SA
        }
        val header2 = IsakmpHeader.decode(raw2)
        responderCookie = header2.responderCookie
        val chain2 = IsakmpCodec.decodeMessage(raw2, header2)
        val lifetimeSeconds = checkResponderPhase1Sa(chain2)
        selectNatTraversalFlavor(chain2)

        val gxr = requirePayload(chain2.find<KeyExchangePayload>(), "responder key exchange").data
        val nr = requirePayload(chain2.find<NoncePayload>(), "responder nonce").data
        val keys = derivePhase1Keys(ni, nr, dh.computeSharedSecret(gxr))

        val remoteId = remoteIdBody(chain2)
        val hashR = requirePayload(chain2.find<HashPayload>(), "HASH_R").data
        verifyHashR(keys.skeyid, gxr, dh.publicValue, saBody, remoteId, hashR)

        val nat = evaluateNatDiscovery(chain2)
        if (nat.local || nat.remote) floatToNatTraversalPort(nat)

        val crypto = SaCrypto(prf, cipher, keys.encryptionKey)
        val iv = Bytes.truncate(prf.digest(dh.publicValue, gxr), cipher.blockBytes)
        val hashI = IkeKeyDerivation.phase1AuthHash(
            prf, keys.skeyid, dh.publicValue, gxr, initiatorCookie, responderCookie, saBody, idBody,
        )
        val ciphertext3 = crypto.encrypt(
            IsakmpCodec.encodeChain(listOf(HashPayload(hashI)) + natDiscoveryPayloads()), iv,
        )
        transport.sendIsakmp(
            IsakmpCodec.buildMessage(
                initiatorCookie, responderCookie, ExchangeType.AGGRESSIVE,
                IsakmpFlags.ENCRYPTION, 0, PayloadType.HASH, ciphertext3,
            ),
        )
        return buildPhase1Result(
            keys, crypto.lastBlock(ciphertext3), nat, idBody, remoteId, lifetimeSeconds,
        )
    }

    private fun buildPhase1Result(
        keys: IkeKeyDerivation.Phase1Keys,
        finalIv: ByteArray,
        nat: NatStatus,
        localId: ByteArray,
        remoteId: ByteArray,
        lifetimeSeconds: Int,
    ) = Phase1Result(
        initiatorCookie = initiatorCookie,
        responderCookie = responderCookie,
        encryption = config.phase1.encryption,
        hash = config.phase1.hash,
        dhGroup = config.phase1.dhGroup,
        skeyid = keys.skeyid,
        skeyidD = keys.skeyidD,
        skeyidA = keys.skeyidA,
        skeyidE = keys.skeyidE,
        encryptionKey = keys.encryptionKey,
        phase1Iv = finalIv,
        localBehindNat = nat.local,
        remoteBehindNat = nat.remote,
        natTraversalFlavor = flavor,
        localIdentity = localId,
        remoteIdentity = remoteId,
        lifetimeSeconds = lifetimeSeconds,
    )

    // ---------------------------------------------------------------------------------------
    // Phase 2 — Quick Mode
    // ---------------------------------------------------------------------------------------

    /**
     * RFC 2409 section 5.5:
     * ```
     * HDR*, HASH(1), SA, Ni, [KE], IDci, IDcr  -->
     *                <-- HDR*, HASH(2), SA, Nr, [KE], IDci, IDcr
     * HDR*, HASH(3)                            -->
     * ```
     */
    fun establishPhase2(phase1: Phase1Result): Phase2Result {
        activePhase1 = phase1
        val crypto = cryptoFor(phase1)
        val messageId = randomMessageId()
        val messageIdBytes = int32(messageId)
        val inboundSpi = randomSpi()
        val ni = Bytes.random(NONCE_BYTES)
        val pfs = config.phase2.pfsGroup?.let { DiffieHellman.generate(it) }

        val udpEncapsulationRequired = transport.natTraversalActive
        val encapsulationMode =
            if (udpEncapsulationRequired) phase1.natTraversalFlavor.udpTransportMode
            else EncapsulationMode.TRANSPORT

        val payloads = buildList {
            add(buildPhase2Sa(inboundSpi, encapsulationMode))
            add(NoncePayload(ni))
            if (pfs != null) add(KeyExchangePayload(pfs.publicValue))
            add(trafficSelector(transport.localAddress))
            add(trafficSelector(transport.remoteAddress))
            addAll(natOriginalAddressPayloads(phase1))
        }

        // HASH(1) covers the message id and every byte that follows the HASH payload itself.
        val hash1 = crypto.prf.mac(phase1.skeyidA, messageIdBytes, IsakmpCodec.encodeChain(payloads))
        var iv = Bytes.truncate(
            crypto.prf.digest(phase1.phase1Iv, messageIdBytes), crypto.cipher.blockBytes,
        )
        val ciphertext1 = crypto.encrypt(chainAfterHash(hash1, payloads), iv)
        val message1 = IsakmpCodec.buildMessage(
            phase1.initiatorCookie, phase1.responderCookie, ExchangeType.QUICK_MODE,
            IsakmpFlags.ENCRYPTION, messageId, PayloadType.HASH, ciphertext1,
        )
        iv = crypto.lastBlock(ciphertext1)

        val raw2 = request(message1, "quick mode message 1") {
            it.exchangeType == ExchangeType.QUICK_MODE && it.messageId == messageId && it.isEncrypted
        }
        val header2 = IsakmpHeader.decode(raw2)
        val ciphertext2 = payloadBlockOf(raw2)
        val chain2 = IsakmpCodec.decodeBlock(crypto.decrypt(ciphertext2, iv), header2.nextPayload)
        iv = crypto.lastBlock(ciphertext2)

        if (chain2.indexOfType(PayloadType.HASH) != 0) {
            throw ProtocolException("quick mode message 2 does not start with HASH(2)")
        }
        val nr = requirePayload(chain2.find<NoncePayload>(), "responder nonce").data
        val expectedHash2 = crypto.prf.mac(phase1.skeyidA, messageIdBytes, ni, chain2.bytesAfter(0))
        if (!Bytes.constantTimeEquals(expectedHash2, chain2.bodyAt(0))) {
            throw TunnelException(
                TunnelErrorKind.IKE_AUTH_FAILED,
                "quick mode HASH(2) mismatch; the ISAKMP SA keys disagree",
            )
        }

        val choice = checkResponderPhase2Sa(chain2, udpEncapsulationRequired)
        val qmSecret = if (pfs != null) {
            pfs.computeSharedSecret(
                requirePayload(chain2.find<KeyExchangePayload>(), "PFS key exchange").data,
            )
        } else {
            // Ignoring a key exchange we never asked for would leave the responder seeding KEYMAT
            // with a secret we do not have, and every ESP packet would fail its integrity check.
            if (chain2.find<KeyExchangePayload>() != null) {
                throw TunnelException(
                    TunnelErrorKind.IPSEC_SA_FAILED,
                    "responder answered with a PFS key exchange we did not propose",
                )
            }
            ByteArray(0)
        }

        val encryptionKeyBytes = config.phase2.encryption.keyBytes
        val needed = encryptionKeyBytes + config.phase2.integrity.keyBytes
        val inbound = IkeKeyDerivation.keymat(
            crypto.prf, phase1.skeyidD, qmSecret, ProtocolId.ESP, inboundSpi, ni, nr, needed,
        )
        val outbound = IkeKeyDerivation.keymat(
            crypto.prf, phase1.skeyidD, qmSecret, ProtocolId.ESP, choice.spi, ni, nr, needed,
        )

        val hash3 = crypto.prf.mac(phase1.skeyidA, ByteArray(1), messageIdBytes, ni, nr)
        val ciphertext3 = crypto.encrypt(IsakmpCodec.encodeChain(listOf(HashPayload(hash3))), iv)
        transport.sendIsakmp(
            IsakmpCodec.buildMessage(
                phase1.initiatorCookie, phase1.responderCookie, ExchangeType.QUICK_MODE,
                IsakmpFlags.ENCRYPTION, messageId, PayloadType.HASH, ciphertext3,
            ),
        )

        val result = Phase2Result(
            inboundSpi = inboundSpi,
            outboundSpi = choice.spi,
            inboundEncryptionKey = inbound.copyOfRange(0, encryptionKeyBytes),
            inboundIntegrityKey = inbound.copyOfRange(encryptionKeyBytes, needed),
            outboundEncryptionKey = outbound.copyOfRange(0, encryptionKeyBytes),
            outboundIntegrityKey = outbound.copyOfRange(encryptionKeyBytes, needed),
            encryption = config.phase2.encryption,
            integrity = config.phase2.integrity,
            lifetimeSeconds = choice.lifetimeSeconds,
            udpEncapsulated = EncapsulationMode.isUdpEncapsulated(choice.encapsulationMode),
        )
        log.i(
            "phase 2 established: in=0x${Integer.toHexString(result.inboundSpi)} " +
                "out=0x${Integer.toHexString(result.outboundSpi)} ${result.encryption}/" +
                "${result.integrity} encap=${choice.encapsulationMode} lifetime=${result.lifetimeSeconds}s",
        )
        return result
    }

    // ---------------------------------------------------------------------------------------
    // Quick Mode, responder side
    // ---------------------------------------------------------------------------------------

    /**
     * Answers a Quick Mode the peer started, which is how a router that rekeys on its own schedule
     * replaces an expiring IPsec SA. Without this the peer's rekey would go unanswered and it would
     * eventually delete the SA under us.
     *
     * Returns the new SA pair, or `null` when the message was a retransmission we simply
     * re-acknowledged.
     */
    fun respondToQuickMode(phase1: Phase1Result, rawMessage: ByteArray): Phase2Result? {
        activePhase1 = phase1
        val crypto = cryptoFor(phase1)
        val header1 = IsakmpHeader.decode(rawMessage)
        if (!header1.isEncrypted) throw ProtocolException("quick mode message 1 is not encrypted")
        val messageId = header1.messageId
        val messageIdBytes = int32(messageId)

        answeredQuickModes[messageId]?.let { cached ->
            log.d { "re-sending our answer to a repeated quick mode message id $messageId" }
            transport.sendIsakmp(cached)
            return null
        }

        var iv = Bytes.truncate(
            crypto.prf.digest(phase1.phase1Iv, messageIdBytes), crypto.cipher.blockBytes,
        )
        val ciphertext1 = payloadBlockOf(rawMessage)
        val chain1 = IsakmpCodec.decodeBlock(crypto.decrypt(ciphertext1, iv), header1.nextPayload)
        iv = crypto.lastBlock(ciphertext1)

        if (chain1.indexOfType(PayloadType.HASH) != 0) {
            throw ProtocolException("quick mode message 1 does not start with HASH(1)")
        }
        val expectedHash1 = crypto.prf.mac(phase1.skeyidA, messageIdBytes, chain1.bytesAfter(0))
        if (!Bytes.constantTimeEquals(expectedHash1, chain1.bodyAt(0))) {
            throw TunnelException(
                TunnelErrorKind.IKE_AUTH_FAILED,
                "quick mode HASH(1) mismatch; the ISAKMP SA keys disagree",
            )
        }

        val ni = requirePayload(chain1.find<NoncePayload>(), "initiator nonce").data
        val offer = selectPeerPhase2Offer(chain1, transport.natTraversalActive)

        // Honour whatever PFS group the peer asked for rather than only our configured one: a
        // router with PFS enabled would otherwise get an answer it has to reject.
        val peerKe = chain1.find<KeyExchangePayload>()
        val pfs = offer.pfsGroup?.let { DiffieHellman.generate(it) }
        if (pfs != null && peerKe == null) {
            throw ProtocolException("peer asked for PFS group ${offer.pfsGroup} but sent no key exchange")
        }

        val inboundSpi = randomSpi()
        val nr = Bytes.random(NONCE_BYTES)
        val responsePayloads = buildList {
            add(SaPayload(listOf(ProposalPayload(1, ProtocolId.ESP, int32(inboundSpi), listOf(offer.transform)))))
            add(NoncePayload(nr))
            if (pfs != null) add(KeyExchangePayload(pfs.publicValue))
            // Echo the initiator's selectors verbatim: narrowing them is what makes a peer reject
            // the answer, and we accept whatever it proposed for the L2TP flow anyway.
            addAll(chain1.payloads.filterIsInstance<IdentificationPayload>())
        }
        val hash2 = crypto.prf.mac(
            phase1.skeyidA, messageIdBytes, ni, IsakmpCodec.encodeChain(responsePayloads),
        )
        val ciphertext2 = crypto.encrypt(chainAfterHash(hash2, responsePayloads), iv)
        val message2 = IsakmpCodec.buildMessage(
            phase1.initiatorCookie, phase1.responderCookie, ExchangeType.QUICK_MODE,
            IsakmpFlags.ENCRYPTION, messageId, PayloadType.HASH, ciphertext2,
        )
        transport.sendIsakmp(message2)
        rememberQuickModeAnswer(messageId, message2)
        iv = crypto.lastBlock(ciphertext2)

        val qmSecret = if (pfs == null) ByteArray(0) else pfs.computeSharedSecret(peerKe!!.data)
        val encryptionKeyBytes = offer.encryption.keyBytes
        val needed = encryptionKeyBytes + offer.integrity.keyBytes
        val inbound = IkeKeyDerivation.keymat(
            crypto.prf, phase1.skeyidD, qmSecret, ProtocolId.ESP, inboundSpi, ni, nr, needed,
        )
        val outbound = IkeKeyDerivation.keymat(
            crypto.prf, phase1.skeyidD, qmSecret, ProtocolId.ESP, offer.spi, ni, nr, needed,
        )

        awaitQuickModeConfirmation(crypto, phase1, messageId, messageIdBytes, ni, nr, iv)

        val result = Phase2Result(
            inboundSpi = inboundSpi,
            outboundSpi = offer.spi,
            inboundEncryptionKey = inbound.copyOfRange(0, encryptionKeyBytes),
            inboundIntegrityKey = inbound.copyOfRange(encryptionKeyBytes, needed),
            outboundEncryptionKey = outbound.copyOfRange(0, encryptionKeyBytes),
            outboundIntegrityKey = outbound.copyOfRange(encryptionKeyBytes, needed),
            encryption = offer.encryption,
            integrity = offer.integrity,
            lifetimeSeconds = offer.lifetimeSeconds,
            udpEncapsulated = EncapsulationMode.isUdpEncapsulated(offer.encapsulationMode),
        )
        log.i(
            "answered a peer-initiated quick mode: in=0x${Integer.toHexString(result.inboundSpi)} " +
                "out=0x${Integer.toHexString(result.outboundSpi)} lifetime=${result.lifetimeSeconds}s",
        )
        return result
    }

    /**
     * Waits for HASH(3). The SA is usable as soon as message 2 is on the wire, so a missing
     * confirmation is logged rather than fatal — the peer may simply have lost it, and refusing
     * the SA at that point would drop traffic the peer is already sending on it.
     */
    private fun awaitQuickModeConfirmation(
        crypto: SaCrypto,
        phase1: Phase1Result,
        messageId: Int,
        messageIdBytes: ByteArray,
        ni: ByteArray,
        nr: ByteArray,
        iv: ByteArray,
    ) {
        val expected = crypto.prf.mac(phase1.skeyidA, ByteArray(1), messageIdBytes, ni, nr)
        val deadline = clock.nowMs() + config.ikeRetransmitTimeoutMs * 2
        while (true) {
            val left = deadline - clock.nowMs()
            if (left <= 0) break
            val raw = transport.receiveIsakmp(left.toInt()) ?: break
            val header = try {
                IsakmpHeader.decode(raw)
            } catch (e: ProtocolException) {
                log.w("dropping a malformed datagram while awaiting HASH(3): ${e.message}")
                continue
            }
            // The same overlap as during a rekey, the other way round: a peer-initiated Quick Mode
            // on the SA a rekey has just superseded is answered by *its* negotiator, so anything
            // arriving here for the SA that replaced it would be measured against the wrong keys.
            if (!header.initiatorCookie.contentEquals(initiatorCookie)) {
                log.d { "handing back an ISAKMP message for another SA while awaiting HASH(3)" }
                transport.deferForeignMessage(raw)
                continue
            }
            if (header.exchangeType == ExchangeType.INFORMATIONAL) {
                processInformational(raw)
                continue
            }
            if (header.exchangeType != ExchangeType.QUICK_MODE || header.messageId != messageId) {
                log.w("ignoring $header while awaiting HASH(3)")
                continue
            }
            val chain = try {
                IsakmpCodec.decodeBlock(crypto.decrypt(payloadBlockOf(raw), iv), header.nextPayload)
            } catch (e: ProtocolException) {
                log.w("could not decode quick mode message 3: ${e.message}")
                continue
            }
            if (chain.indexOfType(PayloadType.HASH) == 0 &&
                Bytes.constantTimeEquals(expected, chain.bodyAt(0))
            ) {
                log.d { "quick mode message 3 verified for message id $messageId" }
                return
            }
            log.w("quick mode message 3 did not carry a valid HASH(3)")
        }
        log.w("no quick mode HASH(3) arrived; keeping the SA anyway")
    }

    private fun rememberQuickModeAnswer(messageId: Int, message: ByteArray) {
        answeredQuickModes[messageId] = message
        while (answeredQuickModes.size > REMEMBERED_QUICK_MODES) {
            answeredQuickModes.remove(answeredQuickModes.keys.first())
        }
    }

    private class Phase2Offer(
        val spi: Int,
        val transform: TransformPayload,
        val encryption: EspEncryption,
        val integrity: EspIntegrity,
        val encapsulationMode: Int,
        val lifetimeSeconds: Int,
        val pfsGroup: DhGroup?,
    )

    /** Picks the first transform in the peer's offer that we can actually run. */
    private fun selectPeerPhase2Offer(chain: PayloadChain, requireUdpEncapsulation: Boolean): Phase2Offer {
        val sa = requirePayload(chain.find<SaPayload>(), "quick mode SA")
        val proposal = sa.proposals.firstOrNull { it.protocolId == ProtocolId.ESP }
            ?: throw TunnelException(
                TunnelErrorKind.IPSEC_SA_FAILED,
                "peer's quick mode carries no ESP proposal",
            )
        if (proposal.spi.size != ESP_SPI_BYTES) {
            throw ProtocolException("peer ESP SPI is ${proposal.spi.size} bytes, expected $ESP_SPI_BYTES")
        }
        for (transform in proposal.transforms) {
            val keyBits = transform.intAttribute(Phase2Attribute.KEY_LENGTH)
            val encryption = EspEncryption.find(transform.transformId, keyBits) ?: continue
            val integrity = transform.intAttribute(Phase2Attribute.AUTHENTICATION_ALGORITHM)
                ?.let { EspIntegrity.find(it) } ?: continue
            val encapsulationMode =
                transform.intAttribute(Phase2Attribute.ENCAPSULATION_MODE) ?: EncapsulationMode.TUNNEL
            if (requireUdpEncapsulation && !EncapsulationMode.isUdpEncapsulated(encapsulationMode)) continue
            val group = transform.intAttribute(Phase2Attribute.GROUP_DESCRIPTION)
            val pfsGroup = if (group == null) null else DhGroup.find(group) ?: continue
            val lifetime = negotiatedLifetimeSeconds(
                transform,
                Phase2Attribute.SA_LIFE_TYPE,
                Phase2Attribute.LIFE_TYPE_SECONDS,
                Phase2Attribute.SA_LIFE_DURATION,
                config.phase2.lifetimeSeconds,
            )
            return Phase2Offer(
                spi = ByteReader(proposal.spi).i32(),
                transform = transform,
                encryption = encryption,
                integrity = integrity,
                encapsulationMode = encapsulationMode,
                lifetimeSeconds = lifetime,
                pfsGroup = pfsGroup,
            )
        }
        bestEffort("NO_PROPOSAL_CHOSEN") {
            sendInformational(
                requireNotNull(activePhase1),
                listOf(NotifyPayload(NotifyType.NO_PROPOSAL_CHOSEN, ProtocolId.ESP, proposal.spi)),
            )
        }
        throw TunnelException(
            TunnelErrorKind.IKE_PROPOSAL_REJECTED,
            "peer's quick mode offered no transform this client supports",
        )
    }

    // ---------------------------------------------------------------------------------------
    // Informational exchanges
    // ---------------------------------------------------------------------------------------

    /** ISAKMP Informational carrying Delete for the IPsec SA then the ISAKMP SA. Best effort. */
    fun sendDeleteNotifications(phase1: Phase1Result, phase2: Phase2Result?) {
        if (phase2 != null) sendEspDelete(phase1, phase2.inboundSpi)
        sendIsakmpDelete(phase1)
    }

    /**
     * Tells the peer to stop sending on one IPsec SA. The SPI is ours because a Delete names the
     * sender's inbound SAs; this is what retires a superseded SA after a rekey.
     */
    fun sendEspDelete(phase1: Phase1Result, inboundSpi: Int) {
        bestEffort("IPsec delete") {
            sendInformational(phase1, listOf(DeletePayload(ProtocolId.ESP, listOf(int32(inboundSpi)))))
        }
    }

    fun sendIsakmpDelete(phase1: Phase1Result) {
        bestEffort("ISAKMP delete") {
            val spi = Bytes.concat(phase1.initiatorCookie, phase1.responderCookie)
            sendInformational(phase1, listOf(DeletePayload(ProtocolId.ISAKMP, listOf(spi))))
        }
    }

    /**
     * Handles a received Informational exchange (DPD R-U-THERE, Delete, Notify) and reports what
     * the peer asked to tear down. Deciding what a delete *means* is the tunnel's job: after a
     * rekey the peer deletes the superseded IPsec SA, which must not bring the connection down.
     */
    fun handleInformational(phase1: Phase1Result, rawMessage: ByteArray): InformationalResult {
        val chain = decodeInformational(phase1, rawMessage) ?: return InformationalResult()
        val deletedEsp = mutableListOf<Int>()
        var isakmpDeleted = false
        for (payload in chain.payloads) {
            when (payload) {
                is NotifyPayload -> when (payload.notifyType) {
                    NotifyType.DPD_R_U_THERE -> replyToDpd(phase1, payload)
                    NotifyType.DPD_R_U_THERE_ACK ->
                        log.d { "DPD ack, sequence ${sequenceOf(payload.data)}" }
                    else -> log.i("peer sent notify ${payload.notifyType}")
                }

                is DeletePayload -> when (payload.protocolId) {
                    ProtocolId.ESP -> payload.spis.forEach { spi ->
                        if (spi.size == ESP_SPI_BYTES) {
                            val value = ByteReader(spi).i32()
                            log.i("peer deleted IPsec SA 0x${Integer.toHexString(value)}")
                            deletedEsp += value
                        } else {
                            log.w("peer deleted an IPsec SA with a ${spi.size}-byte SPI; ignoring")
                        }
                    }

                    ProtocolId.ISAKMP -> {
                        log.i("peer deleted the ISAKMP SA")
                        isakmpDeleted = true
                    }

                    else -> log.i("peer deleted an SA for protocol ${payload.protocolId}")
                }

                else -> log.d { "ignoring payload ${payload.type} in an informational exchange" }
            }
        }
        return InformationalResult(deletedEsp, isakmpDeleted)
    }

    /**
     * Sends a DPD R-U-THERE (RFC 3706) and returns the sequence number used.
     *
     * Nothing in the client calls this today: the tunnel layer decides when to probe, and it infers
     * liveness from the L2TP HELLO keepalive instead, which covers the whole stack rather than just
     * the ISAKMP SA. Probing is kept available here because the two answer different questions — a
     * peer can keep the ISAKMP SA alive while the IPsec SA underneath it has stopped carrying
     * traffic. Probes the *peer* sends are answered either way, by [handleInformational] and, while
     * an exchange is in flight, by [processInformational].
     */
    fun sendDpdRequest(phase1: Phase1Result): Long {
        val sequence = dpdSequence++
        sendInformational(
            phase1,
            listOf(
                NotifyPayload(
                    notifyType = NotifyType.DPD_R_U_THERE,
                    protocolId = ProtocolId.ISAKMP,
                    spi = Bytes.concat(phase1.initiatorCookie, phase1.responderCookie),
                    data = int32(sequence),
                ),
            ),
        )
        return sequence.toLong() and 0xFFFFFFFFL
    }

    private fun replyToDpd(phase1: Phase1Result, request: NotifyPayload) {
        log.d { "DPD probe, sequence ${sequenceOf(request.data)}" }
        bestEffort("DPD ack") {
            sendInformational(
                phase1,
                listOf(
                    NotifyPayload(
                        notifyType = NotifyType.DPD_R_U_THERE_ACK,
                        protocolId = ProtocolId.ISAKMP,
                        spi = Bytes.concat(phase1.initiatorCookie, phase1.responderCookie),
                        data = request.data,
                    ),
                ),
            )
        }
    }

    private fun sendInformational(phase1: Phase1Result, payloads: List<IkePayload>) {
        val crypto = cryptoFor(phase1)
        val messageId = randomMessageId()
        val messageIdBytes = int32(messageId)
        val hash = crypto.prf.mac(
            phase1.skeyidA, messageIdBytes, IsakmpCodec.encodeChain(payloads),
        )
        val iv = Bytes.truncate(
            crypto.prf.digest(phase1.phase1Iv, messageIdBytes), crypto.cipher.blockBytes,
        )
        val ciphertext = crypto.encrypt(chainAfterHash(hash, payloads), iv)
        transport.sendIsakmp(
            IsakmpCodec.buildMessage(
                phase1.initiatorCookie, phase1.responderCookie, ExchangeType.INFORMATIONAL,
                IsakmpFlags.ENCRYPTION, messageId, PayloadType.HASH, ciphertext,
            ),
        )
    }

    /** Decrypts and authenticates an informational exchange; null if it cannot be trusted. */
    private fun decodeInformational(phase1: Phase1Result?, raw: ByteArray): PayloadChain? = try {
        val header = IsakmpHeader.decode(raw)
        when {
            // RFC 2408 section 4.8: only an exchange sent before the ISAKMP SA exists may travel in
            // the clear. Afterwards an unprotected Delete or error notify is unauthenticated, and
            // acting on one would let anyone who has seen our cookies tear the tunnel down.
            !header.isEncrypted && phase1 == null -> IsakmpCodec.decodeMessage(raw, header)
            !header.isEncrypted -> {
                log.w("dropping an unprotected informational received after phase 1 completed")
                null
            }

            phase1 == null -> {
                log.w("dropping an encrypted informational received before phase 1 completed")
                null
            }

            else -> {
                val crypto = cryptoFor(phase1)
                val messageIdBytes = int32(header.messageId)
                val iv = Bytes.truncate(
                    crypto.prf.digest(phase1.phase1Iv, messageIdBytes), crypto.cipher.blockBytes,
                )
                val chain = IsakmpCodec.decodeBlock(
                    crypto.decrypt(payloadBlockOf(raw), iv), header.nextPayload,
                )
                // The HASH must be located before anything is hashed: an empty chain, or one that
                // starts with another payload, has no "bytes after the HASH" to authenticate.
                if (chain.indexOfType(PayloadType.HASH) != 0) {
                    log.w("dropping an informational exchange that does not start with a HASH")
                    null
                } else {
                    val expected = crypto.prf.mac(phase1.skeyidA, messageIdBytes, chain.bytesAfter(0))
                    if (!Bytes.constantTimeEquals(expected, chain.bodyAt(0))) {
                        log.w("dropping an informational exchange with a bad HASH")
                        null
                    } else {
                        chain
                    }
                }
            }
        }
    } catch (e: ProtocolException) {
        log.w("could not decode an informational exchange: ${e.message}")
        null
    }

    /**
     * Inspects an informational received while waiting for an exchange to complete: error notifies
     * abort the negotiation, everything else is answered or logged.
     */
    private fun processInformational(raw: ByteArray) {
        val phase1 = activePhase1
        val chain = decodeInformational(phase1, raw) ?: return
        for (notify in chain.all<NotifyPayload>()) {
            mapNotifyError(notify.notifyType)?.let { throw it }
            if (notify.notifyType == NotifyType.DPD_R_U_THERE && phase1 != null) {
                replyToDpd(phase1, notify)
            } else {
                log.i("peer sent notify ${notify.notifyType} during negotiation")
            }
        }
        for (delete in chain.all<DeletePayload>()) {
            if (delete.protocolId == ProtocolId.ISAKMP) {
                throw TunnelException(
                    TunnelErrorKind.PEER_DISCONNECTED,
                    "peer deleted the ISAKMP SA while we were negotiating",
                )
            }
            // An IPsec delete is routine here: a peer that rekeys retires the superseded SA as soon
            // as the new one is up, so it regularly overtakes the HASH(3) we are still waiting for.
            // Aborting on it would kill a healthy tunnel; the SA overlap window retires it instead.
            log.i("peer deleted an SA for protocol ${delete.protocolId} while we were negotiating")
        }
    }

    private fun mapNotifyError(notifyType: Int): TunnelException? = when {
        notifyType == NotifyType.NO_PROPOSAL_CHOSEN -> TunnelException(
            TunnelErrorKind.IKE_PROPOSAL_REJECTED,
            "peer rejected our proposal (NO_PROPOSAL_CHOSEN)",
        )

        notifyType == NotifyType.AUTHENTICATION_FAILED ||
            notifyType == NotifyType.INVALID_ID_INFORMATION -> TunnelException(
            TunnelErrorKind.IKE_AUTH_FAILED,
            "peer refused our identity or pre-shared key (notify $notifyType)",
        )

        NotifyType.isError(notifyType) -> TunnelException(
            TunnelErrorKind.IPSEC_SA_FAILED,
            "peer reported ISAKMP error $notifyType",
        )

        else -> null
    }

    // ---------------------------------------------------------------------------------------
    // Request / response with retransmission
    // ---------------------------------------------------------------------------------------

    /**
     * Sends [message] and waits for the first reply [accept] recognises, retransmitting up to
     * `config.ikeMaxRetransmits` times with an exponential back-off capped at eight times the
     * configured timeout. Anything unexpected is logged and dropped: a duplicate of an earlier
     * response or a stray datagram must not abort a negotiation that is still making progress.
     */
    private fun request(message: ByteArray, what: String, accept: (IsakmpHeader) -> Boolean): ByteArray {
        var timeout = config.ikeRetransmitTimeoutMs
        val maxTimeout = config.ikeRetransmitTimeoutMs * MAX_BACKOFF_FACTOR
        var attempt = 0
        while (true) {
            transport.sendIsakmp(message)
            val deadline = clock.nowMs() + timeout
            while (true) {
                val left = deadline - clock.nowMs()
                if (left <= 0) break
                val raw = transport.receiveIsakmp(left.coerceAtMost(timeout.toLong()).toInt()) ?: break
                val header = try {
                    IsakmpHeader.decode(raw)
                } catch (e: ProtocolException) {
                    log.w("dropping a malformed ISAKMP datagram: ${e.message}")
                    continue
                }
                if (!header.initiatorCookie.contentEquals(initiatorCookie)) {
                    // Routine during a phase-1 rekey: this negotiator shares its inbound stream
                    // with the SA it is replacing, which is still live and still being talked to.
                    log.d { "handing back an ISAKMP message addressed to another initiator cookie" }
                    transport.deferForeignMessage(raw)
                    continue
                }
                if (header.exchangeType == ExchangeType.INFORMATIONAL) {
                    processInformational(raw)
                    continue
                }
                if (accept(header)) return raw
                log.w("ignoring an unexpected message while waiting on $what: $header")
            }
            attempt++
            if (attempt > config.ikeMaxRetransmits) {
                throw TunnelException(
                    TunnelErrorKind.IKE_NO_RESPONSE,
                    "no answer to $what after $attempt attempts",
                )
            }
            timeout = (timeout * 2).coerceAtMost(maxTimeout)
            log.w("retransmitting $what (attempt ${attempt + 1})")
        }
    }

    // ---------------------------------------------------------------------------------------
    // Proposal building and validation
    // ---------------------------------------------------------------------------------------

    private fun buildPhase1Sa(): SaPayload {
        val p = config.phase1
        val attributes = buildList {
            add(SaAttribute.tv(Phase1Attribute.ENCRYPTION, p.encryption.transformId))
            // 3DES has one legal key size and must not carry a Key Length attribute; AES must.
            if (p.encryption.needsKeyLengthAttribute) {
                add(SaAttribute.tv(Phase1Attribute.KEY_LENGTH, p.encryption.keyBits))
            }
            add(SaAttribute.tv(Phase1Attribute.HASH, p.hash.transformId))
            add(SaAttribute.tv(Phase1Attribute.AUTH_METHOD, IkeAuthMethod.PRE_SHARED_KEY))
            add(SaAttribute.tv(Phase1Attribute.GROUP_DESCRIPTION, p.dhGroup.groupId))
            add(SaAttribute.tv(Phase1Attribute.LIFE_TYPE, Phase1Attribute.LIFE_TYPE_SECONDS))
            add(SaAttribute.tlv32(Phase1Attribute.LIFE_DURATION, p.lifetimeSeconds))
        }
        val transform = TransformPayload(1, TransformId.KEY_IKE, attributes)
        return SaPayload(listOf(ProposalPayload(1, ProtocolId.ISAKMP, ByteArray(0), listOf(transform))))
    }

    /**
     * The responder must echo the single transform we offered; anything else is unusable.
     *
     * Returns the ISAKMP SA lifetime the responder settled on, which may be shorter than ours.
     */
    private fun checkResponderPhase1Sa(chain: PayloadChain): Int {
        val sa = requirePayload(chain.find<SaPayload>(), "responder SA")
        val transform = sa.proposals.firstOrNull()?.transforms?.firstOrNull()
            ?: throw ProtocolException("responder SA payload carries no transform")
        val p = config.phase1
        val keyLengthOk = !p.encryption.needsKeyLengthAttribute ||
            transform.intAttribute(Phase1Attribute.KEY_LENGTH) == p.encryption.keyBits
        val matches = transform.transformId == TransformId.KEY_IKE &&
            transform.intAttribute(Phase1Attribute.ENCRYPTION) == p.encryption.transformId &&
            transform.intAttribute(Phase1Attribute.HASH) == p.hash.transformId &&
            transform.intAttribute(Phase1Attribute.GROUP_DESCRIPTION) == p.dhGroup.groupId &&
            transform.intAttribute(Phase1Attribute.AUTH_METHOD) == IkeAuthMethod.PRE_SHARED_KEY &&
            keyLengthOk
        if (!matches) {
            throw TunnelException(
                TunnelErrorKind.IKE_PROPOSAL_REJECTED,
                "responder chose an ISAKMP transform we did not propose: $transform",
            )
        }
        // Schedule the rekey off the peer's number: proposing three hours and being granted ten
        // minutes would otherwise leave us renegotiating long after the SA had been torn down.
        return negotiatedLifetimeSeconds(
            transform,
            Phase1Attribute.LIFE_TYPE,
            Phase1Attribute.LIFE_TYPE_SECONDS,
            Phase1Attribute.LIFE_DURATION,
            p.lifetimeSeconds,
        )
    }

    /**
     * The SA lifetime the peer settled on, in seconds, or [fallback] when it did not name one we
     * can schedule against.
     *
     * A life duration is only usable when it is expressed in seconds and decodes strictly positive.
     * The attribute is a raw 32-bit field, so a four-byte value with its top bit set — 0xFFFFFFFF,
     * which several stacks send to mean "no limit" — reads back negative through
     * [SaAttribute.intValue], and a zero or negative lifetime would leave the tunnel either
     * rekeying in a tight loop or never at all.
     */
    private fun negotiatedLifetimeSeconds(
        transform: TransformPayload,
        lifeTypeAttribute: Int,
        secondsLifeType: Int,
        lifeDurationAttribute: Int,
        fallback: Int,
    ): Int {
        if (transform.intAttribute(lifeTypeAttribute) != secondsLifeType) return fallback
        val duration = transform.intAttribute(lifeDurationAttribute) ?: return fallback
        if (duration > 0) return duration
        log.w("peer named an unusable SA lifetime of $duration seconds; keeping $fallback")
        return fallback
    }

    private fun buildPhase2Sa(spi: Int, encapsulationMode: Int): SaPayload {
        val p = config.phase2
        val attributes = buildList {
            add(SaAttribute.tv(Phase2Attribute.SA_LIFE_TYPE, Phase2Attribute.LIFE_TYPE_SECONDS))
            add(SaAttribute.tlv32(Phase2Attribute.SA_LIFE_DURATION, p.lifetimeSeconds))
            add(SaAttribute.tv(Phase2Attribute.ENCAPSULATION_MODE, encapsulationMode))
            add(SaAttribute.tv(Phase2Attribute.AUTHENTICATION_ALGORITHM, p.integrity.attributeValue))
            if (p.encryption.needsKeyLengthAttribute) {
                add(SaAttribute.tv(Phase2Attribute.KEY_LENGTH, p.encryption.keyBits))
            }
            p.pfsGroup?.let { add(SaAttribute.tv(Phase2Attribute.GROUP_DESCRIPTION, it.groupId)) }
        }
        val transform = TransformPayload(1, p.encryption.transformId, attributes)
        return SaPayload(listOf(ProposalPayload(1, ProtocolId.ESP, int32(spi), listOf(transform))))
    }

    private class Phase2Choice(val spi: Int, val encapsulationMode: Int, val lifetimeSeconds: Int)

    private fun checkResponderPhase2Sa(chain: PayloadChain, requireUdpEncapsulation: Boolean): Phase2Choice {
        val sa = requirePayload(chain.find<SaPayload>(), "quick mode SA")
        val proposal = sa.proposals.firstOrNull()
            ?: throw ProtocolException("quick mode SA payload carries no proposal")
        if (proposal.protocolId != ProtocolId.ESP) {
            throw TunnelException(
                TunnelErrorKind.IPSEC_SA_FAILED,
                "responder selected protocol ${proposal.protocolId}; only ESP is supported",
            )
        }
        if (proposal.spi.size != ESP_SPI_BYTES) {
            throw ProtocolException("responder ESP SPI is ${proposal.spi.size} bytes, expected $ESP_SPI_BYTES")
        }
        val transform = proposal.transforms.firstOrNull()
            ?: throw ProtocolException("quick mode proposal carries no transform")
        val p = config.phase2
        val keyLengthOk = !p.encryption.needsKeyLengthAttribute ||
            transform.intAttribute(Phase2Attribute.KEY_LENGTH) == p.encryption.keyBits
        // A responder that names a PFS group we did not propose expects KEYMAT seeded with a second
        // Diffie-Hellman secret. Accepting it would key the two directions differently and drop
        // every ESP packet in silence, so the group has to match whatever we asked for.
        val responderGroup = transform.intAttribute(Phase2Attribute.GROUP_DESCRIPTION)
        val pfsGroupOk = responderGroup == null || responderGroup == p.pfsGroup?.groupId
        val matches = transform.transformId == p.encryption.transformId && keyLengthOk && pfsGroupOk &&
            transform.intAttribute(Phase2Attribute.AUTHENTICATION_ALGORITHM) == p.integrity.attributeValue
        if (!matches) {
            throw TunnelException(
                TunnelErrorKind.IKE_PROPOSAL_REJECTED,
                "responder chose an IPsec transform we did not propose: $transform",
            )
        }
        val encapsulationMode =
            transform.intAttribute(Phase2Attribute.ENCAPSULATION_MODE) ?: EncapsulationMode.TUNNEL
        if (requireUdpEncapsulation && !EncapsulationMode.isUdpEncapsulated(encapsulationMode)) {
            throw TunnelException(
                TunnelErrorKind.IPSEC_SA_FAILED,
                "responder chose encapsulation mode $encapsulationMode, but this client can only " +
                    "carry ESP inside UDP",
            )
        }
        val lifetime = negotiatedLifetimeSeconds(
            transform,
            Phase2Attribute.SA_LIFE_TYPE,
            Phase2Attribute.LIFE_TYPE_SECONDS,
            Phase2Attribute.SA_LIFE_DURATION,
            p.lifetimeSeconds,
        )
        return Phase2Choice(ByteReader(proposal.spi).i32(), encapsulationMode, lifetime)
    }

    // ---------------------------------------------------------------------------------------
    // Identities and traffic selectors
    // ---------------------------------------------------------------------------------------

    private fun localIdPayload(): IdentificationPayload {
        val identity = config.localIdentity
        // Road-warrior clients send their own address with protocol and port zeroed.
        //
        // AUTO_IPV4 and IPV4_ADDR deliberately share wire type 1: they differ only in where the
        // address comes from, not in what the peer sees. Dispatching on the enum entry rather than
        // on IkeIdentityType.value is what keeps them apart — a reverse lookup by wire value could
        // not tell them apart, and this is the only place in the package that maps the two.
        return when (identity.type) {
            IkeIdentityType.AUTO_IPV4 ->
                IdentificationPayload(IdType.IPV4_ADDR, 0, 0, ipv4(transport.localAddress))

            IkeIdentityType.IPV4_ADDR -> IdentificationPayload(
                IdType.IPV4_ADDR, 0, 0,
                if (identity.value.isBlank()) ipv4(transport.localAddress)
                else Bytes.ipv4ToBytes(identity.value),
            )

            IkeIdentityType.FQDN ->
                IdentificationPayload(IdType.FQDN, 0, 0, identity.value.toByteArray(Charsets.UTF_8))

            IkeIdentityType.USER_FQDN ->
                IdentificationPayload(IdType.USER_FQDN, 0, 0, identity.value.toByteArray(Charsets.UTF_8))

            IkeIdentityType.KEY_ID ->
                IdentificationPayload(IdType.KEY_ID, 0, 0, identity.value.toByteArray(Charsets.UTF_8))
        }
    }

    /** L2TP runs over UDP/1701 in transport mode, so the selectors are single host/port pairs. */
    private fun trafficSelector(address: InetAddress) =
        IdentificationPayload(IdType.IPV4_ADDR, IpProtocol.UDP, config.l2tpPort, ipv4(address))

    private fun remoteIdBody(chain: PayloadChain): ByteArray {
        val index = chain.indexOfType(PayloadType.ID)
        if (index < 0) throw ProtocolException("responder identification payload missing")
        return chain.bodyAt(index)
    }

    // ---------------------------------------------------------------------------------------
    // Key derivation
    // ---------------------------------------------------------------------------------------

    /** RFC 2409 section 5, pre-shared key variant. */
    private fun derivePhase1Keys(ni: ByteArray, nr: ByteArray, gxy: ByteArray) = IkeKeyDerivation.phase1(
        prf, psk, ni, nr, gxy, initiatorCookie, responderCookie, config.phase1.encryption.keyBytes,
    )

    private fun verifyHashR(
        skeyid: ByteArray,
        gxr: ByteArray,
        gxi: ByteArray,
        saBody: ByteArray,
        remoteIdBody: ByteArray,
        received: ByteArray,
    ) {
        val expected = IkeKeyDerivation.phase1AuthHash(
            prf, skeyid, gxr, gxi, responderCookie, initiatorCookie, saBody, remoteIdBody,
        )
        if (!Bytes.constantTimeEquals(expected, received)) {
            throw TunnelException(
                TunnelErrorKind.IKE_AUTH_FAILED,
                "responder HASH_R does not verify; the pre-shared key is wrong",
            )
        }
    }

    // ---------------------------------------------------------------------------------------
    // NAT traversal
    // ---------------------------------------------------------------------------------------

    private fun selectNatTraversalFlavor(chain: PayloadChain) {
        val vendorIds = chain.all<VendorIdPayload>().map { it.data }
        flavor = VendorIds.selectNatTraversalFlavor(vendorIds)
        if (flavor == NatTraversalFlavor.NONE) {
            throw TunnelException(
                TunnelErrorKind.IPSEC_SA_FAILED,
                "peer does not support NAT-T; an unrooted Android client cannot send raw " +
                    "IP-protocol-50 ESP, so the IPsec SA cannot be carried",
            )
        }
        log.d {
            "NAT-T dialect $flavor" + if (VendorIds.supportsDpd(vendorIds)) ", peer supports DPD" else ""
        }
    }

    /**
     * The port the peer is actually listening on right now. It is 500 for the initial exchange and
     * 4500 once we have floated, which matters when phase 1 is renegotiated over an established
     * NAT-T session: hashing the wrong port would make both ends read the NAT state backwards.
     */
    private fun peerIkePort(): Int =
        if (transport.natTraversalActive) config.natTraversalPort else config.ikePort

    private fun natdHash(address: InetAddress, port: Int): ByteArray =
        IkeKeyDerivation.natDiscoveryHash(prf, initiatorCookie, responderCookie, ipv4(address), port)

    private fun natDiscoveryPayloads(): List<IkePayload> {
        // strongSwan's forceencaps=yes: hashing the source with port 0 guarantees the responder
        // cannot reproduce it, so it concludes we are behind a NAT and encapsulates ESP in UDP —
        // the only shape an unrooted Android application is able to send or receive at all.
        val sourcePort = if (config.forceUdpEncapsulation) 0 else transport.localPort
        val payloadType = flavor.natdPayloadType
        return listOf(
            NatDiscoveryPayload(payloadType, natdHash(transport.remoteAddress, peerIkePort())),
            NatDiscoveryPayload(payloadType, natdHash(transport.localAddress, sourcePort)),
        )
    }

    private class NatStatus(val local: Boolean, val remote: Boolean)

    /**
     * RFC 3947 section 3.2: the first NAT-D the peer sends hashes the destination — us, as the peer
     * sees us — and the rest hash the peer itself. A hash we cannot reproduce means an address or
     * port was rewritten in flight.
     */
    private fun evaluateNatDiscovery(chain: PayloadChain): NatStatus {
        val received = chain.all<NatDiscoveryPayload>()
        if (received.isEmpty()) {
            log.w("peer sent no NAT-D payloads")
            return NatStatus(config.forceUdpEncapsulation, false)
        }
        val ourHash = natdHash(transport.localAddress, transport.localPort)
        val peerHash = natdHash(transport.remoteAddress, peerIkePort())
        val localMismatch = !Bytes.constantTimeEquals(received[0].hash, ourHash)
        val remoteMismatch = received.size >= 2 &&
            received.drop(1).none { Bytes.constantTimeEquals(it.hash, peerHash) }
        // When we forced encapsulation the peer has already concluded that we are natted; we must
        // reach the same conclusion or we would keep talking on port 500 after it floated to 4500.
        return NatStatus(localMismatch || config.forceUdpEncapsulation, remoteMismatch)
    }

    private fun floatToNatTraversalPort(nat: NatStatus) {
        log.i(
            "NAT detected (local=${nat.local}, remote=${nat.remote}); " +
                "moving IKE to UDP/${config.natTraversalPort}",
        )
        transport.enableNatTraversal()
    }

    private fun natOriginalAddressPayloads(phase1: Phase1Result): List<IkePayload> {
        if (!phase1.localBehindNat && !phase1.remoteBehindNat) return emptyList()
        val payloadType = phase1.natTraversalFlavor.natOaPayloadType
        val initiator =
            NatOriginalAddressPayload(payloadType, IdType.IPV4_ADDR, ipv4(transport.localAddress))
        return if (phase1.natTraversalFlavor.sendsResponderNatOa) {
            listOf(
                initiator,
                NatOriginalAddressPayload(payloadType, IdType.IPV4_ADDR, ipv4(transport.remoteAddress)),
            )
        } else {
            listOf(initiator)
        }
    }

    // ---------------------------------------------------------------------------------------
    // Message protection helpers
    // ---------------------------------------------------------------------------------------

    /** Protection of one ISAKMP message once phase 1 has produced SKEYID_e. */
    private class SaCrypto(val prf: Prf, val cipher: CbcCipher, private val key: ByteArray) {

        fun encrypt(block: ByteArray, iv: ByteArray): ByteArray {
            val padding = (cipher.blockBytes - block.size % cipher.blockBytes) % cipher.blockBytes
            return cipher.encrypt(key, iv, if (padding == 0) block else block.copyOf(block.size + padding))
        }

        fun decrypt(ciphertext: ByteArray, iv: ByteArray): ByteArray {
            if (ciphertext.isEmpty() || ciphertext.size % cipher.blockBytes != 0) {
                throw ProtocolException(
                    "encrypted ISAKMP body of ${ciphertext.size} bytes is not a whole number of " +
                        "${cipher.blockBytes}-byte blocks",
                )
            }
            return cipher.decrypt(key, iv, ciphertext)
        }

        /** The next IV in the chain (RFC 2409 appendix B). */
        fun lastBlock(ciphertext: ByteArray): ByteArray =
            ciphertext.copyOfRange(ciphertext.size - cipher.blockBytes, ciphertext.size)
    }

    private fun cryptoFor(phase1: Phase1Result) =
        SaCrypto(Prf(phase1.hash), CbcCipher.forIke(phase1.encryption), phase1.encryptionKey)

    /**
     * Emits a payload chain whose first element is a HASH payload. [rest] is serialised on its own
     * so the caller can hash exactly the bytes that follow the HASH payload, which is what
     * HASH(1), HASH(2) and the informational HASH are computed over.
     */
    private fun chainAfterHash(hash: ByteArray, rest: List<IkePayload>): ByteArray = ByteWriter(64)
        .u8(rest.firstOrNull()?.type ?: PayloadType.NONE)
        .u8(0)
        .u16(hash.size + 4)
        .bytes(hash)
        .bytes(IsakmpCodec.encodeChain(rest))
        .toByteArray()

    private fun payloadBlockOf(message: ByteArray): ByteArray {
        if (message.size <= IsakmpCodec.HEADER_SIZE) {
            throw ProtocolException("ISAKMP message carries no payload block")
        }
        return message.copyOfRange(IsakmpCodec.HEADER_SIZE, message.size)
    }

    // ---------------------------------------------------------------------------------------
    // Small helpers
    // ---------------------------------------------------------------------------------------

    private fun <T : IkePayload> requirePayload(payload: T?, what: String): T =
        payload ?: throw ProtocolException("$what payload is missing from the peer's message")

    private fun ipv4(address: InetAddress): ByteArray {
        val raw = address.address
        if (raw.size != 4) {
            throw TunnelException(
                TunnelErrorKind.INTERNAL,
                "IKEv1 over IPv6 is not supported (${address.hostAddress})",
            )
        }
        return raw
    }

    private fun bestEffort(what: String, action: () -> Unit) {
        try {
            action()
        } catch (e: Exception) {
            log.w("could not send $what: ${e.message}", e)
        }
    }

    private fun sequenceOf(data: ByteArray): Long =
        if (data.size >= 4) ByteReader(data).u32() else -1L

    private fun randomNonZeroInt(): Int = ByteReader(Bytes.randomNonZero(4)).i32()

    /** Message id 0 is reserved for phase 1, so every phase-2 exchange needs a non-zero one. */
    private fun randomMessageId(): Int = randomNonZeroInt()

    /** SPI values 0..255 are reserved by RFC 4303 section 2.1. */
    private fun randomSpi(): Int {
        while (true) {
            val spi = ByteReader(Bytes.random(ESP_SPI_BYTES)).i32()
            if (spi.toLong() and 0xFFFFFFFFL >= 256L) return spi
        }
    }

    private fun int32(value: Int): ByteArray = ByteWriter(4).i32(value).toByteArray()

    private companion object {
        const val TAG = "IKEv1"
        const val NONCE_BYTES = 32
        const val ESP_SPI_BYTES = 4
        const val MAX_BACKOFF_FACTOR = 8
        const val REMEMBERED_QUICK_MODES = 4
    }
}
