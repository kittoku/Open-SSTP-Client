package com.arcansecurity.vpn.l2tpipsec.core.ike

/**
 * Wire constants of ISAKMP (RFC 2408), the IKEv1 exchanges (RFC 2409), the IPsec DOI (RFC 2407)
 * and NAT traversal (RFC 3947 plus the pre-RFC drafts that most L2TP servers still speak).
 */

/** ISAKMP payload types. Values above 128 are the pre-RFC NAT-T draft allocations. */
object PayloadType {
    const val NONE = 0
    const val SA = 1
    const val PROPOSAL = 2
    const val TRANSFORM = 3
    const val KE = 4
    const val ID = 5
    const val CERT = 6
    const val CERTREQ = 7
    const val HASH = 8
    const val SIG = 9
    const val NONCE = 10
    const val NOTIFY = 11
    const val DELETE = 12
    const val VENDOR_ID = 13
    const val NAT_D = 20
    const val NAT_OA = 21
    const val NAT_D_DRAFT = 130
    const val NAT_OA_DRAFT = 131
}

object ExchangeType {
    /** Main Mode. */
    const val IDENTITY_PROTECTION = 2
    const val AGGRESSIVE = 4
    const val INFORMATIONAL = 5
    const val QUICK_MODE = 32
}

object IsakmpFlags {
    const val ENCRYPTION = 0x01
    const val COMMIT = 0x02
    const val AUTH_ONLY = 0x04
}

/** Protocol identifiers used inside proposal, notify and delete payloads (RFC 2407 section 4.4.1). */
object ProtocolId {
    const val ISAKMP = 1
    const val AH = 2
    const val ESP = 3
}

object Doi {
    const val IPSEC = 1
    const val SIT_IDENTITY_ONLY = 1
}

/** The single phase-1 transform identifier: KEY_IKE (RFC 2407 section 4.4.2). */
object TransformId {
    const val KEY_IKE = 1
}

/** Notify message types; 1..16383 are errors, 16384 and up are status notifications. */
object NotifyType {
    const val INVALID_PAYLOAD_TYPE = 1
    const val DOI_NOT_SUPPORTED = 2
    const val SITUATION_NOT_SUPPORTED = 3
    const val INVALID_COOKIE = 4
    const val INVALID_MAJOR_VERSION = 5
    const val INVALID_EXCHANGE_TYPE = 7
    const val INVALID_FLAGS = 8
    const val INVALID_MESSAGE_ID = 9
    const val INVALID_PROTOCOL_ID = 10
    const val INVALID_SPI = 11
    const val INVALID_TRANSFORM_ID = 12
    const val ATTRIBUTES_NOT_SUPPORTED = 13
    const val NO_PROPOSAL_CHOSEN = 14
    const val PAYLOAD_MALFORMED = 16
    const val INVALID_KEY_INFORMATION = 17
    const val INVALID_ID_INFORMATION = 18
    const val INVALID_HASH_INFORMATION = 23
    const val AUTHENTICATION_FAILED = 24
    const val CONNECTED = 16384
    const val INITIAL_CONTACT = 24578
    /** RFC 3706 dead peer detection. */
    const val DPD_R_U_THERE = 36136
    const val DPD_R_U_THERE_ACK = 36137

    /** Errors occupy 1..16383; anything above is informational and must not abort the exchange. */
    fun isError(type: Int): Boolean = type in 1..16383
}

/** Phase-1 (ISAKMP SA) attribute types, RFC 2409 appendix A. */
object Phase1Attribute {
    const val ENCRYPTION = 1
    const val HASH = 2
    const val AUTH_METHOD = 3
    const val GROUP_DESCRIPTION = 4
    const val LIFE_TYPE = 11
    const val LIFE_DURATION = 12
    const val KEY_LENGTH = 14

    const val LIFE_TYPE_SECONDS = 1
    const val LIFE_TYPE_KILOBYTES = 2
}

/** Phase-2 (IPsec DOI) attribute types, RFC 2407 section 4.5. */
object Phase2Attribute {
    const val SA_LIFE_TYPE = 1
    const val SA_LIFE_DURATION = 2
    const val GROUP_DESCRIPTION = 3
    const val ENCAPSULATION_MODE = 4
    const val AUTHENTICATION_ALGORITHM = 5
    const val KEY_LENGTH = 6

    const val LIFE_TYPE_SECONDS = 1
    const val LIFE_TYPE_KILOBYTES = 2
}

/**
 * Encapsulation modes. 3 and 4 are the RFC 3947 UDP-encapsulated modes; 61443 and 61444 are the
 * private-use values the NAT-T drafts squatted on, which older servers still expect.
 */
object EncapsulationMode {
    const val TUNNEL = 1
    const val TRANSPORT = 2
    const val UDP_TUNNEL = 3
    const val UDP_TRANSPORT = 4
    const val UDP_TUNNEL_DRAFT = 61443
    const val UDP_TRANSPORT_DRAFT = 61444

    fun isUdpEncapsulated(mode: Int): Boolean =
        mode == UDP_TUNNEL || mode == UDP_TRANSPORT ||
            mode == UDP_TUNNEL_DRAFT || mode == UDP_TRANSPORT_DRAFT
}

/** Identification types, RFC 2407 section 4.6.2.1. */
object IdType {
    const val IPV4_ADDR = 1
    const val FQDN = 2
    const val USER_FQDN = 3
    const val IPV4_ADDR_SUBNET = 4
    const val KEY_ID = 11
}

/** IP protocol numbers that appear in ID payloads. */
object IpProtocol {
    const val UDP = 17
}

/**
 * Which dialect of NAT traversal the peer speaks. The flavor selects the payload numbers and the
 * encapsulation-mode values, which the drafts and the final RFC allocated differently.
 */
enum class NatTraversalFlavor(
    val natdPayloadType: Int,
    val natOaPayloadType: Int,
    val udpTransportMode: Int,
    val udpTunnelMode: Int,
) {
    NONE(PayloadType.NAT_D, PayloadType.NAT_OA, EncapsulationMode.UDP_TRANSPORT, EncapsulationMode.UDP_TUNNEL),
    RFC_3947(PayloadType.NAT_D, PayloadType.NAT_OA, EncapsulationMode.UDP_TRANSPORT, EncapsulationMode.UDP_TUNNEL),
    DRAFT_02(
        PayloadType.NAT_D_DRAFT,
        PayloadType.NAT_OA_DRAFT,
        EncapsulationMode.UDP_TRANSPORT_DRAFT,
        EncapsulationMode.UDP_TUNNEL_DRAFT,
    ),
    DRAFT_03(
        PayloadType.NAT_D_DRAFT,
        PayloadType.NAT_OA_DRAFT,
        EncapsulationMode.UDP_TRANSPORT_DRAFT,
        EncapsulationMode.UDP_TUNNEL_DRAFT,
    ),
    ;

    /** The drafts never specified a responder NAT-OA, so only the initiator's is sent. */
    val sendsResponderNatOa: Boolean get() = this == RFC_3947
}
