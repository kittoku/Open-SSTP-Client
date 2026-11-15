package com.arcansecurity.vpn.l2tpipsec.core.tunnel

import com.arcansecurity.vpn.l2tpipsec.core.crypto.DhGroup
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspIntegrity
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeHash
import com.arcansecurity.vpn.l2tpipsec.core.util.redacted

enum class IkeExchangeMode { MAIN, AGGRESSIVE }

/** ISAKMP identification types (RFC 2407 section 4.6.2.1) usable as a local/peer identity. */
enum class IkeIdentityType(val value: Int) {
    /** Use the socket's local address; the usual choice for L2TP road-warriors. */
    AUTO_IPV4(1),
    IPV4_ADDR(1),
    FQDN(2),
    USER_FQDN(3),
    KEY_ID(11),
}

data class IkeIdentity(
    val type: IkeIdentityType = IkeIdentityType.AUTO_IPV4,
    val value: String = "",
)

/** Phase-1 (ISAKMP SA) proposal. Defaults match `aes256-sha256-modp2048`. */
data class Phase1Proposal(
    val encryption: IkeEncryption = IkeEncryption.AES_CBC_256,
    val hash: IkeHash = IkeHash.SHA2_256,
    val dhGroup: DhGroup = DhGroup.MODP_2048,
    val lifetimeSeconds: Int = 3 * 3600,
)

/** Phase-2 (IPsec SA) proposal. Defaults match `aes256-sha256` with no PFS. */
data class Phase2Proposal(
    val encryption: EspEncryption = EspEncryption.ESP_AES_CBC_256,
    val integrity: EspIntegrity = EspIntegrity.HMAC_SHA2_256_128,
    /** `null` disables PFS, which is what `esp=aes256-sha256!` means on strongSwan. */
    val pfsGroup: DhGroup? = null,
    val lifetimeSeconds: Int = 3600,
)

enum class PppAuthProtocol { PAP, CHAP_MD5, MSCHAP_V2 }

/**
 * Everything the stack needs to bring a tunnel up.
 *
 * Two of these fields are credentials, so the class overrides [toString]; see the note there before
 * adding another one.
 */
data class VpnConfig(
    val serverHost: String,
    /** IKE pre-shared key. Never logged: see [toString]. */
    val presharedKey: String,
    val username: String,
    /** PPP password. Never logged: see [toString]. */
    val password: String,

    val exchangeMode: IkeExchangeMode = IkeExchangeMode.MAIN,
    val localIdentity: IkeIdentity = IkeIdentity(),
    val phase1: Phase1Proposal = Phase1Proposal(),
    val phase2: Phase2Proposal = Phase2Proposal(),

    /**
     * Android applications cannot open raw IP sockets, so ESP can only ever be carried inside
     * UDP/4500. The client therefore advertises a bogus source NAT-D hash, exactly like
     * strongSwan's `forceencaps=yes`, which makes the responder encapsulate unconditionally.
     */
    val forceUdpEncapsulation: Boolean = true,

    val ikePort: Int = 500,
    val natTraversalPort: Int = 4500,
    val l2tpPort: Int = 1701,

    /** Authentication protocols accepted during PPP, in order of preference. */
    val allowedPppAuth: List<PppAuthProtocol> =
        listOf(PppAuthProtocol.MSCHAP_V2, PppAuthProtocol.CHAP_MD5, PppAuthProtocol.PAP),

    val mtu: Int = 1400,
    /** Host name advertised in the L2TP Host Name AVP. */
    val l2tpHostName: String = "android",
    /** DNS servers to push to the system; empty means "use whatever IPCP negotiated". */
    val dnsOverride: List<String> = emptyList(),
    /** Route all IPv6 into the tunnel's blackhole so traffic cannot leak around an IPv4-only VPN. */
    val blockIpv6: Boolean = true,

    /**
     * Replace the IPsec and ISAKMP SAs before their negotiated lifetimes run out, instead of
     * letting the tunnel drop and reconnect. Turning this off is only useful for diagnosing a peer
     * that mishandles rekeying.
     */
    val rekeyEnabled: Boolean = true,

    /**
     * How long a superseded IPsec SA keeps being accepted for inbound traffic. The peer goes on
     * sending on the old SA until it has installed the new one, so retiring it the instant the
     * rekey completes drops the packets in flight.
     */
    val saOverlapMs: Int = 30_000,

    val ikeRetransmitTimeoutMs: Int = 3_000,
    val ikeMaxRetransmits: Int = 5,
    val connectTimeoutMs: Int = 45_000,
    /** RFC 3948 section 4 NAT keepalive period. */
    val natKeepaliveIntervalMs: Int = 20_000,
    /** L2TP HELLO period; also doubles as a liveness probe for the whole tunnel. */
    val l2tpHelloIntervalMs: Int = 60_000,
    /**
     * Carried here so a saved profile keeps it, but nothing in this module reads it: the stack
     * always emits at every level and the [com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger]
     * the host injects decides what to keep. The Android service reads this flag and sets its
     * sink's threshold accordingly.
     */
    val debugLogging: Boolean = false,
) {
    init {
        // These messages travel on an exception, which goes further than a log line, so they name
        // the offending field and never quote a credential's value.
        require(serverHost.isNotBlank()) { "serverHost is required" }
        require(presharedKey.isNotEmpty()) { "presharedKey is required" }
        require(mtu in 576..1500) { "mtu out of range: $mtu" }
        require(allowedPppAuth.isNotEmpty()) { "at least one PPP auth protocol is required" }
    }

    /**
     * Written out by hand because the one a `data class` generates prints every property, the
     * pre-shared key and the PPP password in the clear.
     *
     * A config reaches a string more easily than it looks: an interpolation in a log line, a
     * `require` message, an exception a crash reporter serialises. The Android app keeps the trace
     * in a buffer the user can copy or share, so any of those would put both credentials on their
     * way off the device. Both are therefore reduced to whether they are set; everything else is
     * the operational detail that makes a shared trace worth reading.
     *
     * Add a property below only after deciding which of the two it is.
     * `VpnConfigSecrecyTest` enumerates the class and will fail until that decision is recorded.
     */
    override fun toString(): String =
        "VpnConfig(serverHost=$serverHost, presharedKey=${redacted(presharedKey)}, " +
            "username=$username, password=${redacted(password)}, exchangeMode=$exchangeMode, " +
            "localIdentity=$localIdentity, phase1=$phase1, phase2=$phase2, " +
            "forceUdpEncapsulation=$forceUdpEncapsulation, ikePort=$ikePort, " +
            "natTraversalPort=$natTraversalPort, l2tpPort=$l2tpPort, " +
            "allowedPppAuth=$allowedPppAuth, mtu=$mtu, l2tpHostName=$l2tpHostName, " +
            "dnsOverride=$dnsOverride, blockIpv6=$blockIpv6, rekeyEnabled=$rekeyEnabled, " +
            "saOverlapMs=$saOverlapMs, ikeRetransmitTimeoutMs=$ikeRetransmitTimeoutMs, " +
            "ikeMaxRetransmits=$ikeMaxRetransmits, connectTimeoutMs=$connectTimeoutMs, " +
            "natKeepaliveIntervalMs=$natKeepaliveIntervalMs, " +
            "l2tpHelloIntervalMs=$l2tpHelloIntervalMs, debugLogging=$debugLogging)"
}
