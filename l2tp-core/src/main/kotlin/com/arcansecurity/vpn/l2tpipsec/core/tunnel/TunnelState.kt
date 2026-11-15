package com.arcansecurity.vpn.l2tpipsec.core.tunnel

enum class TunnelState {
    IDLE,
    RESOLVING,
    IKE_PHASE1,
    IKE_PHASE2,
    L2TP_TUNNEL,
    L2TP_SESSION,
    PPP_NEGOTIATION,
    CONNECTED,
    RECONNECTING,
    DISCONNECTING,
    FAILED,
}

/** Everything the UI wants to show once the tunnel is established. */
data class TunnelInfo(
    val serverAddress: String,
    val assignedAddress: String,
    val peerAddress: String,
    val dnsServers: List<String>,
    val mtu: Int,
    val natDetected: Boolean,
    val udpEncapsulated: Boolean,
    val phase1Description: String,
    val phase2Description: String,
    val pppAuthDescription: String,
)

data class TunnelStats(
    val bytesIn: Long = 0,
    val bytesOut: Long = 0,
    val packetsIn: Long = 0,
    val packetsOut: Long = 0,
    val connectedSinceMs: Long = 0,
    /** IPsec SAs installed since the tunnel came up, whoever started the exchange. */
    val ipsecRekeys: Long = 0,
    /** ISAKMP SAs renegotiated since the tunnel came up. */
    val ikeRekeys: Long = 0,
)

/** Categorised failures so the UI can give the user something actionable. */
enum class TunnelErrorKind {
    DNS_FAILURE,

    /** The socket itself would not carry the traffic: no route, no network, port unreachable. */
    NETWORK_UNREACHABLE,
    IKE_NO_RESPONSE,
    IKE_PROPOSAL_REJECTED,
    IKE_AUTH_FAILED,
    IPSEC_SA_FAILED,
    L2TP_FAILED,
    PPP_AUTH_FAILED,
    PPP_FAILED,
    TUN_UNAVAILABLE,
    PEER_DISCONNECTED,
    INTERNAL,
}

/**
 * A categorised failure.
 *
 * [message] travels furthest of anything this module produces: the app renders it on the status
 * card, logs it, and lets the user copy or share that log. It must therefore describe *what*
 * failed — a rejected proposal, a refused password — and never quote the credential involved. Use
 * [com.arcansecurity.vpn.l2tpipsec.core.util.redacted] if a value has to be mentioned at all.
 */
class TunnelException(
    val kind: TunnelErrorKind,
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

interface TunnelListener {
    fun onStateChanged(state: TunnelState, detail: String?) {}
    fun onConnected(info: TunnelInfo) {}
    fun onStats(stats: TunnelStats) {}
    fun onFailed(kind: TunnelErrorKind, message: String, cause: Throwable?) {}
    fun onDisconnected() {}

    companion object {
        val NONE = object : TunnelListener {}
    }
}
