package kittoku.osc.client

import androidx.preference.PreferenceManager
import kittoku.osc.preference.AppString
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getIntPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue
import kittoku.osc.preference.getValidAllowedAppInfos
import kittoku.osc.service.SstpVpnService
import kittoku.osc.terminal.IPTerminal
import kittoku.osc.terminal.SSLTerminal
import kittoku.osc.unit.ppp.option.AuthOption
import kittoku.osc.unit.ppp.option.AuthOptionMSChapv2
import kittoku.osc.unit.ppp.option.AuthOptionPAP
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.*


internal class ChapMessage {
    val serverChallenge = ByteArray(16)
    val clientChallenge = ByteArray(16)
    val serverResponse = ByteArray(42)
    val clientResponse = ByteArray(24)
}

internal enum class Where {
    SSL,
    PROXY,
    SSTP_DATA,
    SSTP_CONTROL,
    SSTP_REQUEST,
    SSTP_HASH,
    PPP,
    PAP,
    CHAP,
    LCP,
    LCP_MRU,
    LCP_AUTH,
    IPCP,
    IPCP_IP,
    IPV6CP,
    IPV6CP_IDENTIFIER,
    IPv4,
    IPv6,
    ROUTE,
    INCOMING,
    OUTGOING,
}

internal data class ControlMessage(
    val from: Where,
    val result: Result
)
internal enum class Result {
    PROCEEDED,

    // common errors
    ERR_TIMEOUT,
    ERR_COUNT_EXHAUSTED,
    ERR_UNKNOWN_TYPE, // the data cannot be parsed
    ERR_UNEXPECTED_MESSAGE, // the data can be parsed, but it's received in the wrong time
    ERR_PARSING_FAILED,
    ERR_VERIFICATION_FAILED,

    // for SSTP
    ERR_NEGATIVE_ACKNOWLEDGED,
    ERR_ABORT_REQUESTED,
    ERR_DISCONNECT_REQUESTED,

    // for PPP
    ERR_TERMINATE_REQUESTED,
    ERR_PROTOCOL_REJECTED,
    ERR_CODE_REJECTED,
    ERR_AUTHENTICATION_FAILED,
    ERR_ADDRESS_REJECTED,
    ERR_OPTION_REJECTED,

    // for IP
    ERR_INVALID_ADDRESS,

    // for INCOMING
    ERR_INVALID_PACKET_SIZE,
}

internal class ClientBridge(internal val service: SstpVpnService) {
    internal val prefs = PreferenceManager.getDefaultSharedPreferences(service)
    internal val builder = service.Builder()
    internal lateinit var handler: CoroutineExceptionHandler

    internal val controlMailbox = Channel<ControlMessage>(Channel.BUFFERED)

    internal var sslTerminal: SSLTerminal? = null
    internal var ipTerminal: IPTerminal? = null

    internal val HOME_USERNAME = getStringPrefValue(OscPrefKey.HOME_USERNAME, prefs)
    internal val HOME_PASSWORD = getStringPrefValue(OscPrefKey.HOME_PASSWORD, prefs)
    internal val PPP_MRU = getIntPrefValue(OscPrefKey.PPP_MRU, prefs)
    internal val PPP_MTU = getIntPrefValue(OscPrefKey.PPP_MTU, prefs)
    internal val PPP_PAP_ENABLED = getBooleanPrefValue(OscPrefKey.PPP_PAP_ENABLED, prefs)
    internal val PPP_MSCHAPv2_ENABLED = getBooleanPrefValue(OscPrefKey.PPP_MSCHAPv2_ENABLED, prefs)
    internal val PPP_IPv4_ENABLED = getBooleanPrefValue(OscPrefKey.PPP_IPv4_ENABLED, prefs)
    internal val PPP_IPv6_ENABLED = getBooleanPrefValue(OscPrefKey.PPP_IPv6_ENABLED, prefs)

    internal lateinit var chapMessage: ChapMessage
    internal val nonce = ByteArray(32)
    internal val guid = UUID.randomUUID().toString()
    internal var hashProtocol: Byte = 0

    private val mutex = Mutex()
    private var frameID = -1

    internal var currentMRU = PPP_MRU
    internal var currentAuth = getPreferredAuthOption()
    internal val currentIPv4 = ByteArray(4)
    internal val currentIPv6 = ByteArray(8)
    internal val currentProposedDNS = ByteArray(4)

    internal val allowedApps: List<AppString> = mutableListOf<AppString>().also {
        if (getBooleanPrefValue(OscPrefKey.ROUTE_DO_ENABLE_APP_BASED_RULE, prefs)) {
            getValidAllowedAppInfos(prefs, service.packageManager).forEach { info ->
                it.add(
                    AppString(
                        info.packageName,
                        service.packageManager.getApplicationLabel(info).toString()
                    )
                )
            }
        }
    }

    internal fun getPreferredAuthOption(): AuthOption {
        return if (PPP_MSCHAPv2_ENABLED) AuthOptionMSChapv2() else AuthOptionPAP()
    }

    internal fun attachSSLTerminal() {
        sslTerminal = SSLTerminal(this)
    }

    internal fun attachIPTerminal() {
        ipTerminal = IPTerminal(this)
    }

    internal suspend fun allocateNewFrameID(): Byte {
        mutex.withLock {
            frameID += 1
            return frameID.toByte()
        }
    }
}
