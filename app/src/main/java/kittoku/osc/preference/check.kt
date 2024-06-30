package kittoku.osc.preference

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.widget.Toast
import kittoku.osc.MAX_MRU
import kittoku.osc.MAX_MTU
import kittoku.osc.MIN_MRU
import kittoku.osc.MIN_MTU
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getIntPrefValue
import kittoku.osc.preference.accessor.getSetPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue
import kittoku.osc.preference.accessor.getURIPrefValue


internal fun toastInvalidSetting(message: String, context: Context) {
    Toast.makeText(context, "INVALID SETTING: $message", Toast.LENGTH_LONG).show()
}

internal fun checkPreferences(prefs: SharedPreferences): String? {
    getStringPrefValue(OscPrefKey.HOME_HOSTNAME, prefs).also {
        if (it.isEmpty()) return "Hostname is missing"
    }

    getIntPrefValue(OscPrefKey.SSL_PORT, prefs).also {
        if (it !in 0..65535) return "The given port is out of 0-65535"
    }

    val doSpecifyCerts = getBooleanPrefValue(OscPrefKey.SSL_DO_SPECIFY_CERT, prefs)
    val version = getStringPrefValue(OscPrefKey.SSL_VERSION, prefs)
    val certDir = getURIPrefValue(OscPrefKey.SSL_CERT_DIR, prefs)
    if (doSpecifyCerts && version == "DEFAULT") return "Specifying trusted certificates needs SSL version to be specified"

    if (doSpecifyCerts && certDir == null) return "No certificates directory was selected"

    val doSelectSuites = getBooleanPrefValue(OscPrefKey.SSL_DO_SELECT_SUITES, prefs)
    val suites = getSetPrefValue(OscPrefKey.SSL_SUITES, prefs)
    if (doSelectSuites && suites.isEmpty()) return "No cipher suite was selected"

    val doUseCustomSNI = getBooleanPrefValue(OscPrefKey.SSL_DO_USE_CUSTOM_SNI, prefs)
    val isAPILevelLacked = Build.VERSION.SDK_INT < Build.VERSION_CODES.N
    val customSNIHostname = getStringPrefValue(OscPrefKey.SSL_CUSTOM_SNI, prefs)
    if (doUseCustomSNI && isAPILevelLacked) return "Custom SNI needs 24 or higher API level"
    if (doUseCustomSNI && customSNIHostname.isEmpty()) return "Custom SNI Hostname must not be blank"

    if (getBooleanPrefValue(OscPrefKey.PROXY_DO_USE_PROXY, prefs)) {
        getStringPrefValue(OscPrefKey.HOME_HOSTNAME, prefs).also {
            if (it.isEmpty()) return "Proxy server hostname is missing"
        }

        getIntPrefValue(OscPrefKey.PROXY_PORT, prefs).also {
            if (it !in 0..65535) return "The given proxy server port is out of 0-65535"
        }
    }

    getIntPrefValue(OscPrefKey.PPP_MRU, prefs).also {
        if (it !in MIN_MRU..MAX_MRU) return "The given MRU is out of $MIN_MRU-$MAX_MRU"
    }

    getIntPrefValue(OscPrefKey.PPP_MTU, prefs).also {
        if (it !in MIN_MTU..MAX_MTU) return "The given MRU is out of $MIN_MTU-$MAX_MTU"
    }

    val isIPv4Enabled = getBooleanPrefValue(OscPrefKey.PPP_IPv4_ENABLED, prefs)
    val isIPv6Enabled = getBooleanPrefValue(OscPrefKey.PPP_IPv6_ENABLED, prefs)
    if (!isIPv4Enabled && !isIPv6Enabled) return "No network protocol was enabled"

    val isStaticIPv4Requested = getBooleanPrefValue(OscPrefKey.PPP_DO_REQUEST_STATIC_IPv4_ADDRESS, prefs)
    if (isIPv4Enabled && isStaticIPv4Requested) {
        getStringPrefValue(OscPrefKey.PPP_STATIC_IPv4_ADDRESS, prefs).also {
            if (it.isEmpty()) return "No static IPv4 address was given"
        }
    }

    val authProtocols = getSetPrefValue(OscPrefKey.PPP_AUTH_PROTOCOLS, prefs)
    if (authProtocols.isEmpty()) return "No authentication protocol was selected"

    getIntPrefValue(OscPrefKey.PPP_AUTH_TIMEOUT, prefs).also {
        if (it < 1) return "PPP authentication timeout period must be >=1 second"
    }

    val isCustomDNSServerUsed = getBooleanPrefValue(OscPrefKey.DNS_DO_USE_CUSTOM_SERVER, prefs)
    val isCustomAddressEmpty = getStringPrefValue(OscPrefKey.DNS_CUSTOM_ADDRESS, prefs).isEmpty()
    if (isCustomDNSServerUsed && isCustomAddressEmpty) {
        return "No custom DNS server address was given"
    }

    getIntPrefValue(OscPrefKey.RECONNECTION_COUNT, prefs).also {
        if (it < 1) return "Retry Count must be a positive integer"
    }

    val doSaveLog = getBooleanPrefValue(OscPrefKey.LOG_DO_SAVE_LOG, prefs)
    val logDir = getURIPrefValue(OscPrefKey.LOG_DIR, prefs)
    if (doSaveLog && logDir == null) return "No log directory was selected"


    return null
}
