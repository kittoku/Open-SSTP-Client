package kittoku.osc.preference

import android.content.Context
import android.content.SharedPreferences
import android.widget.Toast
import kittoku.osc.MAX_MRU
import kittoku.osc.MAX_MTU
import kittoku.osc.MIN_MRU
import kittoku.osc.MIN_MTU
import kittoku.osc.preference.accessor.*


internal fun toastInvalidSetting(message: String, context: Context) {
    Toast.makeText(context, "INVALID SETTING: $message", Toast.LENGTH_LONG).show()
}

internal fun checkPreferences(prefs: SharedPreferences): String? {
    getStringPrefValue(OscPreference.HOME_HOSTNAME, prefs).also {
        if (it.isEmpty()) return "Hostname is missing"
    }

    getIntPrefValue(OscPreference.SSL_PORT, prefs).also {
        if (it !in 0..65535) return "The given port is out of 0-65535"
    }

    val doAddCerts = getBooleanPrefValue(OscPreference.SSL_DO_ADD_CERT, prefs)
    val version = getStringPrefValue(OscPreference.SSL_VERSION, prefs)
    val certDir = getURIPrefValue(OscPreference.SSL_CERT_DIR, prefs)
    if (doAddCerts && version == "DEFAULT") return "Adding trusted certificates needs SSL version to be specified"

    if (doAddCerts && certDir == null) return "No certificates directory was selected"

    val doSelectSuites = getBooleanPrefValue(OscPreference.SSL_DO_SELECT_SUITES, prefs)
    val suites = getSetPrefValue(OscPreference.SSL_SUITES, prefs)
    if (doSelectSuites && suites.isEmpty()) return "No cipher suite was selected"

    if (getBooleanPrefValue(OscPreference.PROXY_DO_USE_PROXY, prefs)) {
        getStringPrefValue(OscPreference.HOME_HOSTNAME, prefs).also {
            if (it.isEmpty()) return "Proxy server hostname is missing"
        }

        getIntPrefValue(OscPreference.PROXY_PORT, prefs).also {
            if (it !in 0..65535) return "The given proxy server port is out of 0-65535"
        }
    }

    getIntPrefValue(OscPreference.PPP_MRU, prefs).also {
        if (it !in MIN_MRU..MAX_MRU) return "The given MRU is out of $MIN_MRU-$MAX_MRU"
    }

    getIntPrefValue(OscPreference.PPP_MTU, prefs).also {
        if (it !in MIN_MTU..MAX_MTU) return "The given MRU is out of $MIN_MTU-$MAX_MTU"
    }

    val isIPv4Enabled = getBooleanPrefValue(OscPreference.PPP_IPv4_ENABLED, prefs)
    val isIPv6Enabled = getBooleanPrefValue(OscPreference.PPP_IPv6_ENABLED, prefs)
    if (!isIPv4Enabled && !isIPv6Enabled) return "No network protocol was enabled"

    val isStaticIPv4Requested = getBooleanPrefValue(OscPreference.PPP_DO_REQUEST_STATIC_IPv4_ADDRESS, prefs)
    if (isIPv4Enabled && isStaticIPv4Requested) {
        getStringPrefValue(OscPreference.PPP_STATIC_IPv4_ADDRESS, prefs).also {
            if (it.isEmpty()) return "No static IPv4 address was given"
        }
    }

    val isPAPEnabled = getBooleanPrefValue(OscPreference.PPP_PAP_ENABLED, prefs)
    val isMSChapv2Enabled = getBooleanPrefValue(OscPreference.PPP_MSCHAPv2_ENABLED, prefs)
    if (!isPAPEnabled && !isMSChapv2Enabled) return "No authentication protocol was enabled"

    getIntPrefValue(OscPreference.PPP_AUTH_TIMEOUT, prefs).also {
        if (it < 1) return "PPP authentication timeout period must be >=1 second"
    }

    val isCustomDNSServerUsed = getBooleanPrefValue(OscPreference.DNS_DO_USE_CUSTOM_SERVER, prefs)
    val isCustomAddressEmpty = getStringPrefValue(OscPreference.DNS_CUSTOM_ADDRESS, prefs).isEmpty()
    if (isCustomDNSServerUsed && isCustomAddressEmpty) {
        return "No custom DNS server address was given"
    }

    getIntPrefValue(OscPreference.RECONNECTION_COUNT, prefs).also {
        if (it < 1) return "Retry Count must be a positive integer"
    }

    val doSaveLog = getBooleanPrefValue(OscPreference.LOG_DO_SAVE_LOG, prefs)
    val logDir = getURIPrefValue(OscPreference.LOG_DIR, prefs)
    if (doSaveLog && logDir == null) return "No log directory was selected"


    return null
}
