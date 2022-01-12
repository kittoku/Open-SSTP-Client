package kittoku.osc.preference

import android.content.Context
import android.content.SharedPreferences
import android.widget.Toast
import kittoku.osc.MAX_MRU
import kittoku.osc.MAX_MTU
import kittoku.osc.MIN_MRU
import kittoku.osc.MIN_MTU
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getIntPrefValue
import kittoku.osc.preference.accessor.getSetPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue


internal fun toastInvalidSetting(message: String, context: Context?) {
    Toast.makeText(context, "INVALID SETTING: $message", Toast.LENGTH_LONG).show()
}

internal fun checkPreferences(prefs: SharedPreferences): String? {
    getStringPrefValue(OscPreference.HOME_HOSTNAME, prefs).also {
        if (it.isEmpty()) return "Host is missing"
    }

    getIntPrefValue(OscPreference.SSL_PORT, prefs).also {
        if (it !in 0..65535) return "The given port is out of 0-65535"
    }

    val doAddCerts = getBooleanPrefValue(OscPreference.SSL_DO_ADD_CERT, prefs)
    val version = getStringPrefValue(OscPreference.SSL_VERSION, prefs)
    val certDir = getStringPrefValue(OscPreference.SSL_CERT_DIR, prefs)
    if (doAddCerts && version == "DEFAULT") return "Adding trusted certificates needs SSL version to be specified"

    if (doAddCerts && certDir.isEmpty()) return "No certificates directory was selected"

    val doSelectSuites = getBooleanPrefValue(OscPreference.SSL_DO_SELECT_SUITES, prefs)
    val suites = getSetPrefValue(OscPreference.SSL_SUITES, prefs)
    if (doSelectSuites && suites.isEmpty()) return "No cipher suite was selected"

    val mru = getIntPrefValue(OscPreference.PPP_MRU, prefs).also {
        if (it !in MIN_MRU..MAX_MRU) return "The given MRU is out of $MIN_MRU-$MAX_MRU"
    }

    val mtu = getIntPrefValue(OscPreference.PPP_MTU, prefs).also {
        if (it !in MIN_MTU..MAX_MTU) return "The given MRU is out of $MIN_MTU-$MAX_MTU"
    }

    val isIpv4Enabled = getBooleanPrefValue(OscPreference.PPP_IPv4_ENABLED, prefs)
    val isIpv6Enabled = getBooleanPrefValue(OscPreference.PPP_IPv6_ENABLED, prefs)
    if (!isIpv4Enabled && !isIpv6Enabled) return "No network protocol was enabled"

    val isPapEnabled = getBooleanPrefValue(OscPreference.PPP_PAP_ENABLED, prefs)
    val isMschapv2Enabled = getBooleanPrefValue(OscPreference.PPP_MSCHAPv2_ENABLED, prefs)
    if (!isPapEnabled && !isMschapv2Enabled) return "No authentication protocol was enabled"

    getIntPrefValue(OscPreference.PPP_AUTH_TIMEOUT, prefs).also {
        if (it < 1) return "PPP authentication timeout period must be >=1 second"
    }

    getIntPrefValue(OscPreference.IP_PREFIX, prefs).also {
        if (it !in 0..32) return "The given address prefix length is out of 0-32"
    }

    getIntPrefValue(OscPreference.RECONNECTION_COUNT, prefs).also {
        if (it < 1) return "Retry Count must be a positive integer"
    }

    getIntPrefValue(OscPreference.BUFFER_INCOMING, prefs).also {
        if (it < 2 * mru) return "Incoming Buffer Size must be >= 2 * MRU"
    }

    getIntPrefValue(OscPreference.BUFFER_OUTGOING, prefs).also {
        if (it < 2 * mtu) return "Outgoing Buffer Size must be >= 2 * MTU"
    }

    val doSaveLog = getBooleanPrefValue(OscPreference.LOG_DO_SAVE_LOG, prefs)
    val logDir = getStringPrefValue(OscPreference.LOG_DIR, prefs)
    if (doSaveLog && logDir.isEmpty()) return "No log directory was selected"


    return null
}
