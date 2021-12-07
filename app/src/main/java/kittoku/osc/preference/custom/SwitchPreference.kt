package kittoku.osc.preference.custom

import android.content.Context
import android.util.AttributeSet
import androidx.preference.SwitchPreferenceCompat
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.getBooleanPrefValue


internal abstract class SwitchPreference(context: Context, attrs: AttributeSet) : SwitchPreferenceCompat(context, attrs) {
    abstract val oscPreference: OscPreference
    abstract val preferenceTitle: String

    private fun initialize() {
        isChecked = getBooleanPrefValue(oscPreference, sharedPreferences)
    }

    override fun onAttached() {
        super.onAttached()

        initialize()

        title = preferenceTitle
        isSingleLineTitle = false
    }
}

internal class SSLDoVerifyPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.SSL_DO_VERIFY
    override val preferenceTitle = "Verify Hostname"
}

internal class SSLDoAddCertPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.SSL_DO_ADD_CERT
    override val preferenceTitle = "Add Trusted Certificates"
}

internal class SSLDoSelectSuitesPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.SSL_DO_SELECT_SUITES
    override val preferenceTitle = "Enable Only Selected Cipher Suites"
}

internal class PPPPapEnabledPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.PPP_PAP_ENABLED
    override val preferenceTitle = "Enable PAP"
}

internal class PPPMsChapv2EnabledPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.PPP_MSCHAPv2_ENABLED
    override val preferenceTitle = "Enable MS-CHAPv2"
}

internal class PPPIPv4EnabledPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.PPP_IPv4_ENABLED
    override val preferenceTitle = "Enable IPv4"
}

internal class PPPIPv6EnabledPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.PPP_IPv6_ENABLED
    override val preferenceTitle = "Enable IPv6"
}

internal class IPOnlyLanPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.IP_ONLY_LAN
    override val preferenceTitle = "Route Only Packets to LAN (IPv4)"
}

internal class IPOnlyUlaPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.IP_ONLY_ULA
    override val preferenceTitle = "Route Only Packets to ULA (IPv6)"
}

internal class ReconnectionEnabledPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.RECONNECTION_ENABLED
    override val preferenceTitle = "Enable Reconnection"
}

internal class LogDoSaveLogPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.LOG_DO_SAVE_LOG
    override val preferenceTitle = "Save Log"
}
