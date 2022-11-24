package kittoku.osc.preference.custom

import android.content.Context
import android.util.AttributeSet
import androidx.preference.SwitchPreferenceCompat
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.getBooleanPrefValue


internal abstract class SwitchPreference(context: Context, attrs: AttributeSet) : SwitchPreferenceCompat(context, attrs) {
    abstract val oscPreference: OscPreference
    abstract val preferenceTitle: String
    protected open val dependingPreference: OscPreference? = null

    private fun initialize() {
        isChecked = getBooleanPrefValue(oscPreference, sharedPreferences!!)
    }

    override fun onAttached() {
        super.onAttached()

        dependingPreference?.also {
            dependency = it.name
        }

        initialize()

        title = preferenceTitle
        isSingleLineTitle = false
    }
}

internal class SSLDoAddCertPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.SSL_DO_ADD_CERT
    override val preferenceTitle = "Add Trusted Certificates"
}

internal class SSLDoSelectSuitesPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.SSL_DO_SELECT_SUITES
    override val preferenceTitle = "Enable Only Selected Cipher Suites"
}

internal class PPPDoRequestStaticIPv4AddressPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.PPP_DO_REQUEST_STATIC_IPv4_ADDRESS
    override val preferenceTitle = "Request Static IPv4 Address"
    override val dependingPreference = OscPreference.PPP_IPv4_ENABLED
}

internal class ProxyDoUseProxyPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.PROXY_DO_USE_PROXY
    override val preferenceTitle = "Use HTTP Proxy"
}

internal class DNSDoRequestAddressPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.DNS_DO_REQUEST_ADDRESS
    override val preferenceTitle = "Request DNS Server Address"
}

internal class DNSDoUseCustomServerPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.DNS_DO_USE_CUSTOM_SERVER
    override val preferenceTitle = "Use Custom DNS Server"
}

internal class RouteDoAddCustomRoutesPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.ROUTE_DO_ADD_CUSTOM_ROUTES
    override val preferenceTitle = "Add Custom Routes"
}

internal class RouteDoEnableAppBasedRulePreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.ROUTE_DO_ENABLE_APP_BASED_RULE
    override val preferenceTitle = "Enable App-Based Rule"
}

internal class ReconnectionEnabledPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.RECONNECTION_ENABLED
    override val preferenceTitle = "Enable Reconnection"
}

internal class LogDoSaveLogPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPreference = OscPreference.LOG_DO_SAVE_LOG
    override val preferenceTitle = "Save Log"
}
