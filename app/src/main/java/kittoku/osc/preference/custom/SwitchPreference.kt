package kittoku.osc.preference.custom

import android.content.Context
import android.util.AttributeSet
import androidx.preference.SwitchPreferenceCompat
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getBooleanPrefValue


internal abstract class SwitchPreference(context: Context, attrs: AttributeSet) : SwitchPreferenceCompat(context, attrs), OscPreference {
    override fun updateView() {
        isChecked = getBooleanPrefValue(oscPrefKey, sharedPreferences!!)
    }

    override fun onAttached() {
        initialize()
    }
}

internal class SSLDoSpecifyCertPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.SSL_DO_SPECIFY_CERT
    override val parentKey: OscPrefKey? = null
    override val preferenceTitle = "Specify Trusted Certificates"
}

internal class SSLDoSelectSuitesPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.SSL_DO_SELECT_SUITES
    override val parentKey: OscPrefKey? = null
    override val preferenceTitle = "Enable Only Selected Cipher Suites"
}

internal class SSLDoUseCustomSNIPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.SSL_DO_USE_CUSTOM_SNI
    override val parentKey: OscPrefKey? = null
    override val preferenceTitle = "Use Custom SNI"
}

internal class PPPDoRequestStaticIPv4AddressPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.PPP_DO_REQUEST_STATIC_IPv4_ADDRESS
    override val parentKey = OscPrefKey.PPP_IPv4_ENABLED
    override val preferenceTitle = "Request Static IPv4 Address"
}

internal class ProxyDoUseProxyPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.PROXY_DO_USE_PROXY
    override val parentKey: OscPrefKey? = null
    override val preferenceTitle = "Use HTTP Proxy"
}

internal class DNSDoRequestAddressPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.DNS_DO_REQUEST_ADDRESS
    override val parentKey: OscPrefKey? = null
    override val preferenceTitle = "Request DNS Server Address"
}

internal class DNSDoUseCustomServerPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.DNS_DO_USE_CUSTOM_SERVER
    override val parentKey: OscPrefKey? = null
    override val preferenceTitle = "Use Custom DNS Server"
}

internal class RouteDoAddCustomRoutesPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.ROUTE_DO_ADD_CUSTOM_ROUTES
    override val parentKey: OscPrefKey? = null
    override val preferenceTitle = "Add Custom Routes"
}

internal class RouteDoEnableAppBasedRulePreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.ROUTE_DO_ENABLE_APP_BASED_RULE
    override val parentKey: OscPrefKey? = null
    override val preferenceTitle = "Enable App-Based Rule"
}

internal class ReconnectionEnabledPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.RECONNECTION_ENABLED
    override val parentKey: OscPrefKey? = null
    override val preferenceTitle = "Enable Reconnection"
}

internal class LogDoSaveLogPreference(context: Context, attrs: AttributeSet) : SwitchPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.LOG_DO_SAVE_LOG
    override val parentKey: OscPrefKey? = null
    override val preferenceTitle = "Save Log"
}
