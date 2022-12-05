package kittoku.osc.preference.custom

import android.content.Context
import android.text.InputType
import android.util.AttributeSet
import android.widget.EditText
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import androidx.preference.Preference.SummaryProvider
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getStringPrefValue


internal abstract class StringPreference(context: Context, attrs: AttributeSet) : EditTextPreference(context, attrs), OscPreference {
    protected open val provider = SummaryProvider<Preference> {
        getStringPrefValue(oscPrefKey, it.sharedPreferences!!).ifEmpty { "[No Value Entered]" }
    }

    protected open fun initEditText(editText: EditText) {
        editText.inputType = InputType.TYPE_CLASS_TEXT
    }

    override fun updateView() {
        text = getStringPrefValue(oscPrefKey, sharedPreferences!!)
    }

    override fun onAttached() {
        setOnBindEditTextListener { initEditText(it) }

        summaryProvider = provider

        initialize()
    }
}

internal class HomeHostnamePreference(context: Context, attrs: AttributeSet) : StringPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.HOME_HOSTNAME
    override val parentKey: OscPrefKey? = null
    override val preferenceTitle = "Hostname"
}

internal class HomeUsernamePreference(context: Context, attrs: AttributeSet) : StringPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.HOME_USERNAME
    override val parentKey: OscPrefKey? = null
    override val preferenceTitle = "Username"
}

internal class PPPStaticIPv4AddressPreference(context: Context, attrs: AttributeSet) : StringPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.PPP_STATIC_IPv4_ADDRESS
    override val preferenceTitle = "Static IPv4 Address"
    override val parentKey = OscPrefKey.PPP_DO_REQUEST_STATIC_IPv4_ADDRESS

    override fun initEditText(editText: EditText) {
        super.initEditText(editText)

        editText.hint = "192.168.0.1"
    }
}

internal class ProxyHostnamePreference(context: Context, attrs: AttributeSet) : StringPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.PROXY_HOSTNAME
    override val parentKey =  OscPrefKey.PROXY_DO_USE_PROXY
    override val preferenceTitle = "Proxy Server Hostname"
}

internal class ProxyUsernamePreference(context: Context, attrs: AttributeSet) : StringPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.PROXY_USERNAME
    override val parentKey =  OscPrefKey.PROXY_DO_USE_PROXY
    override val preferenceTitle = "Proxy Username (optional)"
}

internal class DNSCustomAddressPreference(context: Context, attrs: AttributeSet) : StringPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.DNS_CUSTOM_ADDRESS
    override val parentKey = OscPrefKey.DNS_DO_USE_CUSTOM_SERVER
    override val preferenceTitle = "Custom DNS Server Address"

    override fun onAttached() {
        dialogMessage = "NOTICE: packets associated with this address is routed to the VPN tunnel"

        super.onAttached()
    }
}

internal class RouteCustomRoutesPreference(context: Context, attrs: AttributeSet) : StringPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.ROUTE_CUSTOM_ROUTES
    override val parentKey = OscPrefKey.ROUTE_DO_ADD_CUSTOM_ROUTES
    override val preferenceTitle = "Edit Custom Routes"

    override fun updateView() {
        // to avoid the issue reported in https://issuetracker.google.com/issues/37032278
        text = getStringPrefValue(oscPrefKey, sharedPreferences!!).trim()
    }

    override val provider = SummaryProvider<Preference> {
        val currentValue = getStringPrefValue(oscPrefKey, it.sharedPreferences!!)

        if (currentValue.isEmpty()) {
            "[No Value Entered]"
        } else {
            "[Custom Routes Entered]"
        }
    }

    override fun initEditText(editText: EditText) {
        editText.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
        editText.hint = "192.168.1.0/24\n2001:db8::/32"
    }
}
