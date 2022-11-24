package kittoku.osc.preference.custom

import android.content.Context
import android.text.InputType
import android.util.AttributeSet
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import androidx.preference.Preference.SummaryProvider
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.getStringPrefValue


internal abstract class StringPreference(context: Context, attrs: AttributeSet) : EditTextPreference(context, attrs) {
    abstract val oscPreference: OscPreference
    abstract val preferenceTitle: String
    protected open val textType = InputType.TYPE_CLASS_TEXT
    protected open val hint: String? = null
    protected open val dependingPreference: OscPreference? = null
    protected open val provider = SummaryProvider<Preference> {
        getStringPrefValue(oscPreference, it.sharedPreferences!!).ifEmpty { "[No Value Entered]" }
    }

    override fun onAttached() {
        super.onAttached()

        dependingPreference?.also {
            dependency = it.name
        }

        setOnBindEditTextListener { editText ->
            editText.inputType = textType
            hint?.also {
                editText.hint = it
            }
        }

        text = getStringPrefValue(oscPreference, sharedPreferences!!)
        title = preferenceTitle
        summaryProvider = provider
    }
}

internal class HomeHostnamePreference(context: Context, attrs: AttributeSet) : StringPreference(context, attrs) {
    override val oscPreference = OscPreference.HOME_HOSTNAME
    override val preferenceTitle = "Hostname"
}

internal class HomeUsernamePreference(context: Context, attrs: AttributeSet) : StringPreference(context, attrs) {
    override val oscPreference = OscPreference.HOME_USERNAME
    override val preferenceTitle = "Username"
}

internal class PPPStaticIPv4AddressPreference(context: Context, attrs: AttributeSet) : StringPreference(context, attrs) {
    override val oscPreference = OscPreference.PPP_STATIC_IPv4_ADDRESS
    override val preferenceTitle = "Static IPv4 Address"
    override val hint = "192.168.0.1"
    override val dependingPreference = OscPreference.PPP_DO_REQUEST_STATIC_IPv4_ADDRESS
}

internal class ProxyHostnamePreference(context: Context, attrs: AttributeSet) : StringPreference(context, attrs) {
    override val oscPreference = OscPreference.PROXY_HOSTNAME
    override val preferenceTitle = "Proxy Server Hostname"
    override val dependingPreference = OscPreference.PROXY_DO_USE_PROXY
}

internal class ProxyUsernamePreference(context: Context, attrs: AttributeSet) : StringPreference(context, attrs) {
    override val oscPreference = OscPreference.PROXY_USERNAME
    override val preferenceTitle = "Proxy Username (optional)"
    override val dependingPreference = OscPreference.PROXY_DO_USE_PROXY
}

internal class DNSCustomAddressPreference(context: Context, attrs: AttributeSet) : StringPreference(context, attrs) {
    override val oscPreference = OscPreference.DNS_CUSTOM_ADDRESS
    override val preferenceTitle = "Custom DNS Server Address"
    override val dependingPreference = OscPreference.DNS_DO_USE_CUSTOM_SERVER

    override fun onAttached() {
        super.onAttached()

        dialogMessage = "NOTICE: packets associated with this address is routed to the VPN tunnel"
    }
}
