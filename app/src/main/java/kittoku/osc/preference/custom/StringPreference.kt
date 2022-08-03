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
    protected open val emptyNotice = "[No Value Entered]"
    protected open val textType = InputType.TYPE_CLASS_TEXT
    protected open val provider = SummaryProvider<Preference> {
        getStringPrefValue(oscPreference, it.sharedPreferences!!).ifEmpty { emptyNotice }
    }

    override fun onAttached() {
        super.onAttached()

        setOnBindEditTextListener { editText ->
            editText.inputType = textType
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

internal class HomePasswordPreference(context: Context, attrs: AttributeSet) : StringPreference(context, attrs) {
    override val oscPreference = OscPreference.HOME_PASSWORD
    override val preferenceTitle = "Password"
    override val textType = super.textType or InputType.TYPE_TEXT_VARIATION_PASSWORD

    override val provider = SummaryProvider<Preference> {
        val currentValue = getStringPrefValue(oscPreference, it.sharedPreferences!!)

        if (currentValue.isEmpty()) {
            emptyNotice
        } else {
            "[Password Entered]"
        }
    }
}

internal class DNSCustomAddressPreference(context: Context, attrs: AttributeSet) : StringPreference(context, attrs) {
    override val oscPreference = OscPreference.DNS_CUSTOM_ADDRESS
    override val preferenceTitle = "Custom DNS server address (IPv4 only)"

    override fun onAttached() {
        super.onAttached()

        dependency = OscPreference.DNS_DO_USE_CUSTOM_SERVER.name
        dialogMessage = "NOTICE: packet to and from this address will be routed"
    }
}
