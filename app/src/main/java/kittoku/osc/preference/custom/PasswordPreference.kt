package kittoku.osc.preference.custom

import android.content.Context
import android.text.InputType
import android.util.AttributeSet
import androidx.preference.Preference
import androidx.preference.Preference.SummaryProvider
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getStringPrefValue


internal abstract class PasswordPreference(context: Context, attrs: AttributeSet) : OscEditTextPreference(context, attrs) {
    override val inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
    override val provider = SummaryProvider<Preference> {
        val currentValue = getStringPrefValue(oscPrefKey, it.sharedPreferences!!)

        if (currentValue.isEmpty()) {
            "[No Value Entered]"
        } else {
            "[Password Entered]"
        }
    }
}

internal class HomePasswordPreference(context: Context, attrs: AttributeSet) : PasswordPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.HOME_PASSWORD
    override val parentKey: OscPrefKey? = null
    override val preferenceTitle = "Password"
}

internal class ProxyPasswordPreference(context: Context, attrs: AttributeSet) : PasswordPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.PROXY_PASSWORD
    override val parentKey = OscPrefKey.PROXY_DO_USE_PROXY
    override val preferenceTitle = "Proxy Password (optional)"
}
