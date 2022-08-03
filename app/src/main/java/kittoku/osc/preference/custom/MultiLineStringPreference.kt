package kittoku.osc.preference.custom

import android.content.Context
import android.text.InputType
import android.util.AttributeSet
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import androidx.preference.Preference.SummaryProvider
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.getStringPrefValue


internal abstract class MultiLineStringPreference(context: Context, attrs: AttributeSet) : EditTextPreference(context, attrs) {
    abstract val oscPreference: OscPreference
    abstract val preferenceTitle: String
    protected open val emptyNotice = "[No Value Entered]"
    protected open val textType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
    protected open val hint: String? = null
    protected open val provider = SummaryProvider<Preference> {
        getStringPrefValue(oscPreference, it.sharedPreferences!!).ifEmpty { emptyNotice }
    }

    override fun onAttached() {
        super.onAttached()

        setOnBindEditTextListener { editText ->
            editText.inputType = textType
            hint?.also {
                editText.hint = it
            }
        }

        // to avoid the issue reported in https://issuetracker.google.com/issues/37032278
        text = getStringPrefValue(oscPreference, sharedPreferences!!).trim()

        title = preferenceTitle
        summaryProvider = provider
    }
}

internal class RouteCustomRoutesPreference(context: Context, attrs: AttributeSet) : MultiLineStringPreference(context, attrs) {
    override val oscPreference = OscPreference.ROUTE_CUSTOM_ROUTES
    override val preferenceTitle = "Edit Custom Routes"
    override val textType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
    override val hint = "192.168.1.0/24\n2001:db8::/32"

    override val provider = SummaryProvider<Preference> {
        val currentValue = getStringPrefValue(oscPreference, it.sharedPreferences!!)

        if (currentValue.isEmpty()) {
            emptyNotice
        } else {
            "[Custom Routes Entered]"
        }
    }

    override fun onAttached() {
        super.onAttached()

        dependency = OscPreference.ROUTE_DO_ADD_CUSTOM_ROUTES.name
    }
}
