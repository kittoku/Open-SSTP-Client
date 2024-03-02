package kittoku.osc.preference.custom

import android.content.Context
import android.text.InputType
import android.util.AttributeSet
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import kittoku.osc.preference.DEFAULT_INT_MAP
import kittoku.osc.preference.DEFAULT_STRING_MAP
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getIntPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue


internal interface OscPreference {
    val oscPrefKey: OscPrefKey
    val parentKey: OscPrefKey?
    val preferenceTitle: String
    fun updateView()
}

internal fun <T> T.initialize() where T : Preference, T : OscPreference {
    title = preferenceTitle
    isSingleLineTitle = false

    parentKey?.also { dependency = it.name }

    updateView()
}

internal abstract class OscEditTextPreference(context: Context, attrs: AttributeSet) : EditTextPreference(context, attrs), OscPreference {
    protected open val inputType = InputType.TYPE_CLASS_TEXT
    protected open val hint: String? = null
    protected open val provider: SummaryProvider<out Preference> = SimpleSummaryProvider.getInstance()

    override fun updateView() {
        text = when (oscPrefKey) {
            in DEFAULT_INT_MAP.keys -> getIntPrefValue(oscPrefKey, sharedPreferences!!).toString()
            in DEFAULT_STRING_MAP -> getStringPrefValue(oscPrefKey, sharedPreferences!!)
            else -> throw NotImplementedError(oscPrefKey.name)
        }
    }

    override fun onAttached() {
        setOnBindEditTextListener {
            it.inputType = inputType
            it.hint = hint
            it.setSelection(it.text.length)
        }

        summaryProvider = provider

        initialize()
    }
}
