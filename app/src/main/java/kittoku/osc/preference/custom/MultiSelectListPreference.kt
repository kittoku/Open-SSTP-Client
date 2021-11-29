package kittoku.osc.preference.custom

import android.content.Context
import android.util.AttributeSet
import androidx.preference.MultiSelectListPreference
import androidx.preference.Preference
import androidx.preference.Preference.SummaryProvider
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.getSetPrefValue
import javax.net.ssl.SSLContext


internal abstract class ModifiedMultiSelectListPreference(context: Context, attrs: AttributeSet) : MultiSelectListPreference(context, attrs) {
    abstract val oscPreference: OscPreference
    abstract val preferenceTitle: String
    abstract val values: Array<String>
    protected open val names: Array<String>? = null
    protected open val dependingPreference: OscPreference? = null
    protected open val singularForm = "Value"
    protected open val pluralForm = "Values"

    private val provider = SummaryProvider<Preference> {
        val currentValue = getSetPrefValue(oscPreference, it.sharedPreferences)

        when (currentValue.size) {
            0 -> "[No $singularForm Entered]"
            1 -> "1 $singularForm Selected"
            else -> "${currentValue.size} $pluralForm Selected"
        }
    }

    override fun onAttached() {
        super.onAttached()

        title = preferenceTitle
        dependingPreference?.also {
            dependency = it.name
        }

        summaryProvider = provider
        entryValues = values
        entries = names ?: values
    }
}

internal class SSLSuitesPreference(context: Context, attrs: AttributeSet) : ModifiedMultiSelectListPreference(context, attrs) {
    override val oscPreference = OscPreference.SSL_SUITES
    override val preferenceTitle = "Select Cipher Suites"
    override val values = SSLContext.getDefault().supportedSSLParameters.cipherSuites as Array<String>
    override val dependingPreference = OscPreference.SSL_DO_SELECT_SUITES
    override val singularForm  = "Suite"
    override val pluralForm  = "Suites"
}
