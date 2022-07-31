package kittoku.osc.preference.custom

import android.content.Context
import android.content.SharedPreferences
import android.net.Uri
import android.util.AttributeSet
import androidx.preference.Preference
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.getStringPrefValue


internal abstract class DirectoryPreference(context: Context, attrs: AttributeSet) : Preference(context, attrs) {
    abstract val oscPreference: OscPreference
    abstract val preferenceTitle: String
    protected open val dependingPreference: OscPreference? = null
    protected open val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == oscPreference.name) {
            updateSummary()
        }
    }

    private val summaryValue: String
        get() {
            val currentValue = getStringPrefValue(oscPreference, sharedPreferences!!)

            return if (currentValue.isEmpty()) {
                "[No Directory Selected]"
            } else {
                Uri.parse(currentValue).path!!
            }
        }

    private fun updateSummary() {
        summary = summaryValue
    }

    override fun onAttached() {
        super.onAttached()

        title = preferenceTitle
        dependingPreference?.also {
            dependency = it.name
        }

        updateSummary()

        sharedPreferences!!.registerOnSharedPreferenceChangeListener(listener)
    }

    override fun onDetached() {
        super.onDetached()

        sharedPreferences!!.unregisterOnSharedPreferenceChangeListener(listener)
    }
}

internal class SSLCertDirPreference(context: Context, attrs: AttributeSet) : DirectoryPreference(context, attrs) {
    override val oscPreference = OscPreference.SSL_CERT_DIR
    override val preferenceTitle = "Select Cipher Suites"
    override val dependingPreference = OscPreference.SSL_DO_ADD_CERT
}

internal class LogDirPreference(context: Context, attrs: AttributeSet) : DirectoryPreference(context, attrs) {
    override val oscPreference = OscPreference.LOG_DIR
    override val preferenceTitle = "Select Log Directory"
    override val dependingPreference = OscPreference.LOG_DO_SAVE_LOG
}
