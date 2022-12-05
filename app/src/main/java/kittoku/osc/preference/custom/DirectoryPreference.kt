package kittoku.osc.preference.custom

import android.content.Context
import android.util.AttributeSet
import androidx.preference.Preference
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getURIPrefValue


internal abstract class DirectoryPreference(context: Context, attrs: AttributeSet) : Preference(context, attrs), OscPreference {
    override fun updateView() {
        summary = getURIPrefValue(oscPrefKey, sharedPreferences!!)?.path ?: "[No Directory Selected]"
    }

    override fun onAttached() {
        initialize()
    }
}

internal class SSLCertDirPreference(context: Context, attrs: AttributeSet) : DirectoryPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.SSL_CERT_DIR
    override val preferenceTitle = "Select Cipher Suites"
    override val parentKey = OscPrefKey.SSL_DO_ADD_CERT
}

internal class LogDirPreference(context: Context, attrs: AttributeSet) : DirectoryPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.LOG_DIR
    override val preferenceTitle = "Select Log Directory"
    override val parentKey = OscPrefKey.LOG_DO_SAVE_LOG
}
