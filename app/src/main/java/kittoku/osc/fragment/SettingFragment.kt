package kittoku.osc.fragment

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import kittoku.osc.R
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.setURIPrefValue
import kittoku.osc.preference.custom.DirectoryPreference


private const val CERT_DIR_REQUEST_CODE: Int = 0
private const val LOG_DIR_REQUEST_CODE: Int = 1

internal class SettingFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.settings, rootKey)

        setCertDirListener()
        setLogDirListener()
    }

    private fun setCertDirListener() {
        findPreference<DirectoryPreference>(OscPreference.SSL_CERT_DIR.name)!!.also {
            it.onPreferenceClickListener = Preference.OnPreferenceClickListener {
                val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
                intent.flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
                startActivityForResult(intent, CERT_DIR_REQUEST_CODE)
                true
            }
        }
    }

    private fun setLogDirListener() {
        findPreference<Preference>(OscPreference.LOG_DIR.name)!!.also {
            it.onPreferenceClickListener = Preference.OnPreferenceClickListener {
                val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
                intent.flags = Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                startActivityForResult(intent, LOG_DIR_REQUEST_CODE)
                true
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, resultData: Intent?) {
        when (requestCode) {
            CERT_DIR_REQUEST_CODE -> {
                val uri = if (resultCode == Activity.RESULT_OK) resultData?.data?.also {
                    context?.contentResolver?.takePersistableUriPermission(
                        it, Intent.FLAG_GRANT_READ_URI_PERMISSION
                    )
                } else null

                setURIPrefValue(uri, OscPreference.SSL_CERT_DIR, preferenceManager.sharedPreferences)
            }

            LOG_DIR_REQUEST_CODE -> {
                val uri = if (resultCode == Activity.RESULT_OK) resultData?.data?.also {
                    context?.contentResolver?.takePersistableUriPermission(
                        it, Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                    )
                } else null

                setURIPrefValue(uri, OscPreference.LOG_DIR, preferenceManager.sharedPreferences)
            }
        }
    }
}
