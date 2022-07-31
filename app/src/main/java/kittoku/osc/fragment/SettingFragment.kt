package kittoku.osc.fragment

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import kittoku.osc.R
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.setURIPrefValue
import kittoku.osc.preference.custom.DirectoryPreference


internal class SettingFragment : PreferenceFragmentCompat() {
    private val certDirExplorer = registerForActivityResult(StartActivityForResult()) { result ->
        val uri = if (result.resultCode == Activity.RESULT_OK) result.data?.data?.also {
            context?.contentResolver?.takePersistableUriPermission(
                it, Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        } else null

        setURIPrefValue(uri, OscPreference.SSL_CERT_DIR, preferenceManager.sharedPreferences!!)
    }

    private val logDirExplorer = registerForActivityResult(StartActivityForResult()) { result ->
        val uri = if (result.resultCode == Activity.RESULT_OK) result.data?.data?.also {
            context?.contentResolver?.takePersistableUriPermission(
                it, Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
        } else null

        setURIPrefValue(uri, OscPreference.LOG_DIR, preferenceManager.sharedPreferences!!)
    }

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.settings, rootKey)

        setCertDirListener()
        setLogDirListener()
    }

    private fun setCertDirListener() {
        findPreference<DirectoryPreference>(OscPreference.SSL_CERT_DIR.name)!!.also {
            it.onPreferenceClickListener = Preference.OnPreferenceClickListener {
                Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).also { intent ->
                    intent.flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
                    certDirExplorer.launch(intent)
                }

                true
            }
        }
    }

    private fun setLogDirListener() {
        findPreference<Preference>(OscPreference.LOG_DIR.name)!!.also {
            it.onPreferenceClickListener = Preference.OnPreferenceClickListener {
                Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).also { intent ->
                    intent.flags = Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                    logDirExplorer.launch(intent)
                }

                true
            }
        }
    }
}
