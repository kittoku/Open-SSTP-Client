package kittoku.osc.fragment

import android.app.Activity
import android.content.Intent
import android.content.SharedPreferences
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import kittoku.osc.R
import kittoku.osc.activity.AppsActivity
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.setURIPrefValue
import kittoku.osc.preference.custom.DirectoryPreference
import kittoku.osc.preference.custom.SummaryPreference


internal class SettingFragment : PreferenceFragmentCompat() {
    private lateinit var prefs: SharedPreferences

    private val certDirLauncher = registerForActivityResult(StartActivityForResult()) { result ->
        val uri = if (result.resultCode == Activity.RESULT_OK) result.data?.data?.also {
            requireContext().contentResolver.takePersistableUriPermission(
                it, Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        } else null

        setURIPrefValue(uri, OscPreference.SSL_CERT_DIR, prefs)
    }

    private val logDirLauncher = registerForActivityResult(StartActivityForResult()) { result ->
        val uri = if (result.resultCode == Activity.RESULT_OK) result.data?.data?.also {
            requireContext().contentResolver.takePersistableUriPermission(
                it, Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
        } else null

        setURIPrefValue(uri, OscPreference.LOG_DIR, prefs)
    }

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.settings, rootKey)
        prefs = preferenceManager.sharedPreferences!!

        setCertDirListener()
        setAllowedAppsListener()
        setLogDirListener()
    }

    private fun setCertDirListener() {
        findPreference<DirectoryPreference>(OscPreference.SSL_CERT_DIR.name)!!.also {
            it.onPreferenceClickListener = Preference.OnPreferenceClickListener {
                Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).also { intent ->
                    intent.flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
                    certDirLauncher.launch(intent)
                }

                true
            }
        }
    }

    private fun setAllowedAppsListener() {
        findPreference<SummaryPreference>(OscPreference.ROUTE_ALLOWED_APPS.name)!!.also {
            it.onPreferenceClickListener = Preference.OnPreferenceClickListener {
                startActivity(Intent(requireContext(), AppsActivity::class.java))

                true
            }
        }
    }

    private fun setLogDirListener() {
        findPreference<Preference>(OscPreference.LOG_DIR.name)!!.also {
            it.onPreferenceClickListener = Preference.OnPreferenceClickListener {
                Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).also { intent ->
                    intent.flags = Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                    logDirLauncher.launch(intent)
                }

                true
            }
        }
    }
}
