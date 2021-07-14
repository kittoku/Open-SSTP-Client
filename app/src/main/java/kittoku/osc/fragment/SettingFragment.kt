package kittoku.osc.fragment

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.preference.DropDownPreference
import androidx.preference.MultiSelectListPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import kittoku.osc.R
import javax.net.ssl.SSLContext


private const val CERT_DIR_REQUEST_CODE: Int = 0
private const val LOG_DIR_REQUEST_CODE: Int = 1

private val settingPreferences = arrayOf<PreferenceWrapper<*>>(
    IntPreference.SSL_PORT,
    StrPreference.SSL_VERSION,
    BoolPreference.SSL_DO_VERIFY,
    BoolPreference.SSL_DO_ADD_CERT,
    DirPreference.SSL_CERT_DIR,
    BoolPreference.SSL_DO_SELECT_SUITES,
    SetPreference.SSL_SUITES,
    IntPreference.PPP_MRU,
    IntPreference.PPP_MTU,
    BoolPreference.PPP_PAP_ENABLED,
    BoolPreference.PPP_MSCHAPv2_ENABLED,
    BoolPreference.PPP_IPv4_ENABLED,
    BoolPreference.PPP_IPv6_ENABLED,
    IntPreference.IP_PREFIX,
    BoolPreference.IP_ONLY_LAN,
    BoolPreference.IP_ONLY_ULA,
    BoolPreference.RECONNECTION_ENABLED,
    IntPreference.RECONNECTION_COUNT,
    IntPreference.RECONNECTION_INTERVAL,
    IntPreference.BUFFER_INCOMING,
    IntPreference.BUFFER_OUTGOING,
    BoolPreference.LOG_DO_SAVE_LOG,
    DirPreference.LOG_DIR,
)

internal class SettingFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.settings, rootKey)

        settingPreferences.forEach {
            it.initPreference(this, preferenceManager.sharedPreferences)
        }

        initSSLPreferences()
        setCertDirListener()
        setLogDirListener()
    }

    private fun initSSLPreferences() {
        val params = SSLContext.getDefault().supportedSSLParameters

        findPreference<DropDownPreference>(StrPreference.SSL_VERSION.name)!!.also {
            val versions = arrayOf("DEFAULT") + params.protocols

            it.entries = versions
            it.entryValues = versions
        }

        findPreference<MultiSelectListPreference>(SetPreference.SSL_SUITES.name)!!.also {
            it.entries = params.cipherSuites
            it.entryValues = params.cipherSuites
        }
    }

    private fun setCertDirListener() {
        findPreference<Preference>(DirPreference.SSL_CERT_DIR.name)!!.also {
            it.onPreferenceClickListener = Preference.OnPreferenceClickListener {
                val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
                intent.flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
                startActivityForResult(intent, CERT_DIR_REQUEST_CODE)
                true
            }
        }
    }

    private fun setLogDirListener() {
        findPreference<Preference>(DirPreference.LOG_DIR.name)!!.also {
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

                DirPreference.SSL_CERT_DIR.setValue(this, uri?.toString() ?: "")
            }

            LOG_DIR_REQUEST_CODE -> {
                val uri = if (resultCode == Activity.RESULT_OK) resultData?.data?.also {
                    context?.contentResolver?.takePersistableUriPermission(
                        it, Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                    )
                } else null

                DirPreference.LOG_DIR.setValue(this, uri?.toString() ?: "")
            }
        }
    }
}
