package kittoku.opensstpclient

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.preference.PreferenceManager
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.fragment.app.Fragment
import kotlinx.android.synthetic.main.fragment_setting.*

private const val READ_REQUEST_CODE: Int = 42

internal val sslMap = mapOf(
    0 to "DEFAULT",
    1 to "SSLv3",
    2 to "TLSv1",
    3 to "TLSv1.1",
    4 to "TLSv1.2"
)

class SettingFragment : Fragment() {
    private val TAG = "SettingFragment"

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? = inflater.inflate(R.layout.fragment_setting, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        spinnerSsl.adapter = ArrayAdapter<String>(
            context!!,
            android.R.layout.simple_spinner_item,
            sslMap.values.toTypedArray()
        ).also {
            it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        loadPreferences()

        buttonSave.setOnClickListener {
            savePreferences()
            Toast.makeText(context, "The settings have been saved", Toast.LENGTH_SHORT).show()
        }

        buttonCert.setOnClickListener {
            Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).also {
                it.flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
                startActivityForResult(it, READ_REQUEST_CODE)
            }
        }
    }

    private fun loadPreferences() {
        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        editPort.setText(prefs.getString(PreferenceKey.PORT.value, ""))
        editMru.setText(prefs.getString(PreferenceKey.MRU.value, ""))
        editMtu.setText(prefs.getString(PreferenceKey.MTU.value, ""))
        editPrefix.setText(prefs.getString(PreferenceKey.PREFIX.value, ""))
        textCert.text = uriToPath(prefs.getString(PreferenceKey.CERTIFICATE.value, "")!!)
        spinnerSsl.setSelection(prefs.getInt(PreferenceKey.SSL.value, 0))

        checkboxPap.isChecked = prefs.getBoolean(PreferenceKey.PAP.value, true)
        checkboxMschapv2.isChecked = prefs.getBoolean(PreferenceKey.MSCHAPv2.value, true)
        checkboxIpv4.isChecked = prefs.getBoolean(PreferenceKey.IPv4.value, true)
        checkboxIpv6.isChecked = prefs.getBoolean(PreferenceKey.IPv6.value, false)
        checkboxHvIgnored.isChecked = prefs.getBoolean(PreferenceKey.HV_IGNORED.value, false)
        checkboxDecryptable.isChecked = prefs.getBoolean(PreferenceKey.DECRYPTABLE.value, false)
    }

    private fun savePreferences() {
        val editor = PreferenceManager.getDefaultSharedPreferences(context).edit()
        editor.putString(PreferenceKey.PORT.value, editPort.text.toString())
        editor.putString(PreferenceKey.MRU.value, editMru.text.toString())
        editor.putString(PreferenceKey.MTU.value, editMtu.text.toString())
        editor.putString(PreferenceKey.PREFIX.value, editPrefix.text.toString())
        editor.putInt(PreferenceKey.SSL.value, spinnerSsl.selectedItemPosition)

        editor.putBoolean(PreferenceKey.PAP.value, checkboxPap.isChecked)
        editor.putBoolean(PreferenceKey.MSCHAPv2.value, checkboxMschapv2.isChecked)
        editor.putBoolean(PreferenceKey.IPv4.value, checkboxIpv4.isChecked)
        editor.putBoolean(PreferenceKey.IPv6.value, checkboxIpv6.isChecked)
        editor.putBoolean(PreferenceKey.HV_IGNORED.value, checkboxHvIgnored.isChecked)
        editor.putBoolean(PreferenceKey.DECRYPTABLE.value, checkboxDecryptable.isChecked)

        editor.apply()
    }

    private fun uriToPath(uriString: String): String {
        return if (uriString == "") ""
        else Uri.parse(uriString).path!!
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, resultData: Intent?) {
        if (requestCode == READ_REQUEST_CODE) {
            val editor = PreferenceManager.getDefaultSharedPreferences(context).edit()

            val uri = if (resultCode == Activity.RESULT_OK) resultData?.data?.also {
                context?.contentResolver?.takePersistableUriPermission(
                    it,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            } else null

            val uriString = uri?.toString() ?: ""

            editor.putString(PreferenceKey.CERTIFICATE.value, uriString)
            editor.apply()

            textCert.text = uriToPath(uriString)
        }
    }
}
