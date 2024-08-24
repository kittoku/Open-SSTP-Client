package kittoku.osc.fragment

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.preference.PreferenceFragmentCompat
import kittoku.osc.R
import kittoku.osc.activity.EXTRA_KEY_CERT
import kittoku.osc.activity.EXTRA_KEY_FILENAME
import java.io.BufferedOutputStream


internal class SaveCertFragment(private val givenIntent: Intent) : PreferenceFragmentCompat() {
    private val launcher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) result.data?.data?.also { uri ->
            BufferedOutputStream(requireContext().contentResolver.openOutputStream(uri, "w")).also {
                it.write(givenIntent.getByteArrayExtra(EXTRA_KEY_CERT))
                it.flush()
                it.close()
            }
        }

        requireActivity().finish()
    }

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.blank_preference, rootKey)

        Intent(Intent.ACTION_CREATE_DOCUMENT).also {
            it.addCategory(Intent.CATEGORY_OPENABLE)
            it.setType("application/x-x509-ca-cert")
            it.putExtra(Intent.EXTRA_TITLE, givenIntent.getStringExtra(EXTRA_KEY_FILENAME))

            launcher.launch(it)
        }
    }
}
