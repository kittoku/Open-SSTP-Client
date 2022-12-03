package kittoku.osc.fragment

import android.app.Activity
import android.content.SharedPreferences
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import kittoku.osc.R
import kittoku.osc.extension.removeTemporaryPreferences
import kittoku.osc.preference.PROFILE_KEY_HEADER
import kittoku.osc.preference.importProfile
import kittoku.osc.preference.summarizeProfile


internal class ProfilesFragment : PreferenceFragmentCompat() {
    private lateinit var prefs: SharedPreferences
    private var dialogResource = 0

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.blank_preference, rootKey)
        setHasOptionsMenu(true)
        prefs = preferenceManager.sharedPreferences!!
        dialogResource = EditTextPreference(requireContext()).dialogLayoutResource

        retrieveEachProfile()
    }

    private fun retrieveEachProfile() {
        prefs.all.filter { it.key.startsWith(PROFILE_KEY_HEADER) }.forEach { entry ->
            Preference(requireContext()).also {
                it.key = "_" + entry.key
                it.title = entry.key.substringAfter(PROFILE_KEY_HEADER)
                it.onPreferenceClickListener = Preference.OnPreferenceClickListener {
                    showLoadDialog(entry.key)

                    true
                }

                preferenceScreen.addPreference(it)
            }
        }
    }

    private fun showLoadDialog(key: String) {
        val profile = prefs.getString(key, null)!!

        AlertDialog.Builder(requireContext()).also {
            it.setTitle(key.substringAfter(PROFILE_KEY_HEADER))
            it.setMessage(summarizeProfile(profile))

            it.setPositiveButton("LOAD") { _, _ ->
                importProfile(profile, prefs)

                Toast.makeText(requireContext(), "PROFILE LOADED", Toast.LENGTH_SHORT).show()

                requireActivity().setResult(Activity.RESULT_OK)
                requireActivity().finish()
            }

            it.setNegativeButton("CANCEL") { _, _ -> }

            it.setNeutralButton("DELETE") { _, _ ->
                prefs.edit().also { editor ->
                    editor.remove(key)
                    editor.apply()
                }

                preferenceScreen.removePreference(findPreference("_$key")!!)

                Toast.makeText(requireContext(), "PROFILE DELETED", Toast.LENGTH_SHORT).show()
            }

            it.show()
        }
    }

    override fun onDestroy() {
        super.onDestroy()

        prefs.removeTemporaryPreferences()
    }
}
