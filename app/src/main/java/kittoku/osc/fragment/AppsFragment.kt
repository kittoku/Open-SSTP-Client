package kittoku.osc.fragment

import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import androidx.preference.CheckBoxPreference
import androidx.preference.PreferenceFragmentCompat
import kittoku.osc.R
import kittoku.osc.preference.APP_KEY_HEADER
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.getSetPrefValue
import kittoku.osc.preference.accessor.setSetPrefValue
import kittoku.osc.preference.getInstalledAppInfos


internal class AppsFragment : PreferenceFragmentCompat() {
    private lateinit var prefs: SharedPreferences

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.blank_preference, rootKey)
        setHasOptionsMenu(true)
        prefs = preferenceManager.sharedPreferences!!

        retrieveEachAppPreference(requireContext().applicationContext.packageManager)
    }

    private fun getAppsKeys(): List<String> {
        return prefs.all.keys.filter { it.startsWith(APP_KEY_HEADER) }
    }

    private fun clearEachAppPreference() { // needed for not reserving uninstalled apps' preferences
        prefs.edit().also {
            getAppsKeys().forEach { key ->
                it.remove(key)
            }

            it.apply()
        }
    }

    private fun retrieveEachAppPreference(pm: PackageManager) {
        val allowed = getSetPrefValue(OscPreference.ROUTE_ALLOWED_APPS, prefs)

        getInstalledAppInfos(pm).forEach { info ->
            val checkBox = CheckBoxPreference(requireContext()).also {
                it.key = APP_KEY_HEADER + info.packageName
                it.icon = pm.getApplicationIcon(info)
                it.title = pm.getApplicationLabel(info)
                it.isChecked = allowed.contains(info.packageName)
            }

            preferenceScreen.addPreference(checkBox)
        }
    }

    private fun processCurrentPreferences(f: (CheckBoxPreference) -> Unit) {
        (0 until preferenceScreen.preferenceCount).forEach { i ->
            val pref = preferenceScreen.getPreference(i)
            if (pref is CheckBoxPreference) {
                f(pref)
            }
        }
    }

    private fun changeAllPreferencesStates(newState: Boolean) {
        processCurrentPreferences {
            it.isChecked = newState
        }
    }

    private fun memorizeAllowedApps() {
        val allowed = mutableSetOf<String>()

        // use Checkbox preferences to ensure that only currently-installed apps are memorized
        processCurrentPreferences {
            if (it.isChecked) {
                allowed.add(it.key.substring(APP_KEY_HEADER.length))
            }
        }

        setSetPrefValue(allowed, OscPreference.ROUTE_ALLOWED_APPS, prefs)
    }

    override fun onCreateOptionsMenu(menu: Menu, inflater: MenuInflater) {
        MenuInflater(requireContext()).inflate(R.menu.apps_menu, menu)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.allow_all -> changeAllPreferencesStates(true)
            R.id.disallow_all -> changeAllPreferencesStates(false)
        }

        return true
    }

    override fun onDestroy() {
        super.onDestroy()

        clearEachAppPreference()
        memorizeAllowedApps()
    }
}
