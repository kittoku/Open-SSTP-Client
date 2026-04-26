package kittoku.osc.fragment

import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import androidx.preference.CheckBoxPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import kittoku.osc.R
import kittoku.osc.extension.removeTemporaryPreferences
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.TEMP_KEY_HEADER
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getSetPrefValue
import kittoku.osc.preference.accessor.setSetPrefValue
import kittoku.osc.preference.custom.RouteDoShowBackgroundAppsPreference
import kittoku.osc.preference.getInstalledAppInfos


internal class AppsFragment : PreferenceFragmentCompat() {
    private lateinit var prefs: SharedPreferences
    private lateinit var pm: PackageManager
    private val shownCheckBoxes = mutableSetOf<CheckBoxPreference>()

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.apps, rootKey)
        setHasOptionsMenu(true)
        prefs = preferenceManager.sharedPreferences!!
        pm = requireContext().applicationContext.packageManager

        updateEachAppPreference(getBooleanPrefValue(OscPrefKey.ROUTE_DO_SHOW_BACKGROUND_APPS, prefs))
        attachSwitchListener()
    }

    private fun updateEachAppPreference(doShowBackgroundApps: Boolean) {
        shownCheckBoxes.removeAll {
            preferenceScreen.removePreference(it)
            true
        }

        val selected = getSetPrefValue(OscPrefKey.ROUTE_SELECTED_APPS, prefs)

        getInstalledAppInfos(doShowBackgroundApps, pm).forEach { info ->
            val checkBox = CheckBoxPreference(requireContext()).also {
                it.key = TEMP_KEY_HEADER + info.packageName
                it.icon = pm.getApplicationIcon(info)
                it.title = pm.getApplicationLabel(info)
                it.isChecked = selected.contains(info.packageName)
            }

            shownCheckBoxes.add(checkBox)
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

    private fun memorizeSelectedApps() {
        val selected = mutableSetOf<String>()

        // use Checkbox preferences to ensure that only currently-installed apps are memorized
        processCurrentPreferences {
            if (it.isChecked) {
                selected.add(it.key.substring(TEMP_KEY_HEADER.length))
            }
        }

        setSetPrefValue(selected, OscPrefKey.ROUTE_SELECTED_APPS, prefs)
    }

    override fun onCreateOptionsMenu(menu: Menu, inflater: MenuInflater) {
        MenuInflater(requireContext()).inflate(R.menu.apps_menu, menu)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.select_all -> changeAllPreferencesStates(true)
            R.id.unselect_all -> changeAllPreferencesStates(false)
        }

        return true
    }

    private fun attachSwitchListener() {
        findPreference<RouteDoShowBackgroundAppsPreference>(OscPrefKey.ROUTE_DO_SHOW_BACKGROUND_APPS.name)!!.also {
            it.onPreferenceChangeListener = Preference.OnPreferenceChangeListener { _, newState ->
                updateEachAppPreference(newState as Boolean)

                true
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()

        memorizeSelectedApps()
        prefs.removeTemporaryPreferences()
    }
}
