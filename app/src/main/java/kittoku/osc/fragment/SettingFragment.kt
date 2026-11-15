package kittoku.osc.fragment

import android.app.Activity
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import androidx.preference.ListPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import kittoku.osc.R
import kittoku.osc.activity.BLANK_ACTIVITY_TYPE_APPS
import kittoku.osc.activity.BlankActivity
import kittoku.osc.activity.EXTRA_KEY_TYPE
import kittoku.osc.ThemeMode
import kittoku.osc.activity.showAboutDialog
import kittoku.osc.activity.showLogDialog
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.setURIPrefValue
import kittoku.osc.preference.custom.DirectoryPreference
import kittoku.osc.preference.custom.RouteSelectedAppsPreference

internal class SettingFragment : PreferenceFragmentCompat() {
    private lateinit var prefs: SharedPreferences
    private lateinit var certDirPref: DirectoryPreference
    private lateinit var logDirPref: DirectoryPreference
    private lateinit var selectAppsPref: RouteSelectedAppsPreference

    private val certDirLauncher = registerForActivityResult(StartActivityForResult()) { result ->
        val uri = if (result.resultCode == Activity.RESULT_OK) result.data?.data?.also {
            requireContext().contentResolver.takePersistableUriPermission(
                it,
                Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        } else null

        setURIPrefValue(uri, OscPrefKey.SSL_CERT_DIR, prefs)
        certDirPref.updateView()
    }

    private val logDirLauncher = registerForActivityResult(StartActivityForResult()) { result ->
        val uri = if (result.resultCode == Activity.RESULT_OK) result.data?.data?.also {
            requireContext().contentResolver.takePersistableUriPermission(
                it,
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
        } else null

        setURIPrefValue(uri, OscPrefKey.LOG_DIR, prefs)
        logDirPref.updateView()
    }

    private val selectAppsLauncher = registerForActivityResult(StartActivityForResult()) {
        selectAppsPref.updateView()
    }

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.settings, rootKey)

        prefs = preferenceManager.sharedPreferences!!

        certDirPref = findPreference(OscPrefKey.SSL_CERT_DIR.name)!!
        logDirPref = findPreference(OscPrefKey.LOG_DIR.name)!!
        selectAppsPref = findPreference(OscPrefKey.ROUTE_SELECTED_APPS.name)!!

        setCertDirListener()
        setLogDirListener()
        setSelectAppsListener()
        setAboutListener()
        setTelegramListener()
        setLogListener()
        setThemeListener()
        setLanguageListener()
        setAdvancedToggle()
    }

    private fun setLanguageListener() {
        val pref = findPreference<ListPreference>("LANGUAGE") ?: return
        val saved = preferenceManager.sharedPreferences?.getString("app_language", "fa") ?: "fa"
        pref.value = if (saved == "en") "en" else "fa"

        pref.onPreferenceChangeListener = Preference.OnPreferenceChangeListener { _, newValue ->
            val tag = if ((newValue as? String) == "en") "en" else "fa"
            preferenceManager.sharedPreferences?.edit()?.putString("app_language", tag)?.apply()
            AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(tag))

            true
        }
    }

    private val advancedKeys = listOf(
        "ADV_SSL", "ADV_PPP", "ADV_PPP_AUTH", "ADV_PPP_NET", "ADV_DNS", "ADV_ROUTING", "ADV_LOG"
    )

    private fun setAdvancedToggle() {
        val toggle = findPreference<Preference>("ADVANCED_TOGGLE") ?: return
        var expanded = false

        fun apply() {
            advancedKeys.forEach { findPreference<Preference>(it)?.isVisible = expanded }
            toggle.setIcon(if (expanded) R.drawable.ic_expand_less else R.drawable.ic_expand_more)
        }

        apply()

        toggle.onPreferenceClickListener = Preference.OnPreferenceClickListener {
            expanded = !expanded
            apply()

            true
        }
    }

    private fun setCertDirListener() {
        certDirPref.onPreferenceClickListener = Preference.OnPreferenceClickListener {
            Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).also {
                it.flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
                certDirLauncher.launch(it)
            }

            true
        }
    }

    private fun setLogDirListener() {
        logDirPref.onPreferenceClickListener = Preference.OnPreferenceClickListener {
            Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).also {
                it.flags = Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                logDirLauncher.launch(it)
            }

            true
        }
    }

    private fun setSelectAppsListener() {
        selectAppsPref.onPreferenceClickListener = Preference.OnPreferenceClickListener {
            Intent(requireContext(), BlankActivity::class.java).also {
                it.putExtra(EXTRA_KEY_TYPE, BLANK_ACTIVITY_TYPE_APPS)
                selectAppsLauncher.launch(it)
            }

            true
        }
    }

    private fun setAboutListener() {
        findPreference<Preference>("ABOUT_BANAFSH")?.onPreferenceClickListener =
            Preference.OnPreferenceClickListener {
                (activity as? AppCompatActivity)?.let { showAboutDialog(it) }

                true
            }
    }

    private fun setTelegramListener() {
        findPreference<Preference>("TELEGRAM_CHANNEL")?.onPreferenceClickListener =
            Preference.OnPreferenceClickListener {
                try {
                    startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/Banafsh_sstp")))
                } catch (e: Exception) {
                    // no app can open the link
                }

                true
            }
    }

    private fun setLogListener() {
        findPreference<Preference>("CONNECTION_LOG")?.onPreferenceClickListener =
            Preference.OnPreferenceClickListener {
                (activity as? AppCompatActivity)?.let { showLogDialog(it) }

                true
            }
    }

    private fun setThemeListener() {
        findPreference<ListPreference>("THEME_MODE")?.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { _, newValue ->
                ThemeMode.apply(newValue as? String)

                true
            }
    }
}
