package kittoku.opensstpclient.fragment

import android.content.SharedPreferences
import android.net.Uri
import android.text.InputType
import android.text.TextUtils
import androidx.preference.*
import kittoku.opensstpclient.DEFAULT_MRU
import kittoku.opensstpclient.DEFAULT_MTU


internal const val TYPE_PASSWORD =
    InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD

internal interface PreferenceWrapper<T> {
    val name: String

    val defaultValue: T

    fun getValue(prefs: SharedPreferences): T

    fun setValue(
        fragment: PreferenceFragmentCompat,
        value: T
    ) // Use Preference to ensure its summary is updated.

    fun initValue(fragment: PreferenceFragmentCompat, prefs: SharedPreferences) {
        if (!prefs.contains(name)) {
            setValue(fragment, defaultValue)
        }
    }

    fun initPreference(fragment: PreferenceFragmentCompat, prefs: SharedPreferences)

    fun restoreDefault(fragment: PreferenceFragmentCompat) {
        setValue(fragment, defaultValue)
    }
}

private fun EditTextPreference.setInputType(type: Int) {
    setOnBindEditTextListener { editText ->
        editText.inputType = type
    }
}

internal enum class StrPreference(override val defaultValue: String) : PreferenceWrapper<String> {
    HOME_HOST(""),
    HOME_USER(""),
    HOME_PASS(""),
    SSL_VERSION("DEFAULT");

    override fun getValue(prefs: SharedPreferences): String {
        return prefs.getString(name, defaultValue)!!
    }

    override fun setValue(fragment: PreferenceFragmentCompat, value: String) {
        if (this == SSL_VERSION) {
            fragment.findPreference<DropDownPreference>(name)!!.also {
                it.value = value
            }
        } else {
            fragment.findPreference<EditTextPreference>(name)!!.also {
                it.text = value
            }
        }
    }

    override fun initPreference(fragment: PreferenceFragmentCompat, prefs: SharedPreferences) {
        if (this == SSL_VERSION) {
            fragment.findPreference<DropDownPreference>(name)!!.also {
                it.summaryProvider = ListPreference.SimpleSummaryProvider.getInstance()
                initValue(fragment, prefs)
            }
        } else {
            fragment.findPreference<EditTextPreference>(name)!!.also {
                if (this == HOME_PASS) {
                    it.summaryProvider = passwordSummaryProvider
                    it.setInputType(TYPE_PASSWORD)
                } else {
                    it.summaryProvider = normalSummaryProvider
                    it.setInputType(InputType.TYPE_CLASS_TEXT)
                }

                initValue(fragment, prefs)
            }
        }
    }
}

internal enum class DirPreference(override val defaultValue: String) : PreferenceWrapper<String> {
    SSL_CERT_DIR(""),
    LOG_DIR("");

    override fun getValue(prefs: SharedPreferences): String {
        return prefs.getString(name, defaultValue)!!
    }

    override fun setValue(fragment: PreferenceFragmentCompat, value: String) {
        fragment.findPreference<Preference>(name)!!.also {
            it.sharedPreferences.edit().also { editor ->
                editor.putString(name, value)
                editor.apply()
            }

            it.provideSummary(value)
        }
    }

    override fun initPreference(fragment: PreferenceFragmentCompat, prefs: SharedPreferences) {
        fragment.findPreference<Preference>(name)!!.also {
            it.provideSummary(getValue(it.sharedPreferences))
            initValue(fragment, prefs)
        }
    }

    private fun Preference.provideSummary(uri: String) {
        summary = if (TextUtils.isEmpty(uri)) {
            "[No Directory Selected]"
        } else {
            Uri.parse(uri).path
        }
    }
}

internal enum class BoolPreference(override val defaultValue: Boolean) :
    PreferenceWrapper<Boolean> {
    HOME_CONNECTOR(false),
    SSL_DO_VERIFY(true),
    SSL_DO_DECRYPT(false),
    SSL_DO_ADD_CERT(false),
    PPP_PAP_ENABLED(true),
    PPP_MSCHAPv2_ENABLED(true),
    PPP_IPv4_ENABLED(true),
    PPP_IPv6_ENABLED(false),
    IP_ONLY_LAN(false),
    IP_ONLY_ULA(false),
    LOG_DO_SAVE_LOG(false);

    override fun getValue(prefs: SharedPreferences): Boolean {
        return prefs.getBoolean(name, defaultValue)
    }

    override fun setValue(fragment: PreferenceFragmentCompat, value: Boolean) {
        fragment.findPreference<TwoStatePreference>(name)!!.also {
            it.isChecked = value
        }
    }

    override fun initPreference(fragment: PreferenceFragmentCompat, prefs: SharedPreferences) {
        fragment.findPreference<TwoStatePreference>(name)!!.also {
            initValue(fragment, prefs)
        }
    }
}

internal enum class IntPreference(override val defaultValue: Int) : PreferenceWrapper<Int> {
    SSL_PORT(443),
    PPP_MRU(DEFAULT_MRU),
    PPP_MTU(DEFAULT_MTU),
    IP_PREFIX(0);

    override fun getValue(prefs: SharedPreferences): Int {
        return prefs.getString(name, defaultValue.toString())!!.toIntOrNull() ?: defaultValue
    }

    override fun setValue(fragment: PreferenceFragmentCompat, value: Int) {
        fragment.findPreference<EditTextPreference>(name)!!.also {
            it.text = value.toString()
        }
    }

    override fun initPreference(fragment: PreferenceFragmentCompat, prefs: SharedPreferences) {
        fragment.findPreference<EditTextPreference>(name)!!.also {
            it.summaryProvider = if (this == IP_PREFIX) {
                it.dialogMessage = "0 means prefix length will be inferred"
                zeroDefaultSummaryProvider
            } else {
                numSummaryProvider
            }

            it.setInputType(InputType.TYPE_CLASS_NUMBER)
            initValue(fragment, prefs)
        }
    }
}
