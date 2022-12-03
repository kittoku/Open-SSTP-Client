package kittoku.osc.preference.accessor

import android.content.SharedPreferences
import kittoku.osc.preference.DEFAULT_STRING_MAP
import kittoku.osc.preference.OscPrefKey


internal fun getStringPrefValue(key: OscPrefKey, prefs: SharedPreferences): String {
    return prefs.getString(key.name, DEFAULT_STRING_MAP[key]!!)!!
}

internal fun setStringPrefValue(value: String, key: OscPrefKey, prefs: SharedPreferences) {
    prefs.edit().also {
        it.putString(key.name, value)
        it.apply()
    }
}
