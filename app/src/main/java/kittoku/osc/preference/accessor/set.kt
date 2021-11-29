package kittoku.osc.preference.accessor

import android.content.SharedPreferences
import kittoku.osc.preference.OscPreference


internal fun getSetPrefValue(key: OscPreference, prefs: SharedPreferences): Set<String> {
    val defaultValue = when (key) {
        OscPreference.SSL_SUITES -> setOf<String>()
        else -> throw NotImplementedError()
    }

    return prefs.getStringSet(key.name, defaultValue)!!
}

internal fun setSetPrefValue(value: Set<String>, key: OscPreference, prefs: SharedPreferences) {
    prefs.edit().also {
        it.putStringSet(key.name, value)
        it.apply()
    }
}
