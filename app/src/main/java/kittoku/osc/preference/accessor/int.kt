package kittoku.osc.preference.accessor

import android.content.SharedPreferences
import kittoku.osc.DEFAULT_MRU
import kittoku.osc.DEFAULT_MTU
import kittoku.osc.preference.OscPreference


internal fun getIntPrefValue(key: OscPreference, prefs: SharedPreferences): Int {
    val defaultValue = when (key) {
        OscPreference.SSL_PORT -> 443
        OscPreference.PPP_MRU -> DEFAULT_MRU
        OscPreference.PPP_MTU -> DEFAULT_MTU
        OscPreference.PPP_AUTH_TIMEOUT -> 3
        OscPreference.RECONNECTION_COUNT -> 3
        OscPreference.RECONNECTION_INTERVAL -> 10
        OscPreference.RECONNECTION_LIFE -> 0
        else -> throw NotImplementedError()
    }

    return prefs.getString(key.name, null)?.toIntOrNull() ?: defaultValue
}

internal fun setIntPrefValue(value: Int, key: OscPreference, prefs: SharedPreferences) {
    prefs.edit().also {
        it.putString(key.name, value.toString())
        it.apply()
    }
}

internal fun resetReconnectionLife(prefs: SharedPreferences) {
    getIntPrefValue(OscPreference.RECONNECTION_COUNT, prefs).also {
        setIntPrefValue(it, OscPreference.RECONNECTION_LIFE, prefs)
    }
}
