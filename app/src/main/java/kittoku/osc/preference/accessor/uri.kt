package kittoku.osc.preference.accessor

import android.content.SharedPreferences
import android.net.Uri
import kittoku.osc.extension.toUri
import kittoku.osc.preference.DEFAULT_URI_MAP
import kittoku.osc.preference.OscPrefKey


internal fun getURIPrefValue(key: OscPrefKey, prefs: SharedPreferences): Uri? {
    return prefs.getString(key.name, null)?.toUri() ?: DEFAULT_URI_MAP[key]
}

internal fun setURIPrefValue(value: Uri?, key: OscPrefKey, prefs: SharedPreferences) {
    prefs.edit().also {
        it.putString(key.name, value?.toString() ?: "")
        it.apply()
    }
}
