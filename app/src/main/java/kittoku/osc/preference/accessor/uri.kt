package kittoku.osc.preference.accessor

import android.content.SharedPreferences
import android.net.Uri
import kittoku.osc.preference.OscPreference


internal fun getURIPrefValue(key: OscPreference, prefs: SharedPreferences): Uri? {
    val defaultValue = when (key) {
        OscPreference.SSL_CERT_DIR,
        OscPreference.LOG_DIR -> ""
        else -> throw NotImplementedError()
    }

    return prefs.getString(key.name, defaultValue)!!.toUri()
}

internal fun setURIPrefValue(value: Uri?, key: OscPreference, prefs: SharedPreferences) {
    prefs.edit().also {
        it.putString(key.name, value.toString())
        it.apply()
    }
}

private fun String.toUri(): Uri? {
    return if (this.isEmpty()) {
        null
    } else {
        Uri.parse(this)
    }
}
