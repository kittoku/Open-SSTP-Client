package kittoku.osc.preference

import android.content.SharedPreferences
import kittoku.osc.extension.toUri
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getIntPrefValue
import kittoku.osc.preference.accessor.getSetPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue
import kittoku.osc.preference.accessor.getURIPrefValue
import kittoku.osc.preference.accessor.setBooleanPrefValue
import kittoku.osc.preference.accessor.setIntPrefValue
import kittoku.osc.preference.accessor.setSetPrefValue
import kittoku.osc.preference.accessor.setStringPrefValue
import kittoku.osc.preference.accessor.setURIPrefValue


private const val RECORD_SEPARATOR = 0x1E.toChar().toString()
private const val UNIT_SEPARATOR = 0x1F.toChar().toString()

private val EXCLUDED_BOOLEAN_PREFERENCES = arrayOf(
    OscPrefKey.ROOT_STATE,
    OscPrefKey.HOME_CONNECTOR,
    OscPrefKey.HOME_STATUS,
)

private val EXCLUDED_STRING_PREFERENCES = arrayOf(
    OscPrefKey.HOME_STATUS,
)


internal fun exportProfile(prefs: SharedPreferences): String {
    var profile = ""

    DEFAULT_BOOLEAN_MAP.keys.filter { it !in EXCLUDED_BOOLEAN_PREFERENCES }.forEach {
        profile += it.name + UNIT_SEPARATOR + getBooleanPrefValue(it, prefs).toString() + RECORD_SEPARATOR
    }

    DEFAULT_INT_MAP.keys.forEach {
        profile += it.name + UNIT_SEPARATOR + getIntPrefValue(it, prefs).toString() + RECORD_SEPARATOR
    }

    DEFAULT_STRING_MAP.keys.filter { it !in EXCLUDED_STRING_PREFERENCES }.forEach {
        profile += it.name + UNIT_SEPARATOR + getStringPrefValue(it, prefs) + RECORD_SEPARATOR
    }

    DEFAULT_SET_MAP.keys.forEach {
        profile += it.name + UNIT_SEPARATOR + getSetPrefValue(it, prefs).joinToString(UNIT_SEPARATOR) + RECORD_SEPARATOR
    }

    DEFAULT_URI_MAP.keys.forEach {
        getURIPrefValue(it, prefs)?.also { uri ->
            profile += it.name + UNIT_SEPARATOR + uri.toString() + RECORD_SEPARATOR
        }
    }

    return profile
}

internal fun importProfile(profile: String?, prefs: SharedPreferences) {
    val profileMap = profile?.split(RECORD_SEPARATOR)?.filter { it.isNotEmpty() }?.associate {
        val index = it.indexOf(UNIT_SEPARATOR)
        val key = it.substring(0, index)
        val value = it.substring(index + 1)

        key to value
    } ?: mapOf()

    DEFAULT_BOOLEAN_MAP.keys.filter { it !in EXCLUDED_BOOLEAN_PREFERENCES }.forEach {
        val value = profileMap[it.name]?.toBooleanStrict() ?: DEFAULT_BOOLEAN_MAP.getValue(it)
        setBooleanPrefValue(value, it, prefs)
    }

    DEFAULT_INT_MAP.keys.forEach {
        val value = profileMap[it.name]?.toInt() ?: DEFAULT_INT_MAP.getValue(it)
        setIntPrefValue(value, it, prefs)
    }

    DEFAULT_STRING_MAP.keys.filter { it !in EXCLUDED_STRING_PREFERENCES }.forEach {
        val value = profileMap[it.name] ?: DEFAULT_STRING_MAP.getValue(it)
        setStringPrefValue(value, it, prefs)
    }

    DEFAULT_SET_MAP.keys.forEach { key ->
        val value = profileMap[key.name]?.split(UNIT_SEPARATOR)?.filter { it.isNotEmpty() }?.toSet() ?: DEFAULT_SET_MAP.getValue(key)

        setSetPrefValue(value, key, prefs)
    }

    DEFAULT_URI_MAP.keys.forEach {
        val value = profileMap[it.name]?.toUri() ?: DEFAULT_URI_MAP.getValue(it)
        setURIPrefValue(value, it, prefs)
    }
}

internal fun summarizeProfile(profile: String): String {
    var hostname: String = DEFAULT_STRING_MAP.getValue(OscPrefKey.HOME_HOSTNAME)
    var username: String = DEFAULT_STRING_MAP.getValue(OscPrefKey.HOME_USERNAME)
    var portNumber: String = DEFAULT_INT_MAP.getValue(OscPrefKey.SSL_PORT).toString()

    profile.split(RECORD_SEPARATOR).filter { it.isNotEmpty() }.forEach {
        val index = it.indexOf(UNIT_SEPARATOR)
        val key = it.substring(0, index)
        val value = it.substring(index + 1)

        when (key) {
            OscPrefKey.HOME_HOSTNAME.name -> {
                hostname = value
            }

            OscPrefKey.HOME_USERNAME.name -> {
                username = value
            }

            OscPrefKey.SSL_PORT.name -> {
                portNumber = value
            }
        }
    }

    return "[Hostname]\n$hostname\n\n[Username]\n$username\n\n[Port Number]\n$portNumber"
}
