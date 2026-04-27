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
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json


private val EXCLUDED_BOOLEAN_PREFERENCES = arrayOf(
    OscPrefKey.ROOT_STATE,
    OscPrefKey.HOME_CONNECTOR,
    OscPrefKey.HOME_STATUS,
)

private val EXCLUDED_STRING_PREFERENCES = arrayOf(
    OscPrefKey.HOME_STATUS,
)

@Serializable
internal class Config() {
    internal val booleanSetting = mutableMapOf<String, Boolean>()
    internal val intSetting = mutableMapOf<String, Int>()
    internal val stringSetting = mutableMapOf<String, String>()
    internal val setSetting = mutableMapOf<String, Set<String>>()
    internal val uriSetting = mutableMapOf<String, String>()
}

internal fun serializeProfile(prefs: SharedPreferences): String {
    val config = Config()

    DEFAULT_BOOLEAN_MAP.keys.filter { it !in EXCLUDED_BOOLEAN_PREFERENCES }.forEach {
        config.booleanSetting[it.name] = getBooleanPrefValue(it, prefs)
    }

    DEFAULT_INT_MAP.keys.forEach {
        config.intSetting[it.name] = getIntPrefValue(it, prefs)
    }

    DEFAULT_STRING_MAP.keys.filter { it !in EXCLUDED_STRING_PREFERENCES }.forEach {
        config.stringSetting[it.name] = getStringPrefValue(it, prefs)
    }

    DEFAULT_SET_MAP.keys.forEach {
        config.setSetting[it.name] = getSetPrefValue(it, prefs)
    }

    DEFAULT_URI_MAP.keys.forEach {
        getURIPrefValue(it, prefs)?.also { uri ->
            config.uriSetting[it.name] = uri.toString()
        }
    }

    return Json.encodeToString(config)
}

internal fun importProfile(serialized: String?, prefs: SharedPreferences) {
    val config = serialized?.let { Json.decodeFromString<Config>(serialized) }

    DEFAULT_BOOLEAN_MAP.keys.filter { it !in EXCLUDED_BOOLEAN_PREFERENCES }.forEach {
        val value = config?.booleanSetting[it.name] ?: DEFAULT_BOOLEAN_MAP.getValue(it)
        setBooleanPrefValue(value, it, prefs)
    }

    DEFAULT_INT_MAP.keys.forEach {
        val value = config?.intSetting[it.name] ?: DEFAULT_INT_MAP.getValue(it)
        setIntPrefValue(value, it, prefs)
    }

    DEFAULT_STRING_MAP.keys.filter { it !in EXCLUDED_STRING_PREFERENCES }.forEach {
        val value = config?.stringSetting[it.name] ?: DEFAULT_STRING_MAP.getValue(it)
        setStringPrefValue(value, it, prefs)
    }

    DEFAULT_SET_MAP.keys.forEach {
        val value = config?.setSetting[it.name] ?: DEFAULT_SET_MAP.getValue(it)

        setSetPrefValue(value, it, prefs)
    }

    DEFAULT_URI_MAP.keys.forEach {
        val value = config?.uriSetting[it.name]?.toUri() ?: DEFAULT_URI_MAP.getValue(it)
        setURIPrefValue(value, it, prefs)
    }
}

internal fun summarizeProfile(serialized: String): String {
    val config = Json.decodeFromString<Config>(serialized)
    val hostname = config.stringSetting[OscPrefKey.HOME_HOSTNAME.name]
    val username = config.stringSetting[OscPrefKey.HOME_USERNAME.name]
    val portNumber = config.intSetting[OscPrefKey.SSL_PORT.name].toString()

    return "[Hostname]\n$hostname\n\n[Username]\n$username\n\n[Port Number]\n$portNumber"
}
