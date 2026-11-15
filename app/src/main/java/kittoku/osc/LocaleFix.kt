package kittoku.osc

import android.content.Context
import android.content.res.Configuration
import androidx.preference.PreferenceManager
import java.util.Locale

/**
 * Makes the saved app language (Persian by default) apply from the very first screen,
 * even when the system has not applied the per-app locale yet.
 * If AppCompat already has a locale of its own, that one wins over this wrapper.
 */
object LocaleFix {
    fun language(context: Context): String {
        val saved = PreferenceManager.getDefaultSharedPreferences(context).getString("app_language", "fa")
        return if (saved == "en") "en" else "fa"
    }

    fun wrap(base: Context): Context {
        val locale = Locale(language(base))
        val config = Configuration(base.resources.configuration)
        config.setLocale(locale)
        config.setLayoutDirection(locale)
        return base.createConfigurationContext(config)
    }
}
