package kittoku.osc

import androidx.appcompat.app.AppCompatDelegate

internal object ThemeMode {
    // Only the light look exists now, whatever value an older version saved.
    @Suppress("UNUSED_PARAMETER")
    fun apply(value: String?) {
        AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_NO)
    }
}
