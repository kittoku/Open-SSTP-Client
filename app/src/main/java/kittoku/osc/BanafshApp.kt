package kittoku.osc

import android.app.Application
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat

class BanafshApp : Application() {
    override fun onCreate() {
        super.onCreate()

        // The app has one look: light.
        androidx.appcompat.app.AppCompatDelegate.setDefaultNightMode(androidx.appcompat.app.AppCompatDelegate.MODE_NIGHT_NO)

        // The L2TP service reports its state to the bridge, which keeps the home screen in step.
        L2tpBridge.init(this)

        // Persian is the default language until the user picks another one.
        // The locale is set only when it differs, so a restart does not trigger a pointless reload.
        val language = LocaleFix.language(this)
        if (AppCompatDelegate.getApplicationLocales().toLanguageTags() != language) {
            AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(language))
        }
    }
}
