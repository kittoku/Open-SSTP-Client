package kittoku.osc.preference

import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import kittoku.osc.preference.accessor.getSetPrefValue


internal data class AppString(val packageName: String, val label: String)

internal fun getInstalledAppInfos(doShowBackgroundApps: Boolean, pm: PackageManager): List<ApplicationInfo> {
    val intent = Intent(Intent.ACTION_MAIN)
    if (!doShowBackgroundApps) {
        intent.addCategory(Intent.CATEGORY_LAUNCHER)
    }

    val addedPackageNames = mutableSetOf<String>()

    return pm.queryIntentActivities(intent, 0).map { it.activityInfo.applicationInfo }.filter {
        if (addedPackageNames.contains(it.packageName)) { // workaround for duplicated 'Google Quick Search Box'
            false
        } else {
            addedPackageNames.add(it.packageName)
            true
        }
    }
}

internal fun getValidSelectedAppInfos(prefs: SharedPreferences, pm: PackageManager): List<ApplicationInfo> {
    // return currently-installed selected apps
    return getSetPrefValue(OscPrefKey.ROUTE_SELECTED_APPS, prefs).mapNotNull {
        try {
            pm.getApplicationInfo(it, 0)
        } catch (_: PackageManager.NameNotFoundException) {
            null
        }
    }
}
