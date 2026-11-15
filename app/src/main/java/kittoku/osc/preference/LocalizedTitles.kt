package kittoku.osc.preference

import android.content.Context
import kittoku.osc.R

/**
 * Titles of the main-section preferences follow the app language.
 * The Advanced section keeps its technical English titles.
 */
internal fun localizedTitle(context: Context, key: OscPrefKey): String? {
    val id = when (key) {
        OscPrefKey.RECONNECTION_ENABLED -> R.string.bs_pref_reconnection_enabled
        OscPrefKey.RECONNECTION_COUNT -> R.string.bs_pref_reconnection_count
        OscPrefKey.RECONNECTION_INTERVAL -> R.string.bs_pref_reconnection_interval
        OscPrefKey.PROXY_DO_USE_PROXY -> R.string.bs_pref_proxy_use
        OscPrefKey.PROXY_HOSTNAME -> R.string.bs_pref_proxy_host
        OscPrefKey.PROXY_PORT -> R.string.bs_pref_proxy_port
        OscPrefKey.PROXY_USERNAME -> R.string.bs_pref_proxy_user
        OscPrefKey.PROXY_PASSWORD -> R.string.bs_pref_proxy_pass
        OscPrefKey.ROUTE_DO_ENABLE_APP_BASED_RULE -> R.string.bs_pref_app_rule
        OscPrefKey.ROUTE_SELECTED_APPS -> R.string.bs_pref_app_select
        OscPrefKey.ROUTE_DO_SHOW_BACKGROUND_APPS -> R.string.bs_pref_show_bg
        OscPrefKey.ROUTE_APP_LIST_TYPE -> R.string.bs_pref_list_type
        else -> return null
    }

    return context.getString(id)
}
