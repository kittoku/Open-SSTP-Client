package kittoku.osc.preference.custom

import android.content.Context
import android.content.SharedPreferences
import android.util.AttributeSet
import android.widget.TextView
import androidx.preference.Preference
import androidx.preference.PreferenceViewHolder
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getSetPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue


internal abstract class SummaryPreference(context: Context, attrs: AttributeSet) : Preference(context, attrs), OscPreference {
    open val dependencyKey: OscPrefKey? = null

    protected open val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == oscPrefKey.name || key == dependencyKey?.name) {
            updateView()
        }
    }

    override fun onAttached() {
        sharedPreferences!!.registerOnSharedPreferenceChangeListener(listener)

        initialize()
    }

    override fun onDetached() {
        sharedPreferences!!.unregisterOnSharedPreferenceChangeListener(listener)
    }

    override fun onBindViewHolder(holder: PreferenceViewHolder) {
        super.onBindViewHolder(holder)

        holder.findViewById(android.R.id.summary)?.also {
            it as TextView
            it.maxLines = Int.MAX_VALUE
        }
    }
}

internal class HomeStatusPreference(context: Context, attrs: AttributeSet) : SummaryPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.HOME_STATUS
    override val parentKey: OscPrefKey? = null
    override val preferenceTitle = "Current Status"

    override fun updateView() {
        summary = getStringPrefValue(oscPrefKey, sharedPreferences!!).ifEmpty { "[No Connection Established]" }
    }
}

internal class RouteAllowedAppsPreference(context: Context, attrs: AttributeSet) : SummaryPreference(context, attrs) {
    override val dependencyKey = OscPrefKey.ROUTE_DO_INVERT_ALLOWED_APPS
    override val oscPrefKey = OscPrefKey.ROUTE_ALLOWED_APPS
    override val parentKey = OscPrefKey.ROUTE_DO_ENABLE_APP_BASED_RULE
    override val preferenceTitle = "Select Allowed Apps"

    override fun updateView() {
        title = if (getBooleanPrefValue(OscPrefKey.ROUTE_DO_INVERT_ALLOWED_APPS, sharedPreferences!!)) "Select Disallowed Apps" else preferenceTitle
        summary = when (val size = getSetPrefValue(oscPrefKey, sharedPreferences!!).size) {
            0 -> "[No App Selected]"
            1 -> "[1 App Selected]"
            else -> "[$size Apps Selected]"
        }
    }
}
