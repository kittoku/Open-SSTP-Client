package kittoku.osc.preference.custom

import android.content.Context
import android.content.SharedPreferences
import android.util.AttributeSet
import android.widget.TextView
import androidx.preference.Preference
import androidx.preference.PreferenceViewHolder
import kittoku.osc.preference.LIST_TYPE_ALLOWED
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getSetPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue


internal abstract class SummaryPreference(context: Context, attrs: AttributeSet) : Preference(context, attrs), OscPreference {
    protected open val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == oscPrefKey.name) {
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

internal class RouteSelectedAppsPreference(context: Context, attrs: AttributeSet) : SummaryPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.ROUTE_SELECTED_APPS
    override val parentKey = OscPrefKey.ROUTE_DO_ENABLE_APP_BASED_RULE
    override val preferenceTitle = "Select Allowed/Disallowed Apps"

    override fun updateView() {
        val isAllowedList = getStringPrefValue(OscPrefKey.ROUTE_APP_LIST_TYPE, sharedPreferences!!) == LIST_TYPE_ALLOWED
        val verb = if (isAllowedList) "Allowed" else "Disallowed"

        summary = when (val size = getSetPrefValue(oscPrefKey, sharedPreferences!!).size) {
            0 -> "[No App $verb]"
            1 -> "[1 App $verb]"
            else -> "[$size Apps $verb]"
        }
    }
}
