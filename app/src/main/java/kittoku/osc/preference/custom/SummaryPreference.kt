package kittoku.osc.preference.custom

import android.content.Context
import android.content.SharedPreferences
import android.util.AttributeSet
import android.widget.TextView
import androidx.preference.Preference
import androidx.preference.PreferenceViewHolder
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.getSetPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue


internal abstract class SummaryPreference(context: Context, attrs: AttributeSet) : Preference(context, attrs) {
    abstract val oscPreference: OscPreference
    abstract val preferenceTitle: String
    protected open val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == oscPreference.name) {
            updateSummary()
        }
    }

    protected open val summaryValue: String
        get() = getStringPrefValue(oscPreference, sharedPreferences!!)

    private fun updateSummary() {
        summary = summaryValue
    }

    override fun onAttached() {
        super.onAttached()

        title = preferenceTitle
        updateSummary()

        sharedPreferences!!.registerOnSharedPreferenceChangeListener(listener)
    }

    override fun onDetached() {
        super.onDetached()

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
    override val oscPreference = OscPreference.HOME_STATUS
    override val preferenceTitle = "Current Status"
    override val summaryValue: String
        get() {
            val status = getStringPrefValue(oscPreference, sharedPreferences!!)

            return status.ifEmpty {
                "[No Connection Established]"
            }
        }
}

internal class RouteAllowedAppsPreference(context: Context, attrs: AttributeSet) : SummaryPreference(context, attrs) {
    override val oscPreference = OscPreference.ROUTE_ALLOWED_APPS
    override val preferenceTitle = "Select Allowed Apps"
    override val summaryValue: String
        get() {
            return when (val size = getSetPrefValue(oscPreference, sharedPreferences!!).size) {
                0 -> "[No App Selected]"
                1 -> "[1 App Selected]"
                else -> "[$size Apps Selected]"
            }
        }

    override fun onAttached() {
        super.onAttached()

        dependency = OscPreference.ROUTE_DO_ENABLE_APP_BASED_RULE.name
    }
}
