package kittoku.osc.preference.custom

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.AttributeSet
import android.widget.TextView
import androidx.preference.Preference
import androidx.preference.PreferenceViewHolder
import kittoku.osc.preference.OscPreference


internal abstract class LinkPreference(context: Context, attrs: AttributeSet) : Preference(context, attrs) {
    abstract val oscPreference: OscPreference
    abstract val preferenceTitle: String
    abstract val preferenceSummary: String
    abstract val url: String

    override fun onAttached() {
        super.onAttached()

        title = preferenceTitle
        summary = preferenceSummary
        intent = Intent(Intent.ACTION_VIEW).also { it.data = Uri.parse(url) }
    }

    override fun onBindViewHolder(holder: PreferenceViewHolder?) {
        super.onBindViewHolder(holder)

        holder?.findViewById(android.R.id.summary)?.also {
            it as TextView
            it.maxLines = Int.MAX_VALUE
        }
    }
}

internal class LinkOscPreference(context: Context, attrs: AttributeSet) : LinkPreference(context, attrs) {
    override val oscPreference = OscPreference.LINK_OSC
    override val preferenceTitle = "Move to this app's project page"
    override val preferenceSummary = "github.com/kittoku/Open-SSTP-Client"
    override val url = "https://github.com/kittoku/Open-SSTP-Client"
}
