package kittoku.osc.preference.custom

import android.content.Context
import android.util.AttributeSet
import androidx.preference.DropDownPreference
import kittoku.osc.preference.OscPreference
import javax.net.ssl.SSLContext


internal abstract class ModifiedDropDownPreference(context: Context, attrs: AttributeSet) : DropDownPreference(context, attrs) {
    abstract val oscPreference: OscPreference
    abstract val preferenceTitle: String
    abstract val values: Array<String>
    protected open val names: Array<String>? = null

    override fun onAttached() {
        super.onAttached()

        title = preferenceTitle
        summaryProvider = SimpleSummaryProvider.getInstance()
        entryValues = values
        entries = names ?: values
    }
}

internal class SSLVersionPreference(context: Context, attrs: AttributeSet) : ModifiedDropDownPreference(context, attrs) {
    override val oscPreference = OscPreference.SSL_VERSION
    override val preferenceTitle = "SSL Version"
    override val values = arrayOf("DEFAULT") + SSLContext.getDefault().supportedSSLParameters.protocols
}
