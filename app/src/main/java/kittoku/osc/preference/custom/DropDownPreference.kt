package kittoku.osc.preference.custom

import android.content.Context
import android.util.AttributeSet
import androidx.preference.DropDownPreference
import kittoku.osc.preference.LIST_TYPE_ALLOWED
import kittoku.osc.preference.LIST_TYPE_DISALLOWED
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getStringPrefValue
import javax.net.ssl.SSLContext


internal abstract class ModifiedDropDownPreference(context: Context, attrs: AttributeSet) : DropDownPreference(context, attrs), OscPreference {
    protected abstract val values: Array<String>
    protected open val names: Array<String>? = null
    override fun updateView() {
        value = getStringPrefValue(oscPrefKey, sharedPreferences!!)
    }

    override fun onAttached() {
        entryValues = values
        entries = names ?: values
        summaryProvider = SimpleSummaryProvider.getInstance()

        initialize()
    }
}

internal class SSLVersionPreference(context: Context, attrs: AttributeSet) : ModifiedDropDownPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.SSL_VERSION
    override val parentKey: OscPrefKey? = null
    override val preferenceTitle = "SSL Version"
    override val values = arrayOf("DEFAULT") + SSLContext.getDefault().supportedSSLParameters.protocols
}

internal class RouteAppListTypePreference(context: Context, attrs: AttributeSet) : ModifiedDropDownPreference(context, attrs) {
    override val oscPrefKey = OscPrefKey.ROUTE_APP_LIST_TYPE
    override val parentKey: OscPrefKey? = null
    override val preferenceTitle = "List Type"
    override val values = arrayOf(LIST_TYPE_ALLOWED, LIST_TYPE_DISALLOWED)
}