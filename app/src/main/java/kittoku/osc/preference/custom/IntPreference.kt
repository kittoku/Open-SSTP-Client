package kittoku.osc.preference.custom

import android.content.Context
import android.text.InputType
import android.util.AttributeSet
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import androidx.preference.Preference.SummaryProvider
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.getIntPrefValue


internal abstract class IntPreference(context: Context, attrs: AttributeSet) : EditTextPreference(context, attrs) {
    abstract val oscPreference: OscPreference
    abstract val preferenceTitle: String
    protected open val dependingPreference: OscPreference? = null
    protected open val provider = SummaryProvider<Preference> {
        getIntPrefValue(oscPreference, it.sharedPreferences).toString()
    }

    private fun initialize() {
        text = getIntPrefValue(oscPreference, sharedPreferences).toString()
    }

    override fun onAttached() {
        super.onAttached()

        initialize()

        title = preferenceTitle
        summaryProvider = provider
        dependingPreference?.also {
            dependency = it.name
        }

        setOnBindEditTextListener { editText ->
            editText.inputType = InputType.TYPE_CLASS_NUMBER
        }
    }
}

internal class SSLPortPreference(context: Context, attrs: AttributeSet) : IntPreference(context, attrs) {
    override val oscPreference = OscPreference.SSL_PORT
    override val preferenceTitle = "Port Number"
}

internal class PPPMruPreference(context: Context, attrs: AttributeSet) : IntPreference(context, attrs) {
    override val oscPreference = OscPreference.PPP_MRU
    override val preferenceTitle = "MRU"
}

internal class PPPMtuPreference(context: Context, attrs: AttributeSet) : IntPreference(context, attrs) {
    override val oscPreference = OscPreference.PPP_MTU
    override val preferenceTitle = "MTU"
}

internal class PPPAuthTimeoutPreference(context: Context, attrs: AttributeSet) : IntPreference(context, attrs) {
    override val oscPreference = OscPreference.PPP_AUTH_TIMEOUT
    override val preferenceTitle = "Timeout Period (second)"
}

internal class IPPrefixPreference(context: Context, attrs: AttributeSet) : IntPreference(context, attrs) {
    override val oscPreference = OscPreference.IP_PREFIX
    override val preferenceTitle = "Address Prefix Length"
    override val provider = SummaryProvider<Preference> {
        getIntPrefValue(oscPreference, it.sharedPreferences).let { length ->
            if (length == 0) "DEFAULT" else length.toString()
        }
    }

    override fun onAttached() {
        super.onAttached()

        dialogMessage = "0 means prefix length will be inferred"
    }
}

internal class ReconnectionCountPreference(context: Context, attrs: AttributeSet) : IntPreference(context, attrs) {
    override val oscPreference = OscPreference.RECONNECTION_COUNT
    override val preferenceTitle = "Retry Count"
    override val dependingPreference = OscPreference.RECONNECTION_ENABLED
}

internal class ReconnectionIntervalPreference(context: Context, attrs: AttributeSet) : IntPreference(context, attrs) {
    override val oscPreference = OscPreference.RECONNECTION_INTERVAL
    override val preferenceTitle = "Retry Interval (second)"
    override val dependingPreference = OscPreference.RECONNECTION_ENABLED
}

internal class BufferIncomingPreference(context: Context, attrs: AttributeSet) : IntPreference(context, attrs) {
    override val oscPreference = OscPreference.BUFFER_INCOMING
    override val preferenceTitle = "Incoming Buffer Size"
}

internal class BufferOutgoingPreference(context: Context, attrs: AttributeSet) : IntPreference(context, attrs) {
    override val oscPreference = OscPreference.BUFFER_OUTGOING
    override val preferenceTitle = "Outgoing Buffer Size"
}
