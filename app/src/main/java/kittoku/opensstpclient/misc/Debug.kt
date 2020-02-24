package kittoku.opensstpclient.misc

import android.content.Intent
import android.preference.PreferenceManager
import android.support.v4.content.LocalBroadcastManager
import kittoku.opensstpclient.ControlClient
import kittoku.opensstpclient.PreferenceKey
import kittoku.opensstpclient.VpnAction
import kittoku.opensstpclient.unit.DataUnit
import java.text.SimpleDateFormat
import java.util.*
import kotlin.reflect.KFunction


internal class DataUnitParsingError : Error("Failed to parse data unit")

internal class SuicideException : Exception("Kill this client as intended")

internal fun ControlClient.inform(message: String, cause: Throwable?) {
    val currentTime = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
    var printing = "[$currentTime] $message"
    cause?.also {
        printing += ":\n"
        val trace =
            it::class.simpleName + "\n" + it.message + "\n" + it.stackTrace.joinToString("\n")
        printing += trace
    }
    printing += "\n"

    PreferenceManager.getDefaultSharedPreferences(vpnService.applicationContext).also {
        val new = it.getString(PreferenceKey.LOG.value, "") as String + printing
        it.edit().putString(PreferenceKey.LOG.value, new).apply()
    }

    LocalBroadcastManager.getInstance(vpnService.applicationContext)
        .sendBroadcast(Intent(VpnAction.ACTION_UPDATE.value))
}


internal fun ControlClient.informDataUnitParsingError(unit: DataUnit<*>, cause: DataUnitParsingError) {
    inform("Failed to parse ${unit::class.simpleName}", cause)
}

internal fun ControlClient.informTimerOver(where: KFunction<*>) {
    inform("The timer was over: ${where.name}", null)
}

internal fun ControlClient.informCounterExhausted(where: KFunction<*>) {
    inform("The counter was exhausted: ${where.name}", null)
}

internal fun ControlClient.informOptionRejected(option: DataUnit<*>) {
    inform("${option::class.simpleName} was rejected", null)
}

internal fun ControlClient.informInvalidUnit(where: KFunction<*>) {
    inform("Received an invalid unit: ${where.name}", null)
}

internal fun ControlClient.informAuthenticationFailed(where: KFunction<*>) {
    inform("Failed to be authenticated: ${where.name}", null)
}

internal fun ControlClient.informReceivedCallDisconnect(where: KFunction<*>) {
    inform("Received a Call Disconnect: ${where.name}", null)
}

internal fun ControlClient.informReceivedCallAbort(where: KFunction<*>) {
    inform("Received a Call Abort: ${where.name}", null)
}
