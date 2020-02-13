package kittoku.opensstpclient.misc

import android.content.Intent
import android.support.v4.content.LocalBroadcastManager
import kittoku.opensstpclient.ControlClient
import kittoku.opensstpclient.VpnAction
import kittoku.opensstpclient.unit.DataUnit
import kittoku.opensstpclient.unit.Option
import java.text.SimpleDateFormat
import java.util.*
import kotlin.reflect.KFunction


internal class DataUnitParsingError : Error("Failed to parse data unit")

internal class SuicideException : Exception("Kill this client as intended")

const val EXTENDED_LOG = "kittoku.opensstpclient.LOG"

internal fun ControlClient.inform(message: String, cause: Throwable?) {
    val currentTime = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
    var printing = "[$currentTime] $message"
    cause?.also {
        printing += ":\n"
        val trace = it::class.simpleName + "\n" + it.stackTrace.joinToString("\n")
        printing += trace
    }
    printing += "\n"

    val conveyIntent = Intent(VpnAction.ACTION_CONVEY.value).also {
        it.putExtra(EXTENDED_LOG, printing)
    }

    LocalBroadcastManager.getInstance(vpnService).sendBroadcast(conveyIntent)
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

internal fun ControlClient.informUnableToCompromise(option: Option<*>, where: KFunction<*>) {
    inform("Failed to compromise with ${option::class.simpleName}: ${where.name}", null)
}

internal fun ControlClient.informOptionRejected(option: Option<*>) {
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
