package kittoku.opensstpclient.layer

import kittoku.opensstpclient.ControlClient
import kittoku.opensstpclient.INTERVAL_STEP
import kittoku.opensstpclient.MAX_INTERVAL
import kittoku.opensstpclient.unit.DataUnit
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.math.min


internal enum class PppStatus {
    NEGOTIATE_LCP, AUTHENTICATE, NEGOTIATE_IPCP, NETWORK, KILLED
}

internal enum class SstpStatus {
    CALL_ABORT_IN_PROGRESS_1,
    CALL_ABORT_IN_PROGRESS_2,
    CALL_DISCONNECT_IN_PROGRESS_1,
    CALL_DISCONNECT_IN_PROGRESS_2,
    CLIENT_CALL_DISCONNECTED,
    CLIENT_CONNECT_REQUEST_SENT,
    CLIENT_CONNECT_ACK_RECEIVED,
    CLIENT_CALL_CONNECTED
}

internal class DualClientStatus {
    internal var ppp = PppStatus.NEGOTIATE_LCP
    internal var sstp = SstpStatus.CLIENT_CALL_DISCONNECTED
}

internal class Counter(private val maxCount: Int) {
    private var currentCount = maxCount

    internal val isExhausted: Boolean
        get() = currentCount <= 0

    internal fun consume() {
        currentCount--
    }

    internal fun reset() {
        currentCount = maxCount
    }
}

internal class Timer(private val maxLength: Long) {
    private var startedTime = System.currentTimeMillis()

    internal val isOver: Boolean
        get() = (System.currentTimeMillis() - startedTime) > maxLength

    internal fun reset() {
        startedTime = System.currentTimeMillis()
    }
}
internal class Waiter {
    private var incoming = 0
    private var outgoing = 0L
    private val maxLong = MAX_INTERVAL.toLong()
    private val stepLong = INTERVAL_STEP.toLong()

    internal fun getIncomingInterval(): Int {
        incoming = min(incoming + INTERVAL_STEP, MAX_INTERVAL)
        return incoming
    }

    internal fun getOutgoingInterval(): Long {
        outgoing = min(outgoing + stepLong, maxLong)
        return outgoing
    }

    internal fun resetIncoming() {
        incoming = 0
    }

    internal fun resetOutgoing() {
        outgoing = 0
    }
}


internal abstract class Client(internal val parent: ControlClient) {
    internal val waitingControlUnits = mutableListOf<DataUnit<*>>()
    internal val mutex = Mutex()
    internal val status = parent.status
    internal val incomingBuffer = parent.incomingBuffer
    internal val outgoingBuffer = parent.outgoingBuffer
    internal val networkSetting = parent.networkSetting

    internal abstract suspend fun proceed() // just check its state or timers, not bytes

    internal abstract suspend fun sendDataUnit()

    internal abstract suspend fun sendControlUnit()

    internal suspend fun addControlUnit(unit: DataUnit<*>) {
        mutex.withLock { waitingControlUnits.add(unit) }
    }
}

internal abstract class Terminal(protected val parent: ControlClient) {
    internal abstract fun release()
}
