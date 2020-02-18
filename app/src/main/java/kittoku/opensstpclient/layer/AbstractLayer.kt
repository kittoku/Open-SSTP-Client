package kittoku.opensstpclient.layer

import kittoku.opensstpclient.ControlClient
import kittoku.opensstpclient.unit.DataUnit
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock


internal enum class PppStatus {
    NEGOTIATE_LCP, AUTHENTICATE, NEGOTIATE_IPCP, NETWORK
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
