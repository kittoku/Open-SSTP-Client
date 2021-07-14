package kittoku.osc.layer

import kittoku.osc.ControlClient


internal enum class PppStatus {
    NEGOTIATE_LCP, AUTHENTICATE, NEGOTIATE_IPCP, NEGOTIATE_IPV6CP, NETWORK
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
    internal val status = parent.status
    internal val incomingBuffer = parent.incomingBuffer
    internal val networkSetting = parent.networkSetting

    internal abstract fun proceed() // just check its state or timers, not bytes
}

internal abstract class Terminal(protected val parent: ControlClient) {
    internal abstract fun release()
}
