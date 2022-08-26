package kittoku.osc.client.control

import kittoku.osc.client.*
import kittoku.osc.client.incoming.IncomingClient
import kittoku.osc.client.ppp.*
import kittoku.osc.debug.assertAlways
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getIntPrefValue
import kittoku.osc.preference.accessor.resetReconnectionLife
import kittoku.osc.preference.accessor.setIntPrefValue
import kittoku.osc.service.NOTIFICATION_ERROR_ID
import kittoku.osc.service.NOTIFICATION_RECONNECT_ID
import kittoku.osc.terminal.SSL_REQUEST_INTERVAL
import kittoku.osc.unit.ppp.option.AuthOptionMSChapv2
import kittoku.osc.unit.ppp.option.AuthOptionPAP
import kittoku.osc.unit.sstp.SSTP_MESSAGE_TYPE_CALL_ABORT
import kittoku.osc.unit.sstp.SSTP_MESSAGE_TYPE_CALL_DISCONNECT
import kittoku.osc.unit.sstp.SSTP_MESSAGE_TYPE_CALL_DISCONNECT_ACK
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex


internal class ControlClient(internal val bridge: ClientBridge) {
    private var observer: NetworkObserver? = null
    private var logWriter: LogWriter? = null

    private var sstpClient: SstpClient? = null
    private var pppClient: PPPClient? = null
    private var incomingClient: IncomingClient? = null
    private var outgoingClient: OutgoingClient? = null

    private var lcpClient: LCPClient? = null
    private var papClient: PAPClient? = null
    private var chapClient: ChapClient? = null
    private var ipcpClient: IpcpClient? = null
    private var ipv6cpClient: Ipv6cpClient? = null

    private lateinit var jobMain: Job

    private val mutex = Mutex()

    private val isReconnectionEnabled = getBooleanPrefValue(OscPreference.RECONNECTION_ENABLED, bridge.prefs)
    private val isReconnectionAvailable: Boolean
        get() = getIntPrefValue(OscPreference.RECONNECTION_LIFE, bridge.prefs) > 0

    private fun attachHandler() {
        bridge.handler = CoroutineExceptionHandler { _, throwable ->
            kill(isReconnectionEnabled) {
                val header = "OSC: ERR_UNEXPECTED"
                logWriter?.report(header + "\n" + throwable.stackTraceToString())
                bridge.service.makeNotification(NOTIFICATION_ERROR_ID, header)
            }
        }
    }

    internal fun launchJobMain() {
        attachHandler()

        jobMain = bridge.scope.launch(bridge.handler) {
            if (bridge.service.logUri != null) {
                logWriter = LogWriter(bridge)
            }

            logWriter?.report("Establish VPN connection")


            bridge.attachSSLTerminal()
            bridge.sslTerminal!!.initializeSocket()
            if (!expectProceeded(Where.SSL, SSL_REQUEST_INTERVAL)) {
                return@launch
            }


            IncomingClient(bridge).also {
                it.launchJobMain()
                incomingClient = it
            }


            SstpClient(bridge).also {
                sstpClient = it
                incomingClient!!.registerMailbox(it)
                it.launchJobRequest()

                if (!expectProceeded(Where.SSTP_REQUEST, SSTP_REQUEST_TIMEOUT)) {
                    return@launch
                }

                sstpClient!!.launchJobControl()
            }

            PPPClient(bridge).also {
                pppClient = it
                incomingClient!!.registerMailbox(it)
                it.launchJobControl()
            }

            LCPClient(bridge).also {
                incomingClient!!.registerMailbox(it)
                it.launchJobNegotiation()

                if (!expectProceeded(Where.LCP, PPP_NEGOTIATION_TIMEOUT)) {
                    return@launch
                }

                incomingClient!!.unregisterMailbox(it)
            }


            val authTimeout = getIntPrefValue(OscPreference.PPP_AUTH_TIMEOUT, bridge.prefs) * 1000L
            when (bridge.currentAuth) {
                is AuthOptionPAP -> PAPClient(bridge).also {
                    incomingClient!!.registerMailbox(it)
                    it.launchJobAuth()

                    if (!expectProceeded(Where.PAP, authTimeout)) {
                        return@launch
                    }

                    incomingClient!!.unregisterMailbox(it)
                }

                is AuthOptionMSChapv2 -> ChapClient(bridge).also {
                    chapClient = it
                    incomingClient!!.registerMailbox(it)
                    it.launchJobAuth()

                    if (!expectProceeded(Where.CHAP, authTimeout)) {
                        return@launch
                    }
                }

                else -> throw NotImplementedError()
            }


            sstpClient!!.sendCallConnected()


            if (bridge.PPP_IPv4_ENABLED) {
                IpcpClient(bridge).also {
                    incomingClient!!.registerMailbox(it)
                    it.launchJobNegotiation()

                    if (!expectProceeded(Where.IPCP, PPP_NEGOTIATION_TIMEOUT)) {
                        return@launch
                    }

                    incomingClient!!.unregisterMailbox(it)
                }
            }


            if (bridge.PPP_IPv6_ENABLED) {
                Ipv6cpClient(bridge).also {
                    incomingClient!!.registerMailbox(it)
                    it.launchJobNegotiation()

                    if (!expectProceeded(Where.IPV6CP, PPP_NEGOTIATION_TIMEOUT)) {
                        return@launch
                    }

                    incomingClient!!.unregisterMailbox(it)
                }
            }

            OutgoingClient(bridge).also {
                it.launchJobMain()
                outgoingClient = it
            }

            observer = NetworkObserver(bridge)

            if (isReconnectionEnabled) {
                resetReconnectionLife(bridge.prefs)
            }

            expectProceeded(Where.SSTP_CONTROL, null) // wait ERR_ message until disconnection
        }
    }

    private suspend fun expectProceeded(where: Where, timeout: Long?): Boolean {
        val received = if (timeout != null) {
            withTimeoutOrNull(timeout) {
                bridge.controlMailbox.receive()
            } ?: ControlMessage(where, Result.ERR_TIMEOUT)
        } else {
            bridge.controlMailbox.receive()
        }

        if (received.result == Result.PROCEEDED) {
            assertAlways(received.from == where)

            return true
        }

        val lastPacketType = if (received.result == Result.ERR_DISCONNECT_REQUESTED) {
            SSTP_MESSAGE_TYPE_CALL_DISCONNECT_ACK
        } else {
            SSTP_MESSAGE_TYPE_CALL_ABORT
        }

        kill(isReconnectionEnabled) {
            sstpClient?.sendLastPacket(lastPacketType)

            val message = "${received.from.name}: ${received.result.name}"
            logWriter?.report(message)
            bridge.service.makeNotification(NOTIFICATION_ERROR_ID, message)
        }

        return false
    }

    internal fun disconnect() { // use if the user want to normally disconnect
        kill(false) {
            sstpClient?.sendLastPacket(SSTP_MESSAGE_TYPE_CALL_DISCONNECT)
        }
    }

    private suspend fun tryReconnect() {
        getIntPrefValue(OscPreference.RECONNECTION_LIFE, bridge.prefs).also {
            val life = it - 1
            setIntPrefValue(life, OscPreference.RECONNECTION_LIFE, bridge.prefs)

            val message = "Reconnection will be tried (LIFE = $life)"
            bridge.service.makeNotification(NOTIFICATION_RECONNECT_ID, message)
            logWriter?.report(message)
            logWriter?.close()
        }

        delay(getIntPrefValue(OscPreference.RECONNECTION_INTERVAL, bridge.prefs) * 1000L)

        bridge.service.cancelNotification(NOTIFICATION_RECONNECT_ID)
        bridge.service.initializeClient()
    }

    internal fun kill(isReconnectionRequested: Boolean, cleanup: (suspend () -> Unit)?) {
        bridge.scope.launch { // don't suppress exceptions by handler for debugging
            if (!mutex.tryLock()) return@launch // invoked only once
            observer?.close()

            cancelClients()

            cleanup?.invoke()

            closeTerminals()

            if (isReconnectionRequested && isReconnectionAvailable) {
                tryReconnect()
            } else {
                finalize()
            }
        }
    }

    private fun cancelClients() {
        lcpClient?.cancel()
        papClient?.cancel()
        chapClient?.cancel()
        ipcpClient?.cancel()
        ipv6cpClient?.cancel()
        sstpClient?.cancel()
        pppClient?.cancel()
        incomingClient?.cancel()
        outgoingClient?.cancel()
    }

    private fun closeTerminals() {
        bridge.sslTerminal?.close()
        bridge.ipTerminal?.close()
    }

    private suspend fun finalize() {
        logWriter?.report("Terminate VPN connection")
        logWriter?.close()

        bridge.service.stopForeground(true)
        bridge.service.stopSelf()
    }
}
