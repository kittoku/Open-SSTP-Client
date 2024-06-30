package kittoku.osc.client.ppp.auth

import kittoku.osc.ControlMessage
import kittoku.osc.Result
import kittoku.osc.SharedBridge
import kittoku.osc.Where
import kittoku.osc.unit.ppp.auth.PAPAuthenticateRequest
import kittoku.osc.unit.ppp.auth.PAPFrame
import kittoku.osc.unit.ppp.auth.PAP_CODE_AUTHENTICATE_ACK
import kittoku.osc.unit.ppp.auth.PAP_CODE_AUTHENTICATE_NAK
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch


internal class PAPClient(private val bridge: SharedBridge) {
    internal val mailbox = Channel<PAPFrame>(Channel.BUFFERED)
    private var jobAuth: Job? = null

    internal fun launchJobAuth() {
        jobAuth = bridge.service.scope.launch(bridge.handler) {
            val currentID = bridge.allocateNewFrameID()

            sendPAPRequest(currentID)

            while (isActive) {
                val received = mailbox.receive()

                if (received.id != currentID) continue

                when (received.code) {
                    PAP_CODE_AUTHENTICATE_ACK -> {
                        bridge.controlMailbox.send(
                            ControlMessage(Where.PAP, Result.PROCEEDED)
                        )
                    }

                    PAP_CODE_AUTHENTICATE_NAK -> {
                        bridge.controlMailbox.send(
                            ControlMessage(Where.PAP, Result.ERR_AUTHENTICATION_FAILED)
                        )
                    }
                }
            }
        }
    }

    private suspend fun sendPAPRequest(id: Byte) {
        PAPAuthenticateRequest().also {
            it.id = id
            it.idFiled = bridge.HOME_USERNAME.toByteArray(Charsets.US_ASCII)
            it.passwordFiled = bridge.HOME_PASSWORD.toByteArray(Charsets.US_ASCII)

            bridge.sslTerminal!!.send(it.toByteBuffer())
        }
    }

    internal fun cancel() {
        jobAuth?.cancel()
        mailbox.close()
    }
}
