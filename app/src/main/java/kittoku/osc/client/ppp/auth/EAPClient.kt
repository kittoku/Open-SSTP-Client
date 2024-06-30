package kittoku.osc.client.ppp.auth

import kittoku.osc.ControlMessage
import kittoku.osc.Result
import kittoku.osc.SharedBridge
import kittoku.osc.Where
import kittoku.osc.unit.ppp.auth.EAPFailure
import kittoku.osc.unit.ppp.auth.EAPFrame
import kittoku.osc.unit.ppp.auth.EAPRequest
import kittoku.osc.unit.ppp.auth.EAPResponse
import kittoku.osc.unit.ppp.auth.EAPResultFrame
import kittoku.osc.unit.ppp.auth.EAPSuccess
import kittoku.osc.unit.ppp.auth.EAP_TYPE_IDENTITY
import kittoku.osc.unit.ppp.auth.EAP_TYPE_NAK
import kittoku.osc.unit.ppp.auth.EAP_TYPE_NOTIFICATION
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch


internal abstract class EAPClient(protected val bridge: SharedBridge) {
    protected abstract val algorithm: Byte
    internal val mailbox = Channel<EAPFrame>(Channel.BUFFERED)
    protected var isResultAcceptable = false
    private var jobAuth: Job? = null

    internal fun launchJobAuth() {
        jobAuth = bridge.service.scope.launch(bridge.handler) {
            while (isActive) {
                when (val received = mailbox.receive()) {
                    is EAPRequest -> {
                        when (received.type) {
                            EAP_TYPE_IDENTITY -> sendIdentity(received)

                            EAP_TYPE_NOTIFICATION, EAP_TYPE_NAK -> {}

                            algorithm -> responseRequest(received)

                            else -> sendNak(received)
                        }
                    }

                    is EAPResultFrame -> {
                        if (isResultAcceptable) {
                            when (received) {
                                is EAPSuccess -> {
                                    bridge.controlMailbox.send(
                                        ControlMessage(Where.EAP, Result.PROCEEDED)
                                    )
                                }

                                is EAPFailure -> {
                                    bridge.controlMailbox.send(
                                        ControlMessage(Where.EAP, Result.ERR_AUTHENTICATION_FAILED)
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private suspend fun sendIdentity(serverIdentity: EAPRequest) {
        EAPResponse().also {
            it.id = serverIdentity.id
            it.type = EAP_TYPE_IDENTITY
            it.typeData = bridge.HOME_USERNAME.toByteArray(Charsets.US_ASCII)

            bridge.sslTerminal!!.send(it.toByteBuffer())
        }
    }

    private suspend fun sendNak(serverRequest: EAPRequest) {
        EAPResponse().also {
            it.id = serverRequest.id
            it.type = EAP_TYPE_NAK
            it.typeData = ByteArray(1) { algorithm }

            bridge.sslTerminal!!.send(it.toByteBuffer())
        }
    }

    protected abstract suspend fun responseRequest(request: EAPRequest)

    internal fun cancel() {
        jobAuth?.cancel()
        mailbox.close()
    }
}
