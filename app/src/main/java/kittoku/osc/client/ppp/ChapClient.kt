package kittoku.osc.client.ppp

import kittoku.osc.cipher.ppp.authenticateChapServerResponse
import kittoku.osc.cipher.ppp.generateChapClientResponse
import kittoku.osc.client.*
import kittoku.osc.unit.ppp.*
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.security.SecureRandom


internal class ChapClient(private val bridge: ClientBridge) {
    internal val mailbox = Channel<ChapFrame>(Channel.BUFFERED)
    private var jobAuth: Job? = null

    private var challengeID: Byte = 0
    private lateinit var chapMessage: ChapMessage

    private var isInitialAuthentication = true

    internal fun launchJobAuth() {
        jobAuth = bridge.service.scope.launch(bridge.handler) {
            while (isActive) {
                val received = mailbox.receive()

                if (received.code == CHAP_CODE_CHALLENGE) {
                    received as ChapChallenge

                    challengeID = received.id
                    chapMessage = ChapMessage()

                    received.value.copyInto(chapMessage.serverChallenge)
                    sendResponse()

                    continue
                }

                if (received.id != challengeID) continue


                when (received.code) {
                    CHAP_CODE_SUCCESS -> {
                        received as ChapSuccess
                        received.response.copyInto(chapMessage.serverResponse)

                        if (authenticateChapServerResponse(bridge.HOME_USERNAME, bridge.HOME_PASSWORD, chapMessage)) {
                            bridge.chapMessage = chapMessage

                            if (isInitialAuthentication) {
                                bridge.controlMailbox.send(
                                    ControlMessage(Where.CHAP, Result.PROCEEDED)
                                )

                                isInitialAuthentication = false
                            }
                        } else {
                            bridge.controlMailbox.send(
                                ControlMessage(Where.CHAP, Result.ERR_VERIFICATION_FAILED)
                            )
                        }
                    }

                    CHAP_CODE_FAILURE -> {
                        bridge.controlMailbox.send(
                            ControlMessage(Where.CHAP, Result.ERR_AUTHENTICATION_FAILED)
                        )
                    }
                }
            }
        }
    }

    private suspend fun sendResponse() {
        SecureRandom().nextBytes(chapMessage.clientChallenge)
        generateChapClientResponse(bridge.HOME_USERNAME, bridge.HOME_PASSWORD, chapMessage)

        ChapResponse().also {
            it.id = challengeID
            chapMessage.clientChallenge.copyInto(it.challenge)
            chapMessage.clientResponse.copyInto(it.response)
            it.name = bridge.HOME_USERNAME.toByteArray(Charsets.US_ASCII)

            bridge.sslTerminal!!.sendDataUnit(it)
        }
    }

    internal fun cancel() {
        jobAuth?.cancel()
        mailbox.close()
    }
}
