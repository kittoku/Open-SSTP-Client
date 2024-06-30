package kittoku.osc.client.ppp.auth

import kittoku.osc.SharedBridge
import kittoku.osc.unit.ppp.auth.ChapChallenge
import kittoku.osc.unit.ppp.auth.ChapFrame
import kittoku.osc.unit.ppp.auth.ChapMessageFrame
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch


internal abstract class ChapClient(protected val bridge: SharedBridge) {
    internal val mailbox = Channel<ChapFrame>(Channel.BUFFERED)
    protected var challengeID: Byte = 0
    private var jobAuth: Job? = null

    internal fun launchJobAuth() {
        jobAuth = bridge.service.scope.launch(bridge.handler) {
            while (isActive) {
                when(val received = mailbox.receive()) {
                    is ChapChallenge -> {
                        challengeID = received.id

                        responseChallenge(received)
                    }

                    is ChapMessageFrame -> {
                        if (received.id == challengeID) {
                            processResult(received)
                        }
                    }
                }
            }
        }
    }

    protected abstract suspend fun responseChallenge(challenge: ChapChallenge)

    protected abstract suspend fun processResult(result: ChapMessageFrame)

    internal fun cancel() {
        jobAuth?.cancel()
        mailbox.close()
    }
}
