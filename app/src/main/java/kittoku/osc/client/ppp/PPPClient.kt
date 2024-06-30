package kittoku.osc.client.ppp

import kittoku.osc.ControlMessage
import kittoku.osc.Result
import kittoku.osc.SharedBridge
import kittoku.osc.Where
import kittoku.osc.unit.ppp.Frame
import kittoku.osc.unit.ppp.LCPCodeReject
import kittoku.osc.unit.ppp.LCPEchoReply
import kittoku.osc.unit.ppp.LCPEchoRequest
import kittoku.osc.unit.ppp.LCPProtocolReject
import kittoku.osc.unit.ppp.LCPTerminalAck
import kittoku.osc.unit.ppp.LCPTerminalRequest
import kittoku.osc.unit.ppp.LcpDiscardRequest
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch


internal class PPPClient(val bridge: SharedBridge) {
    internal val mailbox = Channel<Frame>(Channel.BUFFERED)

    private var jobControl: Job? = null

    internal suspend fun launchJobControl() {
        jobControl = bridge.service.scope.launch(bridge.handler) {
            while (isActive) {
                when (val received = mailbox.receive()) {
                    is LCPEchoRequest -> {
                        LCPEchoReply().also {
                            it.id = received.id
                            it.holder = "Abura Mashi Mashi".toByteArray(Charsets.US_ASCII)
                            bridge.sslTerminal!!.send(it.toByteBuffer())
                        }
                    }

                    is LCPEchoReply -> { }

                    is LcpDiscardRequest -> { }

                    is LCPTerminalRequest -> {
                        LCPTerminalAck().also {
                            it.id = received.id
                            bridge.sslTerminal!!.send(it.toByteBuffer())
                        }

                        bridge.controlMailbox.send(
                            ControlMessage(Where.PPP, Result.ERR_TERMINATE_REQUESTED)
                        )
                    }

                    is LCPProtocolReject -> {
                        bridge.controlMailbox.send(
                            ControlMessage(Where.PPP, Result.ERR_PROTOCOL_REJECTED)
                        )
                    }

                    is LCPCodeReject -> {
                        bridge.controlMailbox.send(
                            ControlMessage(Where.PPP, Result.ERR_CODE_REJECTED)
                        )
                    }

                    else -> {
                        bridge.controlMailbox.send(
                            ControlMessage(Where.PPP, Result.ERR_UNEXPECTED_MESSAGE)
                        )
                    }
                }
            }
        }
    }

    internal fun cancel() {
        jobControl?.cancel()
        mailbox.close()
    }
}
