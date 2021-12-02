package kittoku.osc.layer

import kittoku.osc.ControlClient
import kittoku.osc.misc.*
import kittoku.osc.negotiator.*
import kittoku.osc.unit.*


internal class SstpClient(parent: ControlClient) : Client(parent) {
    internal val negotiationTimer = Timer(60_000L)
    internal val negotiationCounter = Counter(3)
    internal val echoTimer = Timer(10_000L)
    internal val echoCounter = Counter(1)

    private fun proceedRequestSent() {
        if (negotiationTimer.isOver) {
            sendCallConnectRequest()
            return
        }

        if (!challengeWholePacket()) return

        if (incomingBuffer.getShort() != SSTP_PACKET_TYPE_CONTROL) {
            parent.informInvalidUnit(::proceedRequestSent)
            status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
            return
        }

        incomingBuffer.move(2)

        when (incomingBuffer.getShort()) {
            SSTP_MESSAGE_TYPE_CALL_CONNECT_ACK -> receiveCallConnectAck()

            SSTP_MESSAGE_TYPE_CALL_CONNECT_NAK -> {
                parent.inform("Received Call Connect Nak", null)
                status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
                return
            }

            SSTP_MESSAGE_TYPE_CALL_DISCONNECT -> {
                parent.informReceivedCallDisconnect(::proceedRequestSent)
                status.sstp = SstpStatus.CALL_DISCONNECT_IN_PROGRESS_2
            }

            SSTP_MESSAGE_TYPE_CALL_ABORT -> {
                parent.informReceivedCallAbort(::proceedRequestSent)
                status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_2
            }

            else -> {
                status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
                return
            }
        }

        incomingBuffer.forget()
    }

    private fun proceedAckReceived() {
        if (negotiationTimer.isOver) {
            parent.informTimerOver(::proceedAckReceived)
            status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
            return
        }

        if (status.ppp == PppStatus.NEGOTIATE_IPCP || status.ppp == PppStatus.NETWORK) {
            sendCallConnected()
            status.sstp = SstpStatus.CLIENT_CALL_CONNECTED
            echoTimer.reset()
            return
        }

        if (!challengeWholePacket()) return

        when (incomingBuffer.getShort()) {
            SSTP_PACKET_TYPE_DATA -> readAsData()

            SSTP_PACKET_TYPE_CONTROL -> {
                incomingBuffer.move(2)

                when (incomingBuffer.getShort()) {
                    SSTP_MESSAGE_TYPE_CALL_DISCONNECT -> {
                        parent.informReceivedCallDisconnect(::proceedAckReceived)
                        status.sstp = SstpStatus.CALL_DISCONNECT_IN_PROGRESS_2
                    }

                    SSTP_MESSAGE_TYPE_CALL_ABORT -> {
                        parent.informReceivedCallAbort(::proceedAckReceived)
                        status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_2
                    }

                    else -> {
                        parent.informInvalidUnit(::proceedAckReceived)
                        status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
                        return
                    }
                }

                incomingBuffer.forget()
            }

            else -> {
                parent.informInvalidUnit(::proceedAckReceived)
                status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
            }
        }
    }

    private fun proceedConnected() {
        if (echoTimer.isOver) {
            sendEchoRequest()
            return
        }

        if (!challengeWholePacket()) return
        echoTimer.reset()
        echoCounter.reset()

        when (incomingBuffer.getShort()) {
            SSTP_PACKET_TYPE_DATA-> readAsData()

            SSTP_PACKET_TYPE_CONTROL -> {
                incomingBuffer.move(2)

                when (incomingBuffer.getShort()) {
                    SSTP_MESSAGE_TYPE_CALL_DISCONNECT -> {
                        parent.informReceivedCallDisconnect(::proceedConnected)
                        status.sstp = SstpStatus.CALL_DISCONNECT_IN_PROGRESS_2
                    }

                    SSTP_MESSAGE_TYPE_CALL_ABORT -> {
                        parent.informReceivedCallAbort(::proceedConnected)
                        status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_2
                    }

                    SSTP_MESSAGE_TYPE_ECHO_REQUEST -> receiveEchoRequest()

                    SSTP_MESSAGE_TYPE_ECHO_RESPONSE -> receiveEchoResponse()

                    else -> {
                        parent.informInvalidUnit(::proceedConnected)
                        status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
                        return
                    }
                }

                incomingBuffer.forget()
            }

            else -> {
                parent.informInvalidUnit(::proceedConnected)
                status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
            }
        }
    }

    override fun proceed() {
        when (status.sstp) {
            SstpStatus.CLIENT_CALL_DISCONNECTED -> {
                parent.sslTerminal.initializeSocket()
                sendCallConnectRequest()
                status.sstp = SstpStatus.CLIENT_CONNECT_REQUEST_SENT
            }

            SstpStatus.CLIENT_CONNECT_REQUEST_SENT -> proceedRequestSent()

            SstpStatus.CLIENT_CONNECT_ACK_RECEIVED -> proceedAckReceived()

            SstpStatus.CLIENT_CALL_CONNECTED -> proceedConnected()

            else -> sendLastGreeting()
        }
    }

    private fun readAsData() {
        incomingBuffer.pppLimit = incomingBuffer.getShort().toInt() + incomingBuffer.position() - 4

        if (incomingBuffer.getShort() != PPP_HEADER) {
            parent.inform("Received a non-PPP payload", null)
            status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
        }
    }
}
