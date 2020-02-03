package kittoku.opensstpclient.layer

import kittoku.opensstpclient.ControlClient
import kittoku.opensstpclient.misc.*
import kittoku.opensstpclient.negotiator.*
import kittoku.opensstpclient.unit.MessageType
import kittoku.opensstpclient.unit.PPP_HEADER
import kittoku.opensstpclient.unit.PacketType
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.withLock
import kotlin.math.min


internal class SstpClient(parent: ControlClient) : Client(parent) {
    private var waitInterval = 0L

    internal val negotiationTimer = Timer(60_000L)
    internal val negotiationCounter = Counter(3)
    internal val echoTimer = Timer(10_000L)
    internal val echoCounter = Counter(1)

    private suspend fun proceedRequestSent() {
        if (negotiationTimer.isOver) {
            sendCallConnectRequest()
            return
        }

        if (!challengeWholePacket()) return

        if (PacketType.resolve(incomingBuffer.getShort()) != PacketType.CONTROL) {
            parent.informInvalidUnit(::proceedRequestSent)
            status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
            return
        }

        incomingBuffer.move(2)

        when (MessageType.resolve(incomingBuffer.getShort())) {
            MessageType.CALL_CONNECT_ACK -> receiveCallConnectAck()

            MessageType.CALL_CONNECT_NAK -> {
                parent.inform("Received Call Connect Ack", null)
                status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
                return
            }

            MessageType.CALL_DISCONNECT -> {
                parent.informReceivedCallDisconnect(::proceedRequestSent)
                status.sstp = SstpStatus.CALL_DISCONNECT_IN_PROGRESS_2
            }

            MessageType.CALL_ABORT -> {
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

    private suspend fun proceedAckReceived() {
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

        when (PacketType.resolve(incomingBuffer.getShort())) {
            PacketType.DATA ->{
                readAsData()
                return
            }
            null -> {
                parent.informInvalidUnit(::proceedAckReceived)
                status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
                return
            }
        }

        incomingBuffer.move(2)

        when (MessageType.resolve(incomingBuffer.getShort())) {
            MessageType.CALL_DISCONNECT -> {
                parent.informReceivedCallDisconnect(::proceedAckReceived)
                status.sstp = SstpStatus.CALL_DISCONNECT_IN_PROGRESS_2
            }

            MessageType.CALL_ABORT -> {
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

    private suspend fun proceedConnected() {
        if (echoTimer.isOver) {
            sendEchoRequest()
            return
        }

        if (!challengeWholePacket()) return
        echoTimer.reset()
        echoCounter.reset()

        when (PacketType.resolve(incomingBuffer.getShort())) {
            PacketType.DATA ->{
                readAsData()
                return
            }
            null -> {
                parent.informInvalidUnit(::proceedConnected)
                status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
                return
            }
        }

        incomingBuffer.move(2)

        when (MessageType.resolve(incomingBuffer.getShort())) {
            MessageType.CALL_DISCONNECT -> {
                parent.informReceivedCallDisconnect(::proceedConnected)
                status.sstp = SstpStatus.CALL_DISCONNECT_IN_PROGRESS_2
            }

            MessageType.CALL_ABORT -> {
                parent.informReceivedCallAbort(::proceedConnected)
                status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_2
            }

            MessageType.ECHO_REQUEST -> receiveEchoRequest()

            MessageType.ECHO_RESPONSE -> receiveEchoResponse()

            else -> {
                parent.informInvalidUnit(::proceedConnected)
                status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
                return
            }
        }

        incomingBuffer.forget()
    }

    override suspend fun proceed() {
        when (status.sstp) {
            SstpStatus.CLIENT_CALL_DISCONNECTED -> {
                parent.sslTerminal.also {
                    try {
                        it.initializeSocket()
                    } catch (e: Exception) {
                        parent.inform("Failed to establish SSL connection", e)
                        throw SuicideException()
                    }

                    incomingBuffer.socket = it.socket
                    incomingBuffer.sslInput = it.sslInput
                }

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

    private fun sendPacket(length: Int) {
        try {
            parent.sslTerminal.sslOutput.write(outgoingBuffer.array(), 0, length)
        } catch (e: Exception) {
            parent.inform("SSL layer turned down", e)
            throw SuicideException()
        }
    }

    override suspend fun sendControlUnit() {
        outgoingBuffer.clear()

        mutex.withLock {
            waitingControlUnits.removeAt(0).write(outgoingBuffer)
        }

        sendPacket(outgoingBuffer.position())

    }

    override suspend fun sendDataUnit() {
        if (outgoingBuffer.position() == 4) {
            waitInterval = min(waitInterval + 10, 100)
            delay(waitInterval)
            return
        } else {
            waitInterval = 0
        }

        val length = outgoingBuffer.limit()
        outgoingBuffer.position(0)
        outgoingBuffer.putShort(PacketType.DATA.value)
        outgoingBuffer.putShort(length.toShort())

        sendPacket(length)
    }
}
