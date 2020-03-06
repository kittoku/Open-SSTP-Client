package kittoku.opensstpclient.layer

import kittoku.opensstpclient.ControlClient
import kittoku.opensstpclient.MAX_MTU
import kittoku.opensstpclient.misc.*
import kittoku.opensstpclient.negotiator.*
import kittoku.opensstpclient.unit.*
import kotlinx.coroutines.sync.withLock


internal enum class LcpState {
    REQ_SENT, ACK_RCVD, ACK_SENT, OPENED
}

internal enum class IpcpState {
    REQ_SENT, ACK_RCVD, ACK_SENT, OPENED
}

internal class PppClient(parent: ControlClient) : Client(parent) {
    internal var globalIdentifier: Byte = -1
    internal var currentLcpRequestId: Byte = 0
    internal var currentIpcpRequestId: Byte = 0
    internal var currentAuthRequestId: Byte = 0

    internal val lcpTimer = Timer(3_000L)
    internal val lcpCounter = Counter(10)
    internal var lcpState = LcpState.REQ_SENT
    private var isInitialLcp = true

    internal val authTimer = Timer(3_000L)
    internal var isAuthFinished = false
    private var isInitialAuth = true

    internal val ipcpTimer = Timer(3_000L)
    internal val ipcpCounter = Counter(10)
    internal var ipcpState = IpcpState.REQ_SENT
    private var isInitialIpcp = true

    internal val echoTimer = Timer(60_000L)
    internal val echoCounter = Counter(1)

    private val hasIncoming: Boolean
        get() = incomingBuffer.pppLimit > incomingBuffer.position()

    private val canStartPpp: Boolean
        get() {
            if (status.sstp == SstpStatus.CLIENT_CALL_CONNECTED) return true

            if (status.sstp == SstpStatus.CLIENT_CONNECT_ACK_RECEIVED) return true

            return false
        }

    private fun readAsDiscarded() {
        incomingBuffer.position(incomingBuffer.pppLimit)
    }

    private suspend fun proceedLcp() {
        if (lcpTimer.isOver) {
            sendLcpConfigureRequest()
            if (lcpState == LcpState.ACK_RCVD) lcpState = LcpState.REQ_SENT
            return
        }

        if (!hasIncoming) return

        if  (PppProtocol.resolve(incomingBuffer.getShort()) != PppProtocol.LCP) readAsDiscarded()
        else {
            val code = incomingBuffer.getByte()
            when (LcpCode.resolve(code)) {
                LcpCode.CONFIGURE_REQUEST -> receiveLcpConfigureRequest()

                LcpCode.CONFIGURE_ACK -> receiveLcpConfigureAck()

                LcpCode.CONFIGURE_NAK -> receiveLcpConfigureNak()

                LcpCode.CONFIGURE_REJECT -> receiveLcpConfigureReject()

                LcpCode.TERMINATE_REQUEST, LcpCode.CODE_REJECT -> {
                    parent.informInvalidUnit(::proceedLcp)
                    kill()
                    return
                }

                else -> readAsDiscarded()
            }
        }

        incomingBuffer.forget()
    }

    private suspend fun proceedIpcp() {
        if (ipcpTimer.isOver) {
            sendIpcpConfigureRequest()
            if (ipcpState == IpcpState.ACK_RCVD) ipcpState = IpcpState.REQ_SENT
            return
        }

        if (!hasIncoming) return

        if  (PppProtocol.resolve(incomingBuffer.getShort()) != PppProtocol.IPCP) readAsDiscarded()
        else {
            val code = incomingBuffer.getByte()
            when (IpcpCode.resolve(code)) {
                IpcpCode.CONFIGURE_REQUEST -> receiveIpcpConfigureRequest()

                IpcpCode.CONFIGURE_ACK -> receiveIpcpConfigureAck()

                IpcpCode.CONFIGURE_NAK -> receiveIpcpConfigureNak()

                IpcpCode.CONFIGURE_REJECT -> receiveIpcpConfigureReject()

                IpcpCode.TERMINATE_REQUEST, IpcpCode.CODE_REJECT -> {
                    parent.informInvalidUnit(::proceedIpcp)
                    kill()
                    return
                }

                else -> readAsDiscarded()
            }
        }

        incomingBuffer.forget()
    }

    private suspend fun proceedPap() {
        if (authTimer.isOver) {
            parent.informTimerOver(::proceedPap)
            kill()
            return
        }

        if (!hasIncoming) return

        if  (PppProtocol.resolve(incomingBuffer.getShort()) != PppProtocol.PAP) readAsDiscarded()
        else {
            val code = incomingBuffer.getByte()
            when (PapCode.resolve(code)) {
                PapCode.AUTHENTICATE_ACK -> receivePapAuthenticateAck()

                PapCode.AUTHENTICATE_NAK -> receivePapAuthenticateNak()

                else -> readAsDiscarded()
            }
        }

        incomingBuffer.forget()
    }

    private suspend fun proceedChap() {
        if (authTimer.isOver) {
            parent.informTimerOver(::proceedChap)
            kill()
            return
        }

        if (!hasIncoming) return

        if (PppProtocol.resolve(incomingBuffer.getShort()) != PppProtocol.CHAP) readAsDiscarded()
        else {
            val code = incomingBuffer.getByte()
            when (ChapCode.resolve(code)) {
                ChapCode.CHALLENGE -> receiveChapChallenge()

                ChapCode.SUCCESS -> receiveChapSuccess()

                ChapCode.FAILURE -> receiveChapFailure()

                else -> readAsDiscarded()
            }
        }

        incomingBuffer.forget()
    }

    private suspend fun proceedNetwork() {
        if (echoTimer.isOver) sendLcpEchoRequest()

        if (!hasIncoming) return
        else {
            echoTimer.reset()
            echoCounter.reset()
        }

        when (PppProtocol.resolve(incomingBuffer.getShort())) {
            PppProtocol.LCP -> {
                when (LcpCode.resolve(incomingBuffer.getByte())) {
                    LcpCode.ECHO_REQUEST -> receiveLcpEchoRequest()

                    LcpCode.ECHO_REPLY -> receiveLcpEchoReply()

                    else -> {
                        parent.informInvalidUnit(::proceedNetwork)
                        kill()
                        return
                    }
                }
            }

            PppProtocol.CHAP -> {
                val code = incomingBuffer.getByte()
                when (ChapCode.resolve(code)) {
                    ChapCode.CHALLENGE -> receiveChapChallenge()

                    ChapCode.SUCCESS -> receiveChapSuccess()

                    ChapCode.FAILURE -> receiveChapFailure()

                    else -> readAsDiscarded()
                }
            }

            PppProtocol.IP -> incomingBuffer.convey()

            else -> readAsDiscarded()
        }

        incomingBuffer.forget()
    }

    override suspend fun proceed() {
        if (!canStartPpp) return

        when (status.ppp) {
            PppStatus.NEGOTIATE_LCP -> {
                if (isInitialLcp) {
                    sendLcpConfigureRequest()
                    isInitialLcp = false
                }
                else {
                    proceedLcp()
                    if (lcpState == LcpState.OPENED) status.ppp = PppStatus.AUTHENTICATE
                }
            }

            PppStatus.AUTHENTICATE -> {
                when (networkSetting.currentAuth) {
                    AuthSuite.PAP -> {
                        if (isInitialAuth) {
                            sendPapRequest()
                            isInitialAuth = false
                        }
                        else {
                            proceedPap()
                            if (isAuthFinished) status.ppp = PppStatus.NEGOTIATE_IPCP
                        }
                    }

                    AuthSuite.MSCHAPv2 -> {
                        if (isInitialAuth) {
                            networkSetting.chapSetting = ChapSetting()
                            authTimer.reset()
                            isInitialAuth = false
                        } else {
                            proceedChap()
                            if (isAuthFinished) status.ppp = PppStatus.NEGOTIATE_IPCP
                        }
                    }
                }
            }

            PppStatus.NEGOTIATE_IPCP -> {
                if (isInitialIpcp) {
                    sendIpcpConfigureRequest()
                    isInitialIpcp = false
                }
                else {
                    proceedIpcp()
                    if (ipcpState == IpcpState.OPENED) {
                        parent.ipTerminal.also {
                            try {
                                it.initializeTun()
                            } catch (e: Exception) {
                                parent.inform("Failed to create VPN interface", e)
                                kill()
                                return
                            }
                        }

                        status.ppp = PppStatus.NETWORK
                        echoTimer.reset()
                    }
                }
            }

            PppStatus.NETWORK -> proceedNetwork()
        }
    }

    override suspend fun sendControlUnit() {
        outgoingBuffer.clear()
        outgoingBuffer.position(4)

        mutex.withLock {
            waitingControlUnits.removeAt(0).write(outgoingBuffer)
        }

        outgoingBuffer.limit(outgoingBuffer.position())
    }

    override suspend fun sendDataUnit() {
        outgoingBuffer.clear()
        outgoingBuffer.position(4)

        if (status.ppp == PppStatus.NETWORK) {
            parent.ipTerminal.ipInput.also {
                val readLength = it.read(outgoingBuffer.array(), 8, MAX_MTU)
                if (readLength != 0) {
                    outgoingBuffer.putShort(PPP_HEADER)
                    outgoingBuffer.putShort(PppProtocol.IP.value)
                    outgoingBuffer.position(8 + readLength)
                    outgoingBuffer.limit(outgoingBuffer.position())
                }
            }
        }
    }

    internal fun kill() {
        status.sstp = SstpStatus.CALL_DISCONNECT_IN_PROGRESS_1
        parent.inform("PPP layer turned down", null)
    }
}
