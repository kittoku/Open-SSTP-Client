package kittoku.osc.layer

import kittoku.osc.ControlClient
import kittoku.osc.misc.*
import kittoku.osc.negotiator.*
import kittoku.osc.unit.*


internal enum class LcpState {
    REQ_SENT, ACK_RCVD, ACK_SENT, OPENED
}

internal enum class IpcpState {
    REQ_SENT, ACK_RCVD, ACK_SENT, OPENED
}

internal enum class Ipv6cpState {
    REQ_SENT, ACK_RCVD, ACK_SENT, OPENED
}

internal class PppClient(parent: ControlClient) : Client(parent) {
    internal var globalIdentifier: Byte = -1
    internal var currentLcpRequestId: Byte = 0
    internal var currentIpcpRequestId: Byte = 0
    internal var currentIpv6cpRequestId: Byte = 0
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

    internal val ipv6cpTimer = Timer(3_000L)
    internal val ipv6cpCounter = Counter(10)
    internal var ipv6cpState = Ipv6cpState.REQ_SENT
    private var isInitialIpv6cp = true

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

    private fun proceedLcp() {
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

    private fun proceedPap() {
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

    private fun proceedChap() {
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

    private fun proceedIpcp() {
        if (ipcpTimer.isOver) {
            sendIpcpConfigureRequest()
            if (ipcpState == IpcpState.ACK_RCVD) ipcpState = IpcpState.REQ_SENT
            return
        }

        if (!hasIncoming) return

        when (PppProtocol.resolve(incomingBuffer.getShort())) {
            PppProtocol.LCP -> {
                if (LcpCode.resolve(incomingBuffer.getByte()) == LcpCode.PROTOCOL_REJECT) {
                    receiveLcpProtocolReject(PppProtocol.IPCP)
                } else readAsDiscarded()
            }

            PppProtocol.IPCP -> {
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

            else -> readAsDiscarded()
        }

        incomingBuffer.forget()
    }

    private fun proceedIpv6cp() {
        if (ipv6cpTimer.isOver) {
            sendIpv6cpConfigureRequest()
            if (ipv6cpState == Ipv6cpState.ACK_RCVD) ipv6cpState = Ipv6cpState.REQ_SENT
            return
        }

        if (!hasIncoming) return

        when (PppProtocol.resolve(incomingBuffer.getShort())) {
            PppProtocol.LCP -> {
                if (LcpCode.resolve(incomingBuffer.getByte()) == LcpCode.PROTOCOL_REJECT) {
                    receiveLcpProtocolReject(PppProtocol.IPV6CP)
                }
            }

            PppProtocol.IPV6CP -> {
                val code = incomingBuffer.getByte()
                when (Ipv6cpCode.resolve(code)) {
                    Ipv6cpCode.CONFIGURE_REQUEST -> receiveIpv6cpConfigureRequest()

                    Ipv6cpCode.CONFIGURE_ACK -> receiveIpv6cpConfigureAck()

                    Ipv6cpCode.CONFIGURE_NAK -> receiveIpv6cpConfigureNak()

                    Ipv6cpCode.CONFIGURE_REJECT -> receiveIpv6cpConfigureReject()

                    Ipv6cpCode.TERMINATE_REQUEST, Ipv6cpCode.CODE_REJECT -> {
                        parent.informInvalidUnit(::proceedIpv6cp)
                        kill()
                        return
                    }

                    else -> readAsDiscarded()
                }
            }

            else -> readAsDiscarded()
        }

        incomingBuffer.forget()
    }

    private fun proceedNetwork() {
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

            PppProtocol.IP, PppProtocol.IPV6 -> incomingBuffer.convey()

            else -> readAsDiscarded()
        }

        incomingBuffer.forget()
    }

    override fun proceed() {
        if (!canStartPpp) return

        when (status.ppp) {
            PppStatus.NEGOTIATE_LCP -> {
                if (isInitialLcp) {
                    sendLcpConfigureRequest()
                    isInitialLcp = false
                }

                proceedLcp()
                if (lcpState == LcpState.OPENED) status.ppp = PppStatus.AUTHENTICATE
            }

            PppStatus.AUTHENTICATE -> {
                when (networkSetting.currentAuth) {
                    AuthSuite.PAP -> {
                        if (isInitialAuth) {
                            sendPapRequest()
                            isInitialAuth = false
                        }

                        proceedPap()
                        if (isAuthFinished) {
                            status.ppp = if (networkSetting.PPP_IPv4_ENABLED) {
                                PppStatus.NEGOTIATE_IPCP
                            } else {
                                PppStatus.NEGOTIATE_IPV6CP
                            }
                        }
                    }

                    AuthSuite.MSCHAPv2 -> {
                        if (isInitialAuth) {
                            networkSetting.chapSetting = ChapSetting()
                            authTimer.reset()
                            isInitialAuth = false
                        }

                        proceedChap()
                        if (isAuthFinished) {
                            status.ppp = if (networkSetting.PPP_IPv4_ENABLED) {
                                PppStatus.NEGOTIATE_IPCP
                            } else {
                                PppStatus.NEGOTIATE_IPV6CP
                            }
                        }
                    }
                }
            }

            PppStatus.NEGOTIATE_IPCP -> {
                if (isInitialIpcp) {
                    sendIpcpConfigureRequest()
                    isInitialIpcp = false
                }

                proceedIpcp()
                if (ipcpState == IpcpState.OPENED) {
                    if (networkSetting.PPP_IPv6_ENABLED) {
                        status.ppp = PppStatus.NEGOTIATE_IPV6CP
                    } else startNetworking()
                }
            }

            PppStatus.NEGOTIATE_IPV6CP -> {
                if (isInitialIpv6cp) {
                    sendIpv6cpConfigureRequest()
                    isInitialIpv6cp = false
                }

                proceedIpv6cp()
                if (ipv6cpState == Ipv6cpState.OPENED) startNetworking()
            }

            PppStatus.NETWORK -> proceedNetwork()
        }
    }

    private fun startNetworking() {
        parent.attachNetworkObserver()

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
        parent.reconnectionSettings.resetCount()
        parent.launchJobData()
        echoTimer.reset()
    }

    internal fun kill() {
        status.sstp = SstpStatus.CALL_DISCONNECT_IN_PROGRESS_1
        parent.inform("PPP layer turned down", null)
    }
}
