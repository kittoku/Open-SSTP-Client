package kittoku.opensstpclient.packet

import kittoku.opensstpclient.BUFFER_SIZE_PPP
import kittoku.opensstpclient.ECHO_TIME_PPP
import kittoku.opensstpclient.REQUEST_MRU_SIZE
import kittoku.opensstpclient.misc.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.net.InetAddress
import java.security.SecureRandom


internal class PppClient(lowerBridge: LayerBridge, higherBridge: LayerBridge,
                         networkSetting: NetworkSetting, status: DualClientStatus)
    : AbstractClient(lowerBridge, higherBridge, networkSetting, status, BUFFER_SIZE_PPP) {
    private val readUnitFromSstp = lowerBridge::readUnitFromLower
    private val readUnitFromIp = higherBridge::readUnitFromHigher
    private val writeUnitToSstp = lowerBridge::writeUnitToLower
    private val writeUnitToIp = higherBridge::writeUnitToHigher
    private val magicNumber: Int = SecureRandom().nextInt()
    private var globalIdentifier: Byte = -1
    private var lastReceicedTime: Long = 0L

    private suspend fun cueIncoming(): PppProtocol? {
        incomingBuffer.clear()
        readUnitFromSstp(incomingBuffer)

        return when(incomingBuffer.getShort(2)) {
            PppProtocol.IP.value -> PppProtocol.IP
            PppProtocol.LCP.value -> PppProtocol.LCP
            PppProtocol.PAP.value -> PppProtocol.PAP
            PppProtocol.IPCP.value -> PppProtocol.IPCP
            else -> null
            }
    }

    override fun runOutgoing() {
         launch {
            outgoingBuffer.clear()
            outgoingBuffer.putShort(0xFF03.toShort())
            outgoingBuffer.putShort(PppProtocol.IP.value)

            while (true) {
                outgoingBuffer.position(4)
                readUnitFromIp(outgoingBuffer)
                outgoingBuffer.rewind()
                writeUnitToSstp(outgoingBuffer)
            }
        }
    }

    private fun readAsControlFrame(frame: ControlFrame) {
        incomingBuffer.position(4)
        frame.read(incomingBuffer)
    }

    private suspend fun readAsDataFrame() {
        incomingBuffer.position(4)
        writeUnitToIp(incomingBuffer)
    }

    private suspend fun readAsDiscardingFrame() { readUnitFromSstp(incomingBuffer) }

    private suspend fun sendControlFrame(frame: ControlFrame) {
        controlBuffer.clear()
        frame.write(controlBuffer)
        controlBuffer.flip()
        writeUnitToSstp(controlBuffer)
    }

    private suspend fun establishLink() {
        globalIdentifier++
        var requestLcpFrame = PppLcpFrame()
        requestLcpFrame.code = PppLcpFrame.Code.CONFIGURE_REQUEST
        requestLcpFrame.id = globalIdentifier
        requestLcpFrame.mru = REQUEST_MRU_SIZE
        requestLcpFrame.auth = PppLcpFrame.AuthProtocol.PAP
        sendControlFrame(requestLcpFrame)

        var isClientAcknowledged = false
        var isServerAcknowledged = false
        while (true) {
            if (isClientAcknowledged && isServerAcknowledged) break

            when (cueIncoming()) {
                PppProtocol.LCP -> {
                    val receivedLcpFrame = PppLcpFrame()
                    readAsControlFrame(receivedLcpFrame)

                    when (receivedLcpFrame.code) {
                        PppLcpFrame.Code.CONFIGURE_ACK -> {
                            if (receivedLcpFrame.id == requestLcpFrame.id) {
                                networkSetting.mru = receivedLcpFrame.mru
                                isClientAcknowledged = true
                            }
                        }
                        PppLcpFrame.Code.CONFIGURE_NAK -> {
                            if (receivedLcpFrame.id == requestLcpFrame.id) {
                                if (receivedLcpFrame.auth == PppLcpFrame.AuthProtocol.OTHER)
                                    throw PppParsingError("No authentication protocols other than PAP are implemented")

                                globalIdentifier++
                                requestLcpFrame = PppLcpFrame()
                                requestLcpFrame.code = PppLcpFrame.Code.CONFIGURE_REQUEST
                                requestLcpFrame.id = globalIdentifier
                                requestLcpFrame.mru = receivedLcpFrame.mru
                                requestLcpFrame.auth = receivedLcpFrame.auth
                                sendControlFrame(requestLcpFrame)
                            }
                        }
                        PppLcpFrame.Code.CONFIGURE_REJECT -> {
                            // currently, only primary DNS can be rejected
                            if (receivedLcpFrame.id == requestLcpFrame.id) {
                                globalIdentifier++
                                requestLcpFrame = PppLcpFrame()
                                requestLcpFrame.code = PppLcpFrame.Code.CONFIGURE_REQUEST
                                requestLcpFrame.id = globalIdentifier
                                requestLcpFrame.mru = if (receivedLcpFrame.mru != null) null else REQUEST_MRU_SIZE
                                requestLcpFrame.auth = if (receivedLcpFrame.auth != null) null else PppLcpFrame.AuthProtocol.PAP
                                sendControlFrame(requestLcpFrame)
                            }
                        }
                        PppLcpFrame.Code.CONFIGURE_REQUEST -> {
                            val replyLcpFrame = PppLcpFrame()

                            if (receivedLcpFrame.unknownOption.isNotEmpty()) {
                                replyLcpFrame.code = PppLcpFrame.Code.CONFIGURE_REJECT
                                replyLcpFrame.id = receivedLcpFrame.id
                                replyLcpFrame.unknownOption = receivedLcpFrame.unknownOption
                                sendControlFrame(replyLcpFrame)
                            } else {
                                replyLcpFrame.code = PppLcpFrame.Code.CONFIGURE_ACK
                                replyLcpFrame.id = receivedLcpFrame.id
                                replyLcpFrame.mru = receivedLcpFrame.mru
                                replyLcpFrame.auth = receivedLcpFrame.auth
                                sendControlFrame(replyLcpFrame)
                                isServerAcknowledged = true
                            }
                        }
                        else -> {}
                    }
                }
                else -> readAsDiscardingFrame()
            }
        }
    }

    private suspend fun authenticate() {
        status.ppp = PppClientStatus.AUTHENTICATE
        globalIdentifier++
        val requestParFrame = PppParFrame()
        requestParFrame.code = PppParFrame.Code.AUTHENTICATE_REQUEST
        requestParFrame.id = globalIdentifier
        requestParFrame.credential = networkSetting.credential
        sendControlFrame(requestParFrame)

        loop@ while (true) {
            when (cueIncoming()) {
                PppProtocol.PAP -> {
                    val receivedFrame = PppParFrame()
                    readAsControlFrame(receivedFrame)
                    if (receivedFrame.id != requestParFrame.id) { continue@loop }

                    when (receivedFrame.code) {
                        PppParFrame.Code.AUTHENTICATE_ACK -> break@loop
                        PppParFrame.Code.AUTHENTICATE_NAK -> throw PppClientKilled(null)
                        else -> {}
                    }
                }
                else -> readAsDiscardingFrame()
            }
        }
    }

    private suspend fun configureNetwork() {
        status.ppp = PppClientStatus.NETWORK
        globalIdentifier++
        var requestIpcpFrame = PppIpcpFrame()
        requestIpcpFrame.code = PppIpcpFrame.Code.CONFIGURE_REQUEST
        requestIpcpFrame.id = globalIdentifier
        requestIpcpFrame.ipAddress = InetAddress.getByName("0.0.0.0")
        requestIpcpFrame.primaryDns = InetAddress.getByName("0.0.0.0")
        sendControlFrame(requestIpcpFrame)

        var isClientAcknowledged = false
        var isServerAcknowledged = false
        while (true) {
            if (isClientAcknowledged && isServerAcknowledged) break

            when (cueIncoming()) {
                PppProtocol.IPCP -> {
                    val receivedIpcpFrame = PppIpcpFrame()
                    readAsControlFrame(receivedIpcpFrame)

                    when (receivedIpcpFrame.code) {
                        PppIpcpFrame.Code.CONFIGURE_ACK -> {
                            if (receivedIpcpFrame.id == requestIpcpFrame.id) {
                                networkSetting.ipAdress = receivedIpcpFrame.ipAddress
                                networkSetting.primaryDns = receivedIpcpFrame.primaryDns
                                networkSetting.isNegotiated = true
                                isClientAcknowledged = true
                            }
                        }
                        PppIpcpFrame.Code.CONFIGURE_NAK -> {
                            if (receivedIpcpFrame.id == requestIpcpFrame.id) {
                                globalIdentifier++
                                requestIpcpFrame = PppIpcpFrame()
                                requestIpcpFrame.code = PppIpcpFrame.Code.CONFIGURE_REQUEST
                                requestIpcpFrame.id = globalIdentifier
                                requestIpcpFrame.ipAddress = receivedIpcpFrame.ipAddress
                                requestIpcpFrame.primaryDns = receivedIpcpFrame.primaryDns
                                sendControlFrame(requestIpcpFrame)
                            }
                        }
                        PppIpcpFrame.Code.CONFIGURE_REJECT -> {
                            if (receivedIpcpFrame.id == requestIpcpFrame.id) {
                                globalIdentifier++
                                requestIpcpFrame = PppIpcpFrame()
                                requestIpcpFrame.code = PppIpcpFrame.Code.CONFIGURE_REQUEST
                                requestIpcpFrame.id = globalIdentifier
                                requestIpcpFrame.ipAddress = if (receivedIpcpFrame.ipAddress != null) null else InetAddress.getByName("0.0.0.0")
                                requestIpcpFrame.primaryDns = if (receivedIpcpFrame.primaryDns != null) null else InetAddress.getByName("0.0.0.0")
                                sendControlFrame(requestIpcpFrame)
                            }
                        }
                        PppIpcpFrame.Code.CONFIGURE_REQUEST -> {
                            val replyIpcpFrame = PppIpcpFrame()

                            if (receivedIpcpFrame.unknownOption.isNotEmpty()) {
                                replyIpcpFrame.code = PppIpcpFrame.Code.CONFIGURE_REJECT
                                replyIpcpFrame.id = receivedIpcpFrame.id
                                replyIpcpFrame.unknownOption = receivedIpcpFrame.unknownOption
                                sendControlFrame(replyIpcpFrame)
                            } else {
                                replyIpcpFrame.code = PppIpcpFrame.Code.CONFIGURE_ACK
                                replyIpcpFrame.id = receivedIpcpFrame.id
                                replyIpcpFrame.ipAddress = receivedIpcpFrame.ipAddress
                                replyIpcpFrame.primaryDns = receivedIpcpFrame.primaryDns
                                sendControlFrame(replyIpcpFrame)
                                isServerAcknowledged = true
                            }
                        }
                        else -> {}
                    }
                }
                else -> readAsDiscardingFrame()
            }
        }
    }

    private fun runEchoTimer() {
        launch {
            var pollingTime  = ECHO_TIME_PPP
            var isSendingEcho = false

            while (isActive) {
                delay(pollingTime)
                val elapsedTime: Long = System.currentTimeMillis() - lastReceicedTime

                if (isSendingEcho) {
                    if (elapsedTime < ECHO_TIME_PPP) {
                        pollingTime = ECHO_TIME_PPP
                        isSendingEcho = false
                        continue
                    } else throw PppClientKilled(null)
                } else {
                    if (elapsedTime < ECHO_TIME_PPP) {
                        pollingTime = ECHO_TIME_PPP - elapsedTime
                        continue
                    }
                    else {
                        globalIdentifier++
                        val echoRequest = PppLcpFrame()
                        echoRequest.code = PppLcpFrame.Code.ECHO_REQUEST
                        echoRequest.id = globalIdentifier
                        echoRequest.magicNumber = magicNumber
                        sendControlFrame(echoRequest)
                        pollingTime = ECHO_TIME_PPP
                        isSendingEcho = true
                    }
                }
            }
        }
    }

    override suspend fun run() {
        establishLink()
        authenticate()
        configureNetwork()
        runOutgoing()

        lastReceicedTime = System.currentTimeMillis()
        runEchoTimer()
        while (true) {
            when (cueIncoming()) {
                PppProtocol.IP -> readAsDataFrame()
                PppProtocol.LCP -> {
                    val receivedFrame = PppLcpFrame()
                    readAsControlFrame(receivedFrame)
                    when (receivedFrame.code) {
                        PppLcpFrame.Code.ECHO_REQUEST -> {
                            globalIdentifier++
                            val echoReply = PppLcpFrame()
                            echoReply.code = PppLcpFrame.Code.ECHO_REPLY
                            echoReply.id = globalIdentifier
                            echoReply.magicNumber = magicNumber
                            sendControlFrame(echoReply)
                        }
                        PppLcpFrame.Code.TERMINATE_REQUEST -> throw PppClientKilled(null)
                        else -> {
                        }
                    }
                }
                PppProtocol.IPCP -> {
                    val receivedFrame = PppIpcpFrame()
                    readAsControlFrame(receivedFrame)
                    when (receivedFrame.code) {
                        PppIpcpFrame.Code.TERMINATE_REQUEST -> throw PppClientKilled(null)
                        else -> {
                        }
                    }
                }
                else -> readAsDiscardingFrame()
            }

            lastReceicedTime = System.currentTimeMillis()
        }
    }
}
