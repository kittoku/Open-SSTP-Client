package kittoku.opensstpclient.packet

import kittoku.opensstpclient.BUFFER_SIZE_SSTP
import kittoku.opensstpclient.ECHO_TIME_SSTP
import kittoku.opensstpclient.misc.*
import kotlinx.coroutines.*
import java.nio.channels.Pipe


internal enum class SstpPacketType(val value: Short) {
    DATA(0x1000.toShort()),
    CONTROL(0x1001.toShort())
}

internal class SstpClient(lowerBridge: LayerBridge, higherBridge: LayerBridge,
                          networkSetting: NetworkSetting, status: DualClientStatus)
    : AbstractClient(lowerBridge, higherBridge, networkSetting, status, BUFFER_SIZE_SSTP) {
    private val fromSsl: Pipe.SourceChannel = lowerBridge.fromLower
    private val toSsl = lowerBridge.toLower
    private val readUnitFromPpp = higherBridge::readUnitFromHigher
    private val writeUnitToPpp = higherBridge::writeUnitToHigher
    private var lastReceicedTime: Long = 0L
    private lateinit var cryptoRequest: SstpCryptoBindingRequestAttribute

    private suspend fun cueIncoming(): SstpPacketType {
        incomingBuffer.clear()
        incomingBuffer.limit(4)
        fromSsl.completeRead(incomingBuffer)
        incomingBuffer.limit(incomingBuffer.getShort(2).toInt())

        return when(incomingBuffer.getShort(0)) {
            SstpPacketType.DATA.value -> SstpPacketType.DATA
            SstpPacketType.CONTROL.value -> SstpPacketType.CONTROL
            else -> {
                abortInProgress1("Invalid SSTP Packet Type",
                    SstpAttributeId.SSTP_ATTRIB_STATUS_INFO, SstpAttributeStatus.ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
                SstpPacketType.DATA // not reached here
            }
        }
    }

    override fun runOutgoing() {
        launch {
            outgoingBuffer.putShort(0, SstpPacketType.DATA.value) // fixed in SSTP Data Packet
            outgoingBuffer.putShort(2, 0) // placeholder for SSTP LengthPacket

            while (true) {
                outgoingBuffer.position(4)
                readUnitFromPpp(outgoingBuffer)
                outgoingBuffer.putShort(2, outgoingBuffer.limit().toShort())
                outgoingBuffer.rewind()
                toSsl.write(outgoingBuffer)
            }
        }
    }

    private suspend fun readAsControlPacket(): SstpControlPacket {
        val packet = SstpControlPacket()
        fromSsl.completeRead(incomingBuffer)
        incomingBuffer.position(4)
        try { packet.read(incomingBuffer) }
        catch (e: SstpParsingError) {
            abortInProgress1("Invalid SSTP Packet Type",
                SstpAttributeId.SSTP_ATTRIB_STATUS_INFO, SstpAttributeStatus.ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
        }
        return packet
    }

    private suspend fun readAsDataPacket() {
        fromSsl.completeRead(incomingBuffer)
        incomingBuffer.position(4)
        writeUnitToPpp(incomingBuffer)
    }

    private fun sendControlPacket(packet: SstpControlPacket) {
        controlBuffer.clear()
        packet.write(controlBuffer)
        controlBuffer.flip()
        toSsl.write(controlBuffer)
    }

    private suspend fun expectCallConnectAck() {
        var controlPacket = SstpControlPacket()
        controlPacket.messageType = SstpMessageType.SSTP_MSG_CALL_CONNECT_REQUEST
        controlPacket.addAttribute(SstpEncapsulatedProtocolIdAttribute())
        sendControlPacket(controlPacket)
        status.sstp = SstpClientStatus.CLIENT_CONNECT_REQUEST_SENT

        try {
            withTimeout(60_000L) {
                when (cueIncoming()) {
                    SstpPacketType.CONTROL -> {
                        controlPacket = readAsControlPacket()
                    }
                    SstpPacketType.DATA -> {
                        abortInProgress1(
                            "Expected SSTP Control Packet, but DATA one",
                            SstpAttributeId.SSTP_ATTRIB_STATUS_INFO,
                            SstpAttributeStatus.ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED
                        )
                    }
                }
            }
        } catch (e: TimeoutCancellationException) {
            abortInProgress1(
                null,
                SstpAttributeId.SSTP_ATTRIB_STATUS_INFO, SstpAttributeStatus.ATTRIB_STATUS_NEGOTIATION_TIMEOUT
            )
        }

        when (controlPacket.messageType) {
            SstpMessageType.SSTP_MSG_CALL_DISCONNECT -> disconnectInProgress2(null)
            SstpMessageType.SSTP_MSG_CALL_ABORT -> abortInProgress2(null, null, null)
            SstpMessageType.SSTP_MSG_CALL_CONNECT_NAK -> {
                var message  = ""
                for (attribute in controlPacket.attributeList) message += ", $attribute"
                abortInProgress1(message, null, null)
            }
            SstpMessageType.SSTP_MSG_CALL_CONNECT_ACK -> {
                cryptoRequest = controlPacket.attributeList[0] as SstpCryptoBindingRequestAttribute
            }
            else -> abortInProgress1(
                null,
                SstpAttributeId.SSTP_ATTRIB_STATUS_INFO, SstpAttributeStatus.ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED
            )
        }
    }

    private suspend fun expectAuthentication() {
        var controlPacket: SstpControlPacket
        status.sstp = SstpClientStatus.CLIENT_CONNECT_ACK_RECEIVED
        runOutgoing()

        try {
            withTimeout(60_000L) {
                while (true) {
                    when (cueIncoming()) {
                        SstpPacketType.DATA -> {
                            readAsDataPacket()
                        }
                        SstpPacketType.CONTROL -> {
                            controlPacket = readAsControlPacket()
                            when (controlPacket.messageType) {
                                SstpMessageType.SSTP_MSG_CALL_DISCONNECT -> disconnectInProgress2(null)
                                SstpMessageType.SSTP_MSG_CALL_ABORT -> abortInProgress2(null, null, null)
                                else -> abortInProgress1(
                                    null,
                                    SstpAttributeId.SSTP_ATTRIB_STATUS_INFO, SstpAttributeStatus.ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)
                            }
                        }
                    }

                    if (status.ppp == PppClientStatus.NETWORK) break
                }
                controlPacket = SstpControlPacket()
                controlPacket.messageType = SstpMessageType.SSTP_MSG_CALL_CONNECTED
                val cryptoBinding = SstpCryptoBindingAttribute()
                cryptoBinding.hashProtocol = cryptoRequest.hashProtocol
                cryptoBinding.nonce.put(cryptoRequest.nonce.array())
                cryptoBinding.certHash.put(networkSetting.hashCertificate(cryptoBinding.hashProtocol))
                controlPacket.addAttribute(cryptoBinding)
                controlPacket.computeCmac()
                sendControlPacket(controlPacket)
            }
        } catch (e: TimeoutCancellationException) {
            abortInProgress1(
                null,
                SstpAttributeId.SSTP_ATTRIB_STATUS_INFO, SstpAttributeStatus.ATTRIB_STATUS_NEGOTIATION_TIMEOUT)
        }
    }

    private fun runEchoTimer() {
        launch {
            var isSendingEcho = false
            var pollingTime = ECHO_TIME_SSTP

            while (isActive) {
                delay(pollingTime)
                val elapsedTime: Long = System.currentTimeMillis() - lastReceicedTime

                if (isSendingEcho) {
                    if (elapsedTime < ECHO_TIME_SSTP) {
                        isSendingEcho = false
                        continue
                    } else {
                        abortInProgress1("Echo hasn't been replied",
                            SstpAttributeId.SSTP_ATTRIB_STATUS_INFO, SstpAttributeStatus.ATTRIB_STATUS_NEGOTIATION_TIMEOUT)
                    }
                } else {
                    if (elapsedTime < ECHO_TIME_SSTP) {
                        pollingTime = ECHO_TIME_SSTP - elapsedTime
                        continue
                    }
                    else {
                        val echoRequest = SstpControlPacket()
                        echoRequest.messageType = SstpMessageType.SSTP_MSG_ECHO_REQUEST
                        try { withTimeout(ECHO_TIME_SSTP)  { sendControlPacket(echoRequest) } }
                        catch (e: TimeoutCancellationException) {
                            abortInProgress1("Echo cannot be sent",
                                SstpAttributeId.SSTP_ATTRIB_STATUS_INFO, SstpAttributeStatus.ATTRIB_STATUS_NEGOTIATION_TIMEOUT)
                        }
                        pollingTime = ECHO_TIME_SSTP
                        isSendingEcho = true
                    }
                }
            }
        }
    }

     override suspend fun run() {
         expectCallConnectAck()
         expectAuthentication()

         status.sstp = SstpClientStatus.CLIENT_CALL_CONNECTED
         lastReceicedTime = System.currentTimeMillis()
         runEchoTimer()
         while (true) {
             when (cueIncoming()) {
                 SstpPacketType.DATA -> readAsDataPacket()
                 SstpPacketType.CONTROL -> {
                     val receivedPacket = readAsControlPacket()
                     when (receivedPacket.messageType) {
                         SstpMessageType.SSTP_MSG_ECHO_REQUEST -> {
                             val echoReply = SstpControlPacket()
                             echoReply.messageType = SstpMessageType.SSTP_MSG_ECHO_RESPONSE
                             sendControlPacket(echoReply)
                         }
                         SstpMessageType.SSTP_MSG_ECHO_RESPONSE -> {
                         }
                         SstpMessageType.SSTP_MSG_CALL_ABORT -> abortInProgress2(null, null, null)
                         SstpMessageType.SSTP_MSG_CALL_DISCONNECT -> disconnectInProgress2(null)
                         else -> abortInProgress1(
                             null,
                             SstpAttributeId.SSTP_ATTRIB_STATUS_INFO,
                             SstpAttributeStatus.ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED
                         )
                     }
                 }
             }

             lastReceicedTime = System.currentTimeMillis()
         }
     }

    private suspend fun abortInProgress1(message: String?, attributeId: SstpAttributeId?, infoStatus: SstpAttributeStatus?) {
        // assume received message no more valid, so don't receive any more
        status.sstp = SstpClientStatus.CALL_ABORT_IN_PROGRESS_1

        val packet = SstpControlPacket()
        packet.messageType = SstpMessageType.SSTP_MSG_CALL_ABORT

        if (attributeId != null && infoStatus != null) {
            val attribute = SstpStatusInfoAttribute()
            attribute.attribID = attributeId
            attribute.status = infoStatus
            attribute.attribLength = 12
            packet.addAttribute(attribute)
        }

        status.sstp = SstpClientStatus.CALL_ABORT_PENDING
        withTimeoutOrNull(3_000L) {
            sendControlPacket(packet)
        }

        if (message == null) throw SstpClientKilled("Normally aborted")
        else  throw SstpClientKilled(message)
    }

    private suspend fun abortInProgress2(message: String?, attributeId: SstpAttributeId?, infoStatus: SstpAttributeStatus?) {
        status.sstp = SstpClientStatus.CALL_ABORT_IN_PROGRESS_2

        val packet = SstpControlPacket()
        packet.messageType = SstpMessageType.SSTP_MSG_CALL_ABORT

        if (attributeId != null && infoStatus != null) {
            val attribute = SstpStatusInfoAttribute()
            attribute.attribID = attributeId
            attribute.status = infoStatus
            attribute.attribLength = 12
            packet.addAttribute(attribute)
        }

        status.sstp = SstpClientStatus.CALL_ABORT_TIMEOUT_PENDING
        withTimeoutOrNull(1_000L) {
            sendControlPacket(packet)
        }

        if (message == null) throw SstpClientKilled("Normally aborted")
        else  throw SstpClientKilled(message)
    }

    private suspend fun disconnectInProgress1(message: String?) {
        status.sstp = SstpClientStatus.CALL_DISCONNECT_IN_PROGRESS_1

        val packet = SstpControlPacket()
        val attribute = SstpStatusInfoAttribute()

        attribute.attribID = SstpAttributeId.SSTP_ATTRIB_STATUS_INFO
        attribute.status = SstpAttributeStatus.ATTRIB_STATUS_NO_ERROR
        attribute.attribLength = 12

        packet.messageType = SstpMessageType.SSTP_MSG_CALL_DISCONNECT
        packet.addAttribute(attribute)

        withTimeoutOrNull(5_000L) {
            sendControlPacket(packet)
        }

        if (message == null) throw SstpClientKilled("Normally disconnected")
        else  throw SstpClientKilled(message)
    }

    private suspend fun disconnectInProgress2(message: String?) {
        status.sstp = SstpClientStatus.CALL_DISCONNECT_IN_PROGRESS_1

        val packet = SstpControlPacket()

        packet.messageType = SstpMessageType.SSTP_MSG_CALL_DISCONNECT_ACK

        withTimeoutOrNull(1_000L) {
            sendControlPacket(packet)
        }

        if (message == null) throw SstpClientKilled("Normally disconnected")
        else  throw SstpClientKilled(message)
    }
}

