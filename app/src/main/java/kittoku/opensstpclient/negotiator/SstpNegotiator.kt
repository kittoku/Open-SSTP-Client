package kittoku.opensstpclient.negotiator

import kittoku.opensstpclient.layer.SstpClient
import kittoku.opensstpclient.layer.SstpStatus
import kittoku.opensstpclient.misc.*
import kittoku.opensstpclient.unit.*
import java.nio.ByteBuffer
import java.nio.charset.Charset
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec


internal fun SstpClient.tryReadingPacket(packet: ControlPacket): Boolean {
    try {
        packet.read(incomingBuffer)
    } catch (e: DataUnitParsingError) {
        parent.informDataUnitParsingError(packet, e)
        status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
        return false
    }

    return true
}

internal fun SstpClient.challengeWholePacket(): Boolean {
    if (!incomingBuffer.challenge(4)) {
        return false
    }

    incomingBuffer.move(2)

    (incomingBuffer.getShort().toInt() - 4).also {
        if (it < 0) {
            parent.informInvalidUnit(::challengeWholePacket)
            status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
            return false
        }

        if (!incomingBuffer.challenge(it))  {
            incomingBuffer.reset()
            return false
        }
    }

    incomingBuffer.reset()
    return true
}

internal suspend fun SstpClient.sendCallConnectRequest() {
    if (negotiationCounter.isExhausted) {
        parent.informCounterExhausted(::sendCallConnectRequest)
        status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
        return
    }

    negotiationCounter.consume()

    val sending = SstpCallConnectRequest().also { it.update() }
    addControlUnit(sending)

    negotiationTimer.reset()
}

internal suspend fun SstpClient.sendCallConnected() {
    val sending = SstpCallConnected()
    val cmkInputBuffer = ByteBuffer.allocate(32)
    val cmacInputBuffer = ByteBuffer.allocate(sending.validLengthRange.first)
    val hashSetting = HashSetting(networkSetting.hashProtocol)

    networkSetting.nonce.writeTo(sending.binding.nonce)
    MessageDigest.getInstance(hashSetting.digestProtocol).also {
        it.digest(networkSetting.serverCertificate.encoded).writeTo(sending.binding.certHash)
    }

    sending.write(cmacInputBuffer)

    val HLAK = when (networkSetting.currentAuth) {
        AuthSuite.PAP -> ByteArray(32)
        else -> {
            parent.inform("An unacceptable authentication protocol chosen", null)
            status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
            return
        }
    }

    val cmkSeed = "SSTP inner method derived CMK".toByteArray(Charset.forName("US-ASCII"))
    cmkInputBuffer.put(cmkSeed)
    cmkInputBuffer.putShort(hashSetting.cmacSize)
    cmkInputBuffer.put(1)

    Mac.getInstance(hashSetting.macProtocol).also {
        it.init(SecretKeySpec(HLAK, hashSetting.macProtocol))
        val cmk = it.doFinal(cmkInputBuffer.array())
        it.init(SecretKeySpec(cmk, hashSetting.macProtocol))
        val cmac = it.doFinal(cmacInputBuffer.array())
        cmac.writeTo(sending.binding.compoundMac)
    }

    sending.update()
    addControlUnit(sending)
}

internal suspend fun SstpClient.sendEchoRequest() {
    if (echoCounter.isExhausted) {
        parent.informCounterExhausted(::sendEchoRequest)
        status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
        return
    }

    echoCounter.consume()

    val sending = SstpEchoRequest().also { it.update() }
    addControlUnit(sending)

    echoTimer.reset()
}

internal suspend fun SstpClient.sendEchoReply() {
    val sending = SstpEchoResponse().also { it.update() }
    addControlUnit(sending)
}


internal suspend fun SstpClient.sendLastGreeting() {
    val sending = when (status.sstp) {
        SstpStatus.CALL_DISCONNECT_IN_PROGRESS_1 -> SstpCallDisconnect()
        SstpStatus.CALL_DISCONNECT_IN_PROGRESS_2 -> SstpCallDisconnectAck()
        else -> SstpCallAbort()
    }

    sending.update()
    addControlUnit(sending)

    throw SuicideException()
}

internal suspend fun SstpClient.receiveCallConnectAck() {
    val received = SstpCallConnectAck()
    if (!tryReadingPacket(received)) return

    networkSetting.hashProtocol = when (received.request.bitmask.toInt()) {
        in 2..3 -> HashProtocol.CERT_HASH_PROTOCOL_SHA256
        1 -> HashProtocol.CERT_HASH_PROTOCOL_SHA1
        else -> {
            parent.informInvalidUnit(::receiveCallConnectAck)
            status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
            return
        }
    }

    networkSetting.nonce = received.request.nonce

    status.sstp = SstpStatus.CLIENT_CONNECT_ACK_RECEIVED
    negotiationCounter.reset()
    negotiationTimer.reset()
}

internal suspend fun SstpClient.receiveEchoRequest() {
    val received = SstpEchoRequest()
    if (!tryReadingPacket(received)) return

    sendEchoReply()
}

internal fun SstpClient.receiveEchoResponse() {
    val received = SstpEchoResponse()
    if (!tryReadingPacket(received)) return
}

private class HashSetting(hashProtocol: HashProtocol) {
    internal val cmacSize: Short // little endian
    internal val digestProtocol: String
    internal val macProtocol: String

    init {
        when (hashProtocol) {
            HashProtocol.CERT_HASH_PROTOCOL_SHA1 -> {
                cmacSize = 0x1400.toShort()
                digestProtocol = "SHA-1"
                macProtocol = "HmacSHA1"

            }

            HashProtocol.CERT_HASH_PROTOCOL_SHA256 -> {
                cmacSize = 0x2000.toShort()
                digestProtocol = "SHA-256"
                macProtocol = "HmacSHA256"
            }

        }
    }

}
