package kittoku.osc.negotiator

import kittoku.osc.layer.SstpClient
import kittoku.osc.layer.SstpStatus
import kittoku.osc.misc.*
import kittoku.osc.unit.*
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

internal fun SstpClient.sendCallConnectRequest() {
    if (negotiationCounter.isExhausted) {
        parent.informCounterExhausted(::sendCallConnectRequest)
        status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
        return
    }

    negotiationCounter.consume()

    val sending = SstpCallConnectRequest().also { it.update() }
    parent.controlQueue.add(sending)

    negotiationTimer.reset()
}

internal fun SstpClient.sendCallConnected() {
    val sending = SstpCallConnected()
    val cmkInputBuffer = ByteBuffer.allocate(32)
    val cmacInputBuffer = ByteBuffer.allocate(sending.validLengthRange.first)
    val hashSetting = HashSetting(networkSetting.hashProtocol)

    networkSetting.nonce.copyInto(sending.binding.nonce)
    MessageDigest.getInstance(hashSetting.digestProtocol).also {
        it.digest(networkSetting.serverCertificate.encoded).copyInto(sending.binding.certHash)
    }

    sending.binding.hashProtocol = networkSetting.hashProtocol
    sending.update()
    sending.write(cmacInputBuffer)

    val HLAK = when (networkSetting.currentAuth) {
        AuthSuite.PAP -> ByteArray(32)
        AuthSuite.MSCHAPv2 -> generateChapHLAK(networkSetting)
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
        cmac.copyInto(sending.binding.compoundMac)
    }

    sending.update()
    parent.controlQueue.add(sending)
}

internal fun SstpClient.sendEchoRequest() {
    if (echoCounter.isExhausted) {
        parent.informCounterExhausted(::sendEchoRequest)
        status.sstp = SstpStatus.CALL_ABORT_IN_PROGRESS_1
        return
    }

    echoCounter.consume()

    val sending = SstpEchoRequest().also { it.update() }
    parent.controlQueue.add(sending)

    echoTimer.reset()
}

internal fun SstpClient.sendEchoResponse() {
    val sending = SstpEchoResponse().also { it.update() }
    parent.controlQueue.add(sending)
}


internal fun SstpClient.sendLastGreeting() {
    val sending = when (status.sstp) {
        SstpStatus.CALL_DISCONNECT_IN_PROGRESS_1 -> SstpCallDisconnect()
        SstpStatus.CALL_DISCONNECT_IN_PROGRESS_2 -> SstpCallDisconnectAck()
        else -> SstpCallAbort()
    }

    sending.update()
    parent.controlQueue.add(sending)

    throw SuicideException()
}

internal fun SstpClient.receiveCallConnectAck() {
    val received = SstpCallConnectAck()
    if (!tryReadingPacket(received)) return

    networkSetting.hashProtocol = when (received.request.bitmask.toInt()) {
        in 2..3 -> CERT_HASH_PROTOCOL_SHA256
        1 -> CERT_HASH_PROTOCOL_SHA1
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

internal fun SstpClient.receiveEchoRequest() {
    val received = SstpEchoRequest()
    if (!tryReadingPacket(received)) return

    sendEchoResponse()
}

internal fun SstpClient.receiveEchoResponse() {
    val received = SstpEchoResponse()
    if (!tryReadingPacket(received)) return
}

private class HashSetting(hashProtocol: Byte) {
    val cmacSize: Short // little endian
    val digestProtocol: String
    val macProtocol: String

    init {
        when (hashProtocol) {
            CERT_HASH_PROTOCOL_SHA1 -> {
                cmacSize = 0x1400.toShort()
                digestProtocol = "SHA-1"
                macProtocol = "HmacSHA1"

            }

            CERT_HASH_PROTOCOL_SHA256 -> {
                cmacSize = 0x2000.toShort()
                digestProtocol = "SHA-256"
                macProtocol = "HmacSHA256"
            }

            else -> throw NotImplementedError()
        }
    }

}

private fun generateChapHLAK(setting: NetworkSetting): ByteArray {
    val passArray = setting.HOME_PASSWORD.toByteArray(Charset.forName("UTF-16LE"))

    val magic1 = sum(
        "5468697320697320746865204D505045",
        "204D6173746572204B6579"
    ).toHexByteArray()

    val magic2 = sum(
        "4F6E2074686520636C69656E74207369",
        "64652C20746869732069732074686520",
        "73656E64206B65793B206F6E20746865",
        "2073657276657220736964652C206974",
        "20697320746865207265636569766520",
        "6B65792E"
    ).toHexByteArray()

    val magic3 = sum(
        "4F6E2074686520636C69656E74207369",
        "64652C20746869732069732074686520",
        "72656365697665206B65793B206F6E20",
        "7468652073657276657220736964652C",
        "206974206973207468652073656E6420",
        "6B65792E"
    ).toHexByteArray()

    val pad1 = sum(
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "0000000000000000"
    ).toHexByteArray()

    val pad2 = sum(
        "F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2",
        "F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2",
        "F2F2F2F2F2F2F2F2"
    ).toHexByteArray()

    return MessageDigest.getInstance("SHA-1").let {
        it.update(hashMd4(hashMd4(passArray)))
        it.update(setting.chapSetting.clientResponse)
        it.update(magic1)
        val masterkey = it.digest().sliceArray(0 until 16)

        val hlak = ByteArray(32)
        it.reset()
        it.update(masterkey)
        it.update(pad1)
        it.update(magic2)
        it.update(pad2)
        it.digest().copyInto(hlak, endIndex = 16)

        it.reset()
        it.update(masterkey)
        it.update(pad1)
        it.update(magic3)
        it.update(pad2)
        it.digest().copyInto(hlak, 16, endIndex = 16)

        hlak
    }
}
