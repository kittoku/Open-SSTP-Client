package kittoku.osc.negotiator

import kittoku.osc.layer.PppClient
import kittoku.osc.misc.*
import kittoku.osc.unit.*
import java.nio.ByteBuffer
import java.nio.charset.Charset
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec


internal fun PppClient.tryReadingChap(frame: ChapFrame): Boolean {
    try {
        frame.read(incomingBuffer)
    } catch (e: DataUnitParsingError) {
        parent.informDataUnitParsingError(frame, e)
        kill()
        return false
    }

    if (frame is ChapSuccess || frame is ChapFailure) {
        if (frame.id != currentAuthRequestId) return false
    }

    return true
}

internal fun PppClient.sendChapResponse(received: ChapChallenge) {
    currentAuthRequestId = received.id
    val sending = ChapResponse()
    sending.id = currentAuthRequestId

    parent.networkSetting.also {
        received.value.copyInto(it.chapSetting.serverChallenge)
        SecureRandom().nextBytes(it.chapSetting.clientChallenge)
        generateResponse(it)
        it.chapSetting.clientChallenge.copyInto(sending.challenge)
        it.chapSetting.clientResponse.copyInto(sending.response)
        sending.name = it.HOME_USERNAME.toByteArray(Charset.forName("US-ASCII"))
    }

    sending.update()
    parent.controlQueue.add(sending)

    authTimer.reset()
}

internal fun PppClient.receiveChapChallenge() {
    val received = ChapChallenge()
    if (!tryReadingChap(received)) return

    sendChapResponse(received)
}

internal fun PppClient.receiveChapSuccess() {
    val received = ChapSuccess()
    if (!tryReadingChap(received)) return

    received.response.copyInto(networkSetting.chapSetting.serverResponse)

    if (!authenticateResponse(networkSetting)) {
        parent.informAuthenticationFailed(::receiveChapSuccess)
        kill()
        return
    }

    if (!isAuthFinished) {
        isAuthFinished = true
    }
}

internal fun PppClient.receiveChapFailure() {
    val received = ChapFailure()
    if (!tryReadingChap(received)) return

    if (!isAuthFinished) {
        parent.informAuthenticationFailed(::receiveChapFailure)
        kill()
        return
    }
}

private fun isEvenBits(value: Int): Boolean {
    // only count the bits of the least significant byte
    var count = 0
    var holder = value
    repeat(8) {
        count += (holder and 1)
        holder = holder.shr(1)
    }

    return count % 2 == 0
}

private fun addParity(bytes: ByteArray): ByteArray {
    val buffer = ByteBuffer.allocate(8)
    buffer.position(1)
    buffer.put(bytes)
    buffer.clear()
    var holder = buffer.getLong(0)
    val mask = 0b0111_1111L

    repeat(8) {
        var b = (holder and mask).toInt()
        b = b.shl(1) + if (isEvenBits(b)) 1 else 0
        buffer.put(7 - it, b.toByte())
        holder = holder.shr(7)
    }

    return buffer.array()
}

private fun generateResponse(setting: NetworkSetting) {
    val userArray = setting.HOME_USERNAME.toByteArray(Charset.forName("US-ASCII"))
    val passArray = setting.HOME_PASSWORD.toByteArray(Charset.forName("UTF-16LE"))

    val challenge = MessageDigest.getInstance("SHA-1").let {
        it.update(setting.chapSetting.clientChallenge)
        it.update(setting.chapSetting.serverChallenge)
        it.update(userArray)
        it.digest().sliceArray(0 until 8)
    }

    val zeroPassHash = ByteArray(21)
    hashMd4(passArray).copyInto(zeroPassHash)

    Cipher.getInstance("DES/ECB/NoPadding").also {
        repeat(3) { i ->
            it.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(
                    addParity(zeroPassHash.sliceArray(i * 7 until (i + 1) * 7)),
                    "DES"
                )
            )

            it.doFinal(challenge).copyInto(setting.chapSetting.clientResponse, i * 8)
        }
    }
}

private fun authenticateResponse(setting: NetworkSetting): Boolean {
    val userArray = setting.HOME_USERNAME.toByteArray(Charset.forName("US-ASCII"))
    val passArray = setting.HOME_PASSWORD.toByteArray(Charset.forName("UTF-16LE"))

    val magic1 = sum(
        "4D616769632073657276657220746F20",
        "636C69656E74207369676E696E672063",
        "6F6E7374616E74"
    ).toHexByteArray()

    val magic2 = sum(
        "50616420746F206D616B652069742064",
        "6F206D6F7265207468616E206F6E6520",
        "697465726174696F6E"
    ).toHexByteArray()

    val challenge = MessageDigest.getInstance("SHA-1").let {
        it.update(setting.chapSetting.clientChallenge)
        it.update(setting.chapSetting.serverChallenge)
        it.update(userArray)
        it.digest().sliceArray(0 until 8)
    }

    val digest = MessageDigest.getInstance("SHA-1").let {
        it.update(hashMd4(hashMd4(passArray)))
        it.update(setting.chapSetting.clientResponse)
        it.update(magic1)
        val tempDigest = it.digest()

        it.reset()
        it.update(tempDigest)
        it.update(challenge)
        it.update(magic2)
        it.digest()
    }

    val expected = "S=${digest.toHexString()}".toByteArray(Charset.forName("US-ASCII"))

    return expected.isSame(setting.chapSetting.serverResponse)
}
