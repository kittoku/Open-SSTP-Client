package kittoku.opensstpclient.negotiator

import kittoku.opensstpclient.DEFAULT_MRU
import kittoku.opensstpclient.layer.LcpState
import kittoku.opensstpclient.layer.PppClient
import kittoku.opensstpclient.misc.*
import kittoku.opensstpclient.unit.*
import java.nio.charset.Charset
import java.security.SecureRandom


internal fun PppClient.tryReadingLcp(frame: LcpFrame): Boolean {
    try {
        frame.read(incomingBuffer)
    } catch (e: DataUnitParsingError) {
        parent.informDataUnitParsingError(frame, e)
        kill()
        return false
    }

    if (frame is LcpConfigureAck || frame is LcpConfigureNak || frame is LcpConfigureReject) {
        if (frame.id != currentLcpRequestId) return false
    }

    return true
}

internal suspend fun PppClient.sendLcpConfigureRequest() {
    if (lcpCounter.isExhausted) {
        parent.informCounterExhausted(::sendLcpConfigureRequest)
        kill()
        return
    }

    lcpCounter.consume()

    globalIdentifier++
    currentLcpRequestId = globalIdentifier
    val sending = LcpConfigureRequest()
    sending.id = currentLcpRequestId
    if (!networkSetting.mgMru.isRejected) sending.optionMru = parent.networkSetting.mgMru.create()
    if (!networkSetting.mgAuth.isRejected) sending.optionAuth =
        parent.networkSetting.mgAuth.create()
    sending.update()
    addControlUnit(sending)

    lcpTimer.reset()
}

internal suspend fun PppClient.sendLcpConfigureAck(received: LcpConfigureRequest) {
    val sending = LcpConfigureAck()
    sending.id = received.id
    sending.options = received.options
    sending.update()
    addControlUnit(sending)
}

internal suspend fun PppClient.sendLcpConfigureNak(received: LcpConfigureRequest) {
    if (received.optionMru != null) {
        received.optionMru = networkSetting.mgMru.create()
    }

    if (received.optionAuth != null) {
        received.optionAuth = networkSetting.mgAuth.create()
    }

    val sending = LcpConfigureNak()
    sending.id = received.id
    sending.options = received.options
    sending.update()
    addControlUnit(sending)
}

internal suspend fun PppClient.sendLcpConfigureReject(received: LcpConfigureRequest) {
    val sending = LcpConfigureReject()
    sending.id = received.id
    sending.options = received.extractUnknownOption()
    sending.update()
    addControlUnit(sending)
}

internal suspend fun PppClient.sendLcpEchoRequest() {
    globalIdentifier++
    val sending = LcpEchoRequest()
    sending.id = globalIdentifier
    sending.magicNumber = SecureRandom().nextInt()
    "Abura Mashi Mashi".toByteArray(Charset.forName("US-ASCII")).forEach {
        sending.holder.add(it)
    }
    sending.update()
    addControlUnit(sending)
}

internal suspend fun PppClient.sendLcpEchoReply(received: LcpEchoRequest) {
    val sending = LcpEchoReply()
    sending.id = received.id
    sending.magicNumber = received.magicNumber
    "Abura Mashi Mashi".toByteArray(Charset.forName("US-ASCII")).forEach {
        sending.holder.add(it)
    }
    sending.update()
    addControlUnit(sending)
}

internal suspend fun PppClient.receiveLcpConfigureRequest() {
    val received = LcpConfigureRequest()
    if (!tryReadingLcp(received)) return

    if (lcpState == LcpState.OPENED) {
        parent.informInvalidUnit(::receiveLcpConfigureRequest)
        kill()
        return
    }

    if (received.hasUnknownOption) {
        sendLcpConfigureReject(received)

        if (lcpState == LcpState.ACK_SENT) lcpState = LcpState.REQ_SENT

        return
    }

    val isMruOk = received.optionMru?.let { networkSetting.mgMru.compromiseReq(it) } ?: true
    val isAuthOk = received.optionAuth?.let { networkSetting.mgAuth.compromiseReq(it) } ?: true

    if (isMruOk && isAuthOk) {
        sendLcpConfigureAck(received)

        when (lcpState) {
            LcpState.REQ_SENT -> lcpState = LcpState.ACK_SENT
            LcpState.ACK_RCVD -> lcpState = LcpState.OPENED
        }
    } else {
        if (isMruOk) received.optionMru = null
        if (isAuthOk) received.optionAuth = null
        sendLcpConfigureNak(received)

        if (lcpState == LcpState.ACK_SENT) lcpState = LcpState.REQ_SENT
    }
}

internal suspend fun PppClient.receiveLcpConfigureAck() {
    val received = LcpConfigureAck()
    if (!tryReadingLcp(received)) return

    when (lcpState) {
        LcpState.REQ_SENT -> {
            lcpCounter.reset()
            lcpState = LcpState.ACK_RCVD
        }
        LcpState.ACK_RCVD -> {
            sendLcpConfigureRequest()
            lcpState = LcpState.REQ_SENT
        }
        LcpState.ACK_SENT -> {
            lcpCounter.reset()
            lcpState = LcpState.OPENED
        }
        LcpState.OPENED -> {
            parent.informInvalidUnit(::receiveLcpConfigureAck)
            kill()
            return
        }
    }
}

internal suspend fun PppClient.receiveLcpConfigureNak() {
    val received = LcpConfigureNak()
    if (!tryReadingLcp(received)) return

    if (lcpState == LcpState.OPENED) {
        parent.informInvalidUnit(::receiveLcpConfigureNak)
        kill()
        return
    }

    received.optionMru?.also { networkSetting.mgMru.compromiseNak(it) }
    received.optionAuth?.also { networkSetting.mgAuth.compromiseNak(it) }
    sendLcpConfigureRequest()

    if (lcpState == LcpState.ACK_RCVD) lcpState = LcpState.REQ_SENT
}

internal suspend fun PppClient.receiveLcpConfigureReject() {
    val received = LcpConfigureReject()
    if (!tryReadingLcp(received)) return

    if (received.optionMru != null) {
        if (networkSetting.customMru == null || networkSetting.customMru >= DEFAULT_MRU) {
            networkSetting.mgMru.isRejected = true
            networkSetting.currentMru = DEFAULT_MRU
        } else {
            parent.informOptionRejected(networkSetting.mgMru.create())
            kill()
            return
        }
    }

    when (lcpState) {
        LcpState.REQ_SENT, LcpState.ACK_SENT -> {
            lcpCounter.reset()
            sendLcpConfigureRequest()
        }
        LcpState.ACK_RCVD -> {
            sendLcpConfigureRequest()
            lcpState = LcpState.REQ_SENT
        }
        LcpState.OPENED -> {
            parent.informInvalidUnit(::receiveLcpConfigureReject)
            kill()
            return
        }
    }
}

internal suspend fun PppClient.receiveLcpEchoRequest() {
    val received = LcpEchoRequest()
    if (!tryReadingLcp(received)) return
    sendLcpEchoReply(received)
}
