package kittoku.osc.negotiator

import kittoku.osc.DEFAULT_MRU
import kittoku.osc.layer.LcpState
import kittoku.osc.layer.PppClient
import kittoku.osc.misc.*
import kittoku.osc.unit.*
import java.nio.charset.Charset


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

internal fun PppClient.sendLcpConfigureRequest() {
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
    parent.controlQueue.add(sending)

    lcpTimer.reset()
}

internal fun PppClient.sendLcpConfigureAck(received: LcpConfigureRequest) {
    val sending = LcpConfigureAck()
    sending.id = received.id
    sending.options = received.options
    sending.update()
    parent.controlQueue.add(sending)
}

internal fun PppClient.sendLcpConfigureNak(received: LcpConfigureRequest) {
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
    parent.controlQueue.add(sending)
}

internal fun PppClient.sendLcpConfigureReject(received: LcpConfigureRequest) {
    val sending = LcpConfigureReject()
    sending.id = received.id
    sending.options = received.extractUnknownOption()
    sending.update()
    parent.controlQueue.add(sending)
}

internal fun PppClient.sendLcpEchoRequest() {
    globalIdentifier++
    val sending = LcpEchoRequest()
    sending.id = globalIdentifier
    sending.holder = "Abura Mashi Mashi".toByteArray(Charset.forName("US-ASCII"))
    sending.update()
    parent.controlQueue.add(sending)
}

internal fun PppClient.sendLcpEchoReply(received: LcpEchoRequest) {
    val sending = LcpEchoReply()
    sending.id = received.id
    sending.holder = "Abura Mashi Mashi".toByteArray(Charset.forName("US-ASCII"))
    sending.update()
    parent.controlQueue.add(sending)
}

internal fun PppClient.receiveLcpConfigureRequest() {
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

        lcpState = when (lcpState) {
            LcpState.REQ_SENT -> LcpState.ACK_SENT
            LcpState.ACK_RCVD -> LcpState.OPENED
            else -> lcpState
        }

    } else {
        if (isMruOk) received.optionMru = null
        if (isAuthOk) received.optionAuth = null
        sendLcpConfigureNak(received)

        if (lcpState == LcpState.ACK_SENT) lcpState = LcpState.REQ_SENT
    }
}

internal fun PppClient.receiveLcpConfigureAck() {
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

internal fun PppClient.receiveLcpConfigureNak() {
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

internal fun PppClient.receiveLcpConfigureReject() {
    val received = LcpConfigureReject()
    if (!tryReadingLcp(received)) return

    if (received.optionMru != null) {
        if (networkSetting.PPP_MRU >= DEFAULT_MRU) {
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

internal fun PppClient.receiveLcpEchoRequest() {
    val received = LcpEchoRequest()
    if (!tryReadingLcp(received)) return
    sendLcpEchoReply(received)
}

internal fun PppClient.receiveLcpEchoReply() {
    val received = LcpEchoReply()
    if (!tryReadingLcp(received)) return
}


internal fun PppClient.receiveLcpProtocolReject(assumed: PppProtocol) {
    val received = LcpProtocolReject()
    if (!tryReadingLcp(received)) return

    if (PppProtocol.resolve(received.rejectedProtocol) == assumed) {
        parent.inform("${assumed.name} protocol was rejected", null)
        kill()
        return
    }
}
