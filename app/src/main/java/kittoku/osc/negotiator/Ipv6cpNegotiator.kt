package kittoku.osc.negotiator

import kittoku.osc.layer.Ipv6cpState
import kittoku.osc.layer.PppClient
import kittoku.osc.misc.*
import kittoku.osc.unit.*


internal fun PppClient.tryReadingIpv6cp(frame: Ipv6cpFrame): Boolean {
    try {
        frame.read(incomingBuffer)
    } catch (e: DataUnitParsingError) {
        parent.informDataUnitParsingError(frame, e)
        kill()
        return false
    }

    if (frame is Ipv6cpConfigureAck || frame is Ipv6cpConfigureNak) {
        if (frame.id != currentIpv6cpRequestId) return false
    }

    return true
}

internal fun PppClient.sendIpv6cpConfigureRequest() {
    if (ipv6cpCounter.isExhausted) {
        parent.informCounterExhausted(::sendIpv6cpConfigureRequest)
        kill()
        return
    }

    ipv6cpCounter.consume()

    globalIdentifier++
    currentIpv6cpRequestId = globalIdentifier
    val sending = Ipv6cpConfigureRequest()
    sending.id = currentIpv6cpRequestId
    if (!networkSetting.mgIpv6.isRejected) sending.optionIdentifier =
        parent.networkSetting.mgIpv6.create()
    sending.update()
    parent.controlQueue.add(sending)

    ipv6cpTimer.reset()
}

internal fun PppClient.sendIpv6cpConfigureAck(received: Ipv6cpConfigureRequest) {
    val sending = Ipv6cpConfigureAck()
    sending.id = received.id
    sending.options = received.options
    sending.update()
    parent.controlQueue.add(sending)
}

internal fun PppClient.sendIpv6cpConfigureNak(received: Ipv6cpConfigureRequest) {
    if (received.optionIdentifier != null) {
        received.optionIdentifier = networkSetting.mgIpv6.create()
    }

    val sending = Ipv6cpConfigureNak()
    sending.id = received.id
    sending.options = received.options
    sending.update()
    parent.controlQueue.add(sending)
}

internal fun PppClient.sendIpv6cpConfigureReject(received: Ipv6cpConfigureRequest) {
    val sending = Ipv6cpConfigureReject()
    sending.id = received.id
    sending.options = received.extractUnknownOption()
    sending.update()
    parent.controlQueue.add(sending)
}

internal fun PppClient.receiveIpv6cpConfigureRequest() {
    val received = Ipv6cpConfigureRequest()
    if (!tryReadingIpv6cp(received)) return

    if (ipv6cpState == Ipv6cpState.OPENED) {
        parent.informInvalidUnit(::receiveIpv6cpConfigureRequest)
        kill()
        return
    }

    if (received.hasUnknownOption) {
        sendIpv6cpConfigureReject(received)

        if (ipv6cpState == Ipv6cpState.ACK_SENT) ipv6cpState = Ipv6cpState.REQ_SENT

        return
    }

    val isIdentifierOk =
        received.optionIdentifier?.let { networkSetting.mgIpv6.compromiseReq(it) } ?: true

    if (isIdentifierOk) {
        sendIpv6cpConfigureAck(received)

        ipv6cpState = when (ipv6cpState) {
            Ipv6cpState.REQ_SENT -> Ipv6cpState.ACK_SENT
            Ipv6cpState.ACK_RCVD -> Ipv6cpState.OPENED
            else -> ipv6cpState
        }

    } else {
        if (isIdentifierOk) received.optionIdentifier = null
        sendIpv6cpConfigureNak(received)

        if (ipv6cpState == Ipv6cpState.ACK_SENT) ipv6cpState = Ipv6cpState.REQ_SENT
    }
}


internal fun PppClient.receiveIpv6cpConfigureAck() {
    val received = Ipv6cpConfigureAck()
    if (!tryReadingIpv6cp(received)) return

    when (ipv6cpState) {
        Ipv6cpState.REQ_SENT -> {
            ipv6cpCounter.reset()
            ipv6cpState = Ipv6cpState.ACK_RCVD
        }
        Ipv6cpState.ACK_RCVD -> {
            sendIpv6cpConfigureRequest()
            ipv6cpState = Ipv6cpState.REQ_SENT
        }
        Ipv6cpState.ACK_SENT -> {
            ipv6cpCounter.reset()
            ipv6cpState = Ipv6cpState.OPENED
        }
        Ipv6cpState.OPENED -> {
            parent.informInvalidUnit(::receiveIpv6cpConfigureAck)
            kill()
            return
        }

    }
}

internal fun PppClient.receiveIpv6cpConfigureNak() {
    val received = Ipv6cpConfigureNak()
    if (!tryReadingIpv6cp(received)) return

    if (ipv6cpState == Ipv6cpState.OPENED) {
        parent.informInvalidUnit(::receiveIpv6cpConfigureNak)
        kill()
        return
    }

    received.optionIdentifier?.also { networkSetting.mgIpv6.compromiseNak(it) }
    sendIpv6cpConfigureRequest()

    if (ipv6cpState == Ipv6cpState.ACK_RCVD) ipv6cpState = Ipv6cpState.REQ_SENT
}

internal fun PppClient.receiveIpv6cpConfigureReject() {
    val received = Ipv6cpConfigureReject()
    if (!tryReadingIpv6cp(received)) return

    if (received.optionIdentifier != null) {
        parent.informOptionRejected(networkSetting.mgIpv6.create())
        kill()
        return
    }

    when (ipv6cpState) {
        Ipv6cpState.REQ_SENT, Ipv6cpState.ACK_SENT -> {
            ipv6cpCounter.reset()
            sendIpv6cpConfigureRequest()
        }
        Ipv6cpState.ACK_RCVD -> {
            sendIpv6cpConfigureRequest()
            ipv6cpState = Ipv6cpState.REQ_SENT
        }
        Ipv6cpState.OPENED -> {
            parent.informInvalidUnit(::receiveIpv6cpConfigureReject)
            kill()
            return
        }
    }
}
