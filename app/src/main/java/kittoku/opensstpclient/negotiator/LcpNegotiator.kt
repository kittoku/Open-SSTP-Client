package kittoku.opensstpclient.negotiator

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

internal fun PppClient.isCompromisableLcp(received: LcpConfigureFrame): Boolean {
    received.optionMru?.also {
        if (!networkSetting.mgMru.isAcceptable(it)) return false
    }

    received.optionAuth?.also {
        if (!networkSetting.mgAuth.isAcceptable(it)) return false
    }

    return true
}

internal fun PppClient.extractUncompromisableLcp(received: LcpConfigureFrame): Option<*>? {
    received.optionMru?.also {
        if (!networkSetting.mgMru.isAcceptable(it)) return it
    }

    received.optionAuth?.also {
        if (!networkSetting.mgAuth.isAcceptable(it)) return it
    }

    return null
}

internal fun PppClient.compromiseLcp(received: LcpConfigureFrame) {
    received.optionMru?.also { networkSetting.mgMru.current = it.copy() }

    received.optionAuth?.also { networkSetting.mgAuth.current = it.copy() }
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
    if (!networkSetting.mgMru.isRejected) sending.optionMru = parent.networkSetting.mgMru.current.copy()
    if (!networkSetting.mgAuth.isRejected) sending.optionAuth = parent.networkSetting.mgAuth.current.copy()
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
        received.optionMru = networkSetting.mgMru.current.copy()
    }

    if (received.optionAuth != null) {
        received.optionAuth = networkSetting.mgAuth.current.copy()
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

    when {
        received.hasUnknownOption -> {
            when (lcpState) {
                LcpState.REQ_SENT, LcpState.ACK_RCVD -> sendLcpConfigureReject(received)
                LcpState.ACK_SENT -> {
                    sendLcpConfigureReject(received)
                    lcpState = LcpState.REQ_SENT
                }
                LcpState.OPENED -> {
                    parent.informInvalidUnit(::receiveLcpConfigureRequest)
                    kill()
                    return
                }

            }
        }

        isCompromisableLcp(received) -> {
            compromiseLcp(received)
            when (lcpState) {
                LcpState.REQ_SENT -> {
                    sendLcpConfigureAck(received)
                    lcpState = LcpState.ACK_SENT
                }
                LcpState.ACK_RCVD -> {
                    sendLcpConfigureAck(received)
                    lcpState = LcpState.OPENED
                }
                LcpState.ACK_SENT -> sendLcpConfigureAck(received)
                LcpState.OPENED -> {
                    parent.informInvalidUnit(::receiveLcpConfigureRequest)
                    kill()
                    return
                }
            }
        }

        lcpState == LcpState.ACK_RCVD -> sendLcpConfigureNak(received)
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

    when (lcpState) {
        LcpState.REQ_SENT, LcpState.ACK_SENT -> {
            lcpCounter.reset()
            if (isCompromisableLcp(received)){
                compromiseLcp(received)
                sendLcpConfigureRequest()
            } else {
                parent.informUnableToCompromise(extractUncompromisableLcp(received)!!, ::receiveLcpConfigureNak)
                kill()
                return
            }
        }
        LcpState.ACK_RCVD -> {
            if (isCompromisableLcp(received)){
                compromiseLcp(received)
                sendLcpConfigureRequest()
            } else {
                parent.informUnableToCompromise(extractUncompromisableLcp(received)!!, ::receiveLcpConfigureNak)
                kill()
                return
            }
            lcpState = LcpState.REQ_SENT
        }
        LcpState.OPENED -> {
            parent.informInvalidUnit(::receiveLcpConfigureNak)
            kill()
            return
        }
    }
}

internal suspend fun PppClient.receiveLcpConfigureReject() {
    val received = LcpConfigureReject()
    if (!tryReadingLcp(received)) return

    if (received.optionMru != null) {
        if (networkSetting.mgMru.isRejectable) {
            networkSetting.mgMru.isRejected = true
            networkSetting.mgMru.current = LcpMruOption()
        } else {
            parent.informOptionRejected(networkSetting.mgMru.current)
            kill()
            return
        }
    }

    if (received.optionAuth != null) {
        if (networkSetting.mgAuth.isRejectable) {
            networkSetting.mgAuth.isRejected = true
            networkSetting.mgAuth.current = LcpAuthOption()
        } else {
            parent.informOptionRejected(networkSetting.mgAuth.current)
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
