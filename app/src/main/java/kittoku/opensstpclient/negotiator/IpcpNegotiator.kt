package kittoku.opensstpclient.negotiator

import kittoku.opensstpclient.layer.IpcpState
import kittoku.opensstpclient.layer.PppClient
import kittoku.opensstpclient.misc.*
import kittoku.opensstpclient.unit.*


internal fun PppClient.tryReadingIpcp(frame: IpcpFrame): Boolean {
    try {
        frame.read(incomingBuffer)
    } catch (e: DataUnitParsingError) {
        parent.informDataUnitParsingError(frame, e)
        kill()
        return false
    }

    if (frame is IpcpConfigureAck || frame is IpcpConfigureNak) {
        if (frame.id != currentIpcpRequestId) return false
    }

    return true
}

internal fun PppClient.isCompromisableIpcp(received: IpcpConfigureFrame): Boolean {
    received.optionIpAddress?.also {
        if (!networkSetting.mgIpAddress.isAcceptable(it)) return false
    }

    received.optionDnsAddress?.also {
        if (!networkSetting.mgDnsAddress.isAcceptable(it)) return false
    }

    return true
}

internal fun PppClient.extractUncompromisableIpcp(received: IpcpConfigureFrame): Option<*>? {
    received.optionIpAddress?.also {
        if (!networkSetting.mgIpAddress.isAcceptable(it)) return it
    }

    received.optionDnsAddress?.also {
        if (!networkSetting.mgDnsAddress.isAcceptable(it)) return it
    }

    return null
}

internal fun PppClient.compromiseIpcp(received: IpcpConfigureFrame) {
    received.optionIpAddress?.also { networkSetting.mgIpAddress.current = it.copy() }

    received.optionDnsAddress?.also { networkSetting.mgDnsAddress.current = it.copy() }
}

internal suspend fun PppClient.sendIpcpConfigureRequest() {
    if (ipcpCounter.isExhausted) {
        parent.informCounterExhausted(::sendIpcpConfigureRequest)
        kill()
        return
    }

    ipcpCounter.consume()

    globalIdentifier++
    currentIpcpRequestId = globalIdentifier
    val sending = IpcpConfigureRequest()
    sending.id = currentIpcpRequestId
    if (!networkSetting.mgIpAddress.isRejected) sending.optionIpAddress =
        parent.networkSetting.mgIpAddress.current.copy()
    if (!networkSetting.mgDnsAddress.isRejected) sending.optionDnsAddress =
        parent.networkSetting.mgDnsAddress.current.copy()
    sending.update()
    addControlUnit(sending)

    ipcpTimer.reset()
}

internal suspend fun PppClient.sendIpcpConfigureAck(received: IpcpConfigureRequest) {
    val sending = IpcpConfigureAck()
    sending.id = received.id
    sending.options = received.options
    sending.update()
    addControlUnit(sending)
}

internal suspend fun PppClient.sendIpcpConfigureNak(received: IpcpConfigureRequest) {
    if (received.optionIpAddress != null) {
        received.optionIpAddress = networkSetting.mgIpAddress.current.copy()
    }

    if (received.optionDnsAddress != null) {
        received.optionDnsAddress = networkSetting.mgDnsAddress.current.copy()
    }

    val sending = IpcpConfigureNak()
    sending.id = received.id
    sending.options = received.options
    sending.update()
    addControlUnit(sending)
}

internal suspend fun PppClient.sendIpcpConfigureReject(received: IpcpConfigureRequest) {
    val sending = IpcpConfigureReject()
    sending.id = received.id
    sending.options = received.extractUnknownOption()
    sending.update()
    addControlUnit(sending)
}

internal suspend fun PppClient.receiveIpcpConfigureRequest() {
    val received = IpcpConfigureRequest()
    if (!tryReadingIpcp(received)) return

    when {
        received.hasUnknownOption -> {
            when (ipcpState) {
                IpcpState.REQ_SENT, IpcpState.ACK_RCVD -> sendIpcpConfigureReject(received)
                IpcpState.ACK_SENT -> {
                    sendIpcpConfigureReject(received)
                    ipcpState = IpcpState.REQ_SENT
                }
                IpcpState.OPENED -> {
                    parent.informInvalidUnit(::receiveIpcpConfigureRequest)
                    kill()
                    return
                }
            }
        }

        isCompromisableIpcp(received) -> {
            compromiseIpcp(received)
            when (ipcpState) {
                IpcpState.REQ_SENT -> {
                    sendIpcpConfigureAck(received)
                    ipcpState = IpcpState.ACK_SENT
                }
                IpcpState.ACK_RCVD -> {
                    sendIpcpConfigureAck(received)
                    ipcpState = IpcpState.OPENED
                }
                IpcpState.ACK_SENT -> sendIpcpConfigureAck(received)
                IpcpState.OPENED -> {
                    parent.informInvalidUnit(::receiveIpcpConfigureRequest)
                    kill()
                    return
                }
            }
        }

        ipcpState == IpcpState.ACK_RCVD -> sendIpcpConfigureNak(received)
    }
}

internal suspend fun PppClient.receiveIpcpConfigureAck() {
    val received = IpcpConfigureAck()
    if (!tryReadingIpcp(received)) return

    when (ipcpState) {
        IpcpState.REQ_SENT -> {
            ipcpCounter.reset()
            ipcpState = IpcpState.ACK_RCVD
        }
        IpcpState.ACK_RCVD -> {
            sendIpcpConfigureRequest()
            ipcpState = IpcpState.REQ_SENT
        }
        IpcpState.ACK_SENT -> {
            ipcpCounter.reset()
            ipcpState = IpcpState.OPENED
        }
        IpcpState.OPENED -> {
            parent.informInvalidUnit(::receiveIpcpConfigureAck)
            kill()
            return
        }

    }
}

internal suspend fun PppClient.receiveIpcpConfigureNak() {
    val received = IpcpConfigureNak()
    if (!tryReadingIpcp(received)) return

    when (ipcpState) {
        IpcpState.REQ_SENT, IpcpState.ACK_SENT -> {
            ipcpCounter.reset()
            if (isCompromisableIpcp(received)){
                compromiseIpcp(received)
                sendIpcpConfigureRequest()
            } else {
                parent.informUnableToCompromise(extractUncompromisableIpcp(received)!!, ::receiveIpcpConfigureNak)
                kill()
                return
            }
        }
        IpcpState.ACK_RCVD -> {
            if (isCompromisableIpcp(received)){
                compromiseIpcp(received)
                sendIpcpConfigureRequest()
            } else {
                parent.informUnableToCompromise(extractUncompromisableIpcp(received)!!, ::receiveIpcpConfigureNak)
                kill()
                return
            }
            ipcpState = IpcpState.REQ_SENT
        }
        IpcpState.OPENED -> {
            parent.informInvalidUnit(::receiveIpcpConfigureNak)
            kill()
            return
        }
    }
}

internal suspend fun PppClient.receiveIpcpConfigureReject() {
    val received = IpcpConfigureReject()
    if (!tryReadingIpcp(received)) return

    if (received.optionIpAddress != null) {
        if (networkSetting.mgIpAddress.isRejectable) {
            networkSetting.mgIpAddress.isRejected = true
            networkSetting.mgIpAddress.current = IpcpIpAddressOption()
        } else {
            parent.informOptionRejected(networkSetting.mgIpAddress.current)
            kill()
            return
        }
    }

    if (received.optionDnsAddress != null) {
        if (networkSetting.mgDnsAddress.isRejectable) {
            networkSetting.mgDnsAddress.isRejected = true
            networkSetting.mgDnsAddress.current = IpcpDnsAddressOption()
        } else {
            parent.informOptionRejected(networkSetting.mgDnsAddress.current)
            kill()
            return
        }
    }

    when (ipcpState) {
        IpcpState.REQ_SENT, IpcpState.ACK_SENT -> {
            ipcpCounter.reset()
            sendIpcpConfigureRequest()
        }
        IpcpState.ACK_RCVD -> {
            sendIpcpConfigureRequest()
            ipcpState = IpcpState.REQ_SENT
        }
        IpcpState.OPENED -> {
            parent.informInvalidUnit(::receiveIpcpConfigureReject)
            kill()
            return
        }
    }
}
