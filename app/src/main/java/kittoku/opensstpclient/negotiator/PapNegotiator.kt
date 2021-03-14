package kittoku.opensstpclient.negotiator

import kittoku.opensstpclient.layer.PppClient
import kittoku.opensstpclient.misc.DataUnitParsingError
import kittoku.opensstpclient.misc.informAuthenticationFailed
import kittoku.opensstpclient.misc.informDataUnitParsingError
import kittoku.opensstpclient.unit.PapAuthenticateAck
import kittoku.opensstpclient.unit.PapAuthenticateNak
import kittoku.opensstpclient.unit.PapAuthenticateRequest
import kittoku.opensstpclient.unit.PapFrame
import java.nio.charset.Charset


internal fun PppClient.tryReadingPap(frame: PapFrame): Boolean {
    try {
        frame.read(incomingBuffer)
    } catch (e: DataUnitParsingError) {
        parent.informDataUnitParsingError(frame, e)
        kill()
        return false
    }

    if (frame is PapAuthenticateAck || frame is PapAuthenticateNak) {
        if (frame.id != currentAuthRequestId) return false
    }

    return true
}

internal fun PppClient.sendPapRequest() {
    globalIdentifier++
    currentAuthRequestId = globalIdentifier
    val sending = PapAuthenticateRequest()
    sending.id = currentAuthRequestId
    parent.networkSetting.also {
        sending.idFiled = it.HOME_USER.toByteArray(Charset.forName("US-ASCII"))
        sending.passwordFiled = it.HOME_PASS.toByteArray(Charset.forName("US-ASCII"))
    }
    sending.update()
    parent.controlQueue.add(sending)

    authTimer.reset()
}

internal fun PppClient.receivePapAuthenticateAck() {
    val received = PapAuthenticateAck()
    if (!tryReadingPap(received)) return

    if (!isAuthFinished) {
        isAuthFinished = true
    }
}

internal fun PppClient.receivePapAuthenticateNak() {
    val received = PapAuthenticateAck()
    if (!tryReadingPap(received)) return

    if (!isAuthFinished) {
        parent.informAuthenticationFailed(::receivePapAuthenticateNak)
        kill()
        return
    }
}
