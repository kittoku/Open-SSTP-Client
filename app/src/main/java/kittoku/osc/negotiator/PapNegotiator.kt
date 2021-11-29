package kittoku.osc.negotiator

import kittoku.osc.layer.PppClient
import kittoku.osc.misc.DataUnitParsingError
import kittoku.osc.misc.informAuthenticationFailed
import kittoku.osc.misc.informDataUnitParsingError
import kittoku.osc.unit.PapAuthenticateAck
import kittoku.osc.unit.PapAuthenticateNak
import kittoku.osc.unit.PapAuthenticateRequest
import kittoku.osc.unit.PapFrame
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
        sending.idFiled = it.HOME_USERNAME.toByteArray(Charset.forName("US-ASCII"))
        sending.passwordFiled = it.HOME_PASSWORD.toByteArray(Charset.forName("US-ASCII"))
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
