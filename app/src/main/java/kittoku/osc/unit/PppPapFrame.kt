package kittoku.osc.unit

import kittoku.osc.misc.DataUnitParsingError
import kittoku.osc.misc.IncomingBuffer
import kittoku.osc.misc.generateResolver
import java.nio.ByteBuffer
import kotlin.properties.Delegates


internal enum class PapCode(val value: Byte) {
    AUTHENTICATE_REQUEST(1),
    AUTHENTICATE_ACK(2),
    AUTHENTICATE_NAK(3);

    companion object {
        internal val resolve = generateResolver(values(), PapCode::value)
    }
}

internal abstract class PapFrame : PppFrame() {
    override val protocol = PppProtocol.PAP.value
}

internal class PapAuthenticateRequest : PapFrame() {
    override val code = PapCode.AUTHENTICATE_REQUEST.value

    override val validLengthRange = 6..Short.MAX_VALUE

    private var idLength by Delegates.observable(0) { _, _, new ->
        if (new !in 0..Byte.MAX_VALUE) throw DataUnitParsingError()
    }

    internal var idFiled = ByteArray(0)

    private var passwordLength by Delegates.observable(0) { _, _, new ->
        if (new !in 0..Byte.MAX_VALUE) throw DataUnitParsingError()
    }

    internal var passwordFiled = ByteArray(0)

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        idLength = bytes.getByte().toInt()
        idFiled = ByteArray(idLength).also { bytes.get(it) }
        passwordLength = bytes.getByte().toInt()
        passwordFiled = ByteArray(passwordLength).also { bytes.get(it) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.put(idLength.toByte())
        bytes.put(idFiled)
        bytes.put(passwordLength.toByte())
        bytes.put(passwordFiled)
    }

    override fun update() {
        idLength = idFiled.size
        passwordLength = passwordFiled.size
        _length = validLengthRange.first + idLength + passwordLength
    }
}

internal abstract class PapAuthenticateAcknowledgement : PapFrame() {
    override val validLengthRange = 4..Short.MAX_VALUE

    private var msgLength by Delegates.observable(0) { _, _, new ->
        if (new !in 0..Byte.MAX_VALUE) throw DataUnitParsingError()
    }

    private var message = ByteArray(0)

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        if (_length > 4) {
            msgLength = bytes.getByte().toInt()
            message = ByteArray(msgLength).also { bytes.get(it) }
        }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        if (_length > 4) {
            bytes.put(msgLength.toByte())
            bytes.put(message)
        }
    }

    override fun update() {
        msgLength = message.size
        _length = validLengthRange.first + msgLength
    }
}

internal class PapAuthenticateAck : PapAuthenticateAcknowledgement() {
    override val code = PapCode.AUTHENTICATE_ACK.value
}

internal class PapAuthenticateNak : PapAuthenticateAcknowledgement() {
    override val code = PapCode.AUTHENTICATE_NAK.value
}
