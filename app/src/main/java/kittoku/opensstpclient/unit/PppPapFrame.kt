package kittoku.opensstpclient.unit

import kittoku.opensstpclient.misc.DataUnitParsingError
import kittoku.opensstpclient.misc.IncomingBuffer
import kittoku.opensstpclient.misc.generateResolver
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

    internal val idFiled = mutableListOf<Byte>()

    private var passwordLength by Delegates.observable(0) { _, _, new ->
        if (new !in 0..Byte.MAX_VALUE) throw DataUnitParsingError()
    }

    internal val passwordFiled = mutableListOf<Byte>()

    override fun read(bytes: IncomingBuffer) {
        idFiled.clear()
        passwordFiled.clear()
        readHeader(bytes)
        idLength = bytes.getByte().toInt()
        repeat(idLength) { idFiled.add(bytes.getByte()) }
        passwordLength = bytes.getByte().toInt()
        repeat(passwordLength) { passwordFiled.add(bytes.getByte()) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.put(idLength.toByte())
        idFiled.forEach { bytes.put(it) }
        bytes.put(passwordLength.toByte())
        passwordFiled.forEach { bytes.put(it) }
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

    private val message = mutableListOf<Byte>()

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        if (_length > 4) {
            msgLength = bytes.getByte().toInt()
            repeat(msgLength) { message.add(bytes.getByte()) }
        }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        if (_length > 4) {
            bytes.put(msgLength.toByte())
            message.forEach { bytes.put(it) }
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
