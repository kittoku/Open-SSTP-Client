package kittoku.osc.unit.ppp.auth

import kittoku.osc.unit.ppp.Frame
import kittoku.osc.unit.ppp.PPP_PROTOCOL_EAP
import java.nio.ByteBuffer


internal const val EAP_CODE_REQUEST: Byte = 1
internal const val EAP_CODE_RESPONSE: Byte = 2
internal const val EAP_CODE_SUCCESS: Byte = 3
internal const val EAP_CODE_FAILURE: Byte = 4

internal const val EAP_TYPE_IDENTITY: Byte = 1
internal const val EAP_TYPE_NOTIFICATION: Byte = 2
internal const val EAP_TYPE_NAK: Byte = 3
internal const val EAP_TYPE_MS_AUTH: Byte = 26 // MSCHAPV2

internal abstract class EAPFrame : Frame() {
    override val protocol = PPP_PROTOCOL_EAP
}

internal abstract class EAPDataFrame : EAPFrame() {
    override val length: Int
        get() = headerSize + 1 + typeData.size

    internal var type: Byte = 0
    internal var typeData = ByteArray(0)

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        type = buffer.get()
        typeData = ByteArray(givenLength - length)
        buffer.get(typeData)
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        buffer.put(type)
        buffer.put(typeData)
    }
}

internal class EAPRequest : EAPDataFrame() {
    override val code = EAP_CODE_REQUEST
}

internal class EAPResponse : EAPDataFrame() {
    override val code = EAP_CODE_RESPONSE
}

internal abstract class EAPResultFrame : EAPFrame() {
    override val length = headerSize

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)
    }
}

internal class EAPSuccess : EAPResultFrame() {
    override val code = EAP_CODE_SUCCESS
}

internal class EAPFailure : EAPResultFrame() {
    override val code = EAP_CODE_FAILURE
}
