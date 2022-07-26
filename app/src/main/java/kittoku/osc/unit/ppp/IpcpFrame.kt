package kittoku.osc.unit.ppp

import kittoku.osc.unit.ppp.option.IpcpOptionPack
import java.nio.ByteBuffer


internal abstract class IpcpFrame : Frame() {
    override val protocol = PPP_PROTOCOL_IPCP
}

internal abstract class IpcpConfigureFrame : IpcpFrame() {
    override val length: Int
        get() = headerSize + options.length

    internal var options: IpcpOptionPack = IpcpOptionPack()

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        options = IpcpOptionPack(givenLength - length).also {
            it.read(buffer)
        }
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        options.write(buffer)
    }
}

internal class IpcpConfigureRequest : IpcpConfigureFrame() {
    override val code = LCP_CODE_CONFIGURE_REQUEST
}

internal class IpcpConfigureAck : IpcpConfigureFrame() {
    override val code = LCP_CODE_CONFIGURE_ACK
}

internal class IpcpConfigureNak : IpcpConfigureFrame() {
    override val code = LCP_CODE_CONFIGURE_NAK
}

internal class IpcpConfigureReject : IpcpConfigureFrame() {
    override val code = LCP_CODE_CONFIGURE_REJECT
}
