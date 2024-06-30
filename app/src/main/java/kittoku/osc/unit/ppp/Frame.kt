package kittoku.osc.unit.ppp

import kittoku.osc.debug.assertAlways
import kittoku.osc.extension.toIntAsUShort
import kittoku.osc.unit.DataUnit
import kittoku.osc.unit.sstp.SSTP_PACKET_TYPE_DATA
import java.nio.ByteBuffer


internal const val PPP_HDLC_HEADER = 0xFF03.toShort()
internal const val PPP_HEADER_SIZE = 4 // code, id, and frame length

internal const val PPP_PROTOCOL_LCP = 0xC021.toShort()
internal const val PPP_PROTOCOL_PAP = 0xC023.toShort()
internal const val PPP_PROTOCOL_CHAP = 0xC223.toShort()
internal const val PPP_PROTOCOL_EAP = 0xC227.toShort()
internal const val PPP_PROTOCOL_IPCP = 0x8021.toShort()
internal const val PPP_PROTOCOL_IPv6CP = 0x8057.toShort()
internal const val PPP_PROTOCOL_IP = 0x0021.toShort()
internal const val PPP_PROTOCOL_IPv6 = 0x0057.toShort()


internal abstract class Frame : DataUnit() {
    internal abstract val code: Byte
    internal abstract val protocol: Short

    private val offsetSize = 8 // from SSTP header to PPP HDLC header
    protected val headerSize = offsetSize + PPP_HEADER_SIZE

    protected var givenLength = 0

    internal var id: Byte = 0

    protected fun readHeader(buffer: ByteBuffer) {
        assertAlways(buffer.short == SSTP_PACKET_TYPE_DATA)
        givenLength = buffer.short.toIntAsUShort()

        assertAlways(buffer.short == PPP_HDLC_HEADER)
        assertAlways(buffer.short == protocol)
        assertAlways(buffer.get() == code)
        id = buffer.get()
        assertAlways(buffer.short.toIntAsUShort()+ offsetSize == givenLength)
    }

    protected fun writeHeader(buffer: ByteBuffer) {
        buffer.putShort(SSTP_PACKET_TYPE_DATA)
        buffer.putShort(length.toShort())

        buffer.putShort(PPP_HDLC_HEADER)
        buffer.putShort(protocol)
        buffer.put(code)
        buffer.put(id)
        buffer.putShort((length - offsetSize).toShort())
    }
}
