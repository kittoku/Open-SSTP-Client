package kittoku.osc.unit

import kittoku.osc.misc.IncomingBuffer
import java.nio.ByteBuffer


internal const val PPP_HEADER = 0xFF03.toShort()

internal const val PPP_PROTOCOL_LCP = 0xC021.toShort()
internal const val PPP_PROTOCOL_PAP = 0xC023.toShort()
internal const val PPP_PROTOCOL_CHAP = 0xC223.toShort()
internal const val PPP_PROTOCOL_IPCP = 0x8021.toShort()
internal const val PPP_PROTOCOL_IP = 0x0021.toShort()
internal const val PPP_PROTOCOL_IPV6CP = 0x8057.toShort()
internal const val PPP_PROTOCOL_IPV6 = 0x0057.toShort()

internal abstract class PppFrame : ShortLengthDataUnit() {
    internal abstract val code: Byte

    internal abstract val protocol: Short

    internal var id: Byte = 0

    override val validLengthRange = 4..Short.MAX_VALUE

    internal fun readHeader(bytes: IncomingBuffer) {
        id = bytes.getByte()
        setTypedLength(bytes.getShort())
    }

    internal fun writeHeader(bytes: ByteBuffer) {
        bytes.putShort(PPP_HEADER)
        bytes.putShort(protocol)
        bytes.put(code)
        bytes.put(id)
        bytes.putShort(getTypedLength())
    }
}
