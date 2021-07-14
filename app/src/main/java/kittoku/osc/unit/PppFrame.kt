package kittoku.osc.unit

import kittoku.osc.misc.IncomingBuffer
import kittoku.osc.misc.generateResolver
import java.nio.ByteBuffer


internal const val PPP_HEADER = 0xFF03.toShort()

internal enum class PppProtocol(val value: Short) {
    LCP(0xC021.toShort()),
    PAP(0xC023.toShort()),
    CHAP(0xC223.toShort()),
    IPCP(0x8021.toShort()),
    IP(0x0021.toShort()),
    IPV6CP(0x8057.toShort()),
    IPV6(0x0057.toShort());

    companion object {
        internal val resolve = generateResolver(values(), PppProtocol::value)
    }
}

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
