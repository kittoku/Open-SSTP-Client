package kittoku.osc.unit

import kittoku.osc.DEFAULT_MRU
import kittoku.osc.misc.DataUnitParsingError
import kittoku.osc.misc.IncomingBuffer
import kittoku.osc.misc.generateResolver
import java.nio.ByteBuffer
import kotlin.properties.Delegates


internal enum class LcpCode(val value: Byte) {
    CONFIGURE_REQUEST(1),
    CONFIGURE_ACK(2),
    CONFIGURE_NAK(3),
    CONFIGURE_REJECT(4),
    TERMINATE_REQUEST(5),
    TERMINATE_ACK(6),
    CODE_REJECT(7),
    PROTOCOL_REJECT(8),
    ECHO_REQUEST(9),
    ECHO_REPLY(10),
    DISCARD_REQUEST(11);

    companion object {
        internal val resolve = generateResolver(values(), LcpCode::value)
    }
}

internal enum class LcpOptionType(val value: Byte) {
    MRU(1),
    AUTH(3);

    companion object {
        internal val resolve = generateResolver(values(), LcpOptionType::value)
    }
}

internal enum class AuthProtocol(val value: Short) {
    PAP(0xC023.toShort()),
    CHAP(0xC223.toShort());

    companion object {
        internal val resolve = generateResolver(values(), AuthProtocol::value)
    }
}

internal enum class ChapAlgorithm(val value: Byte) {
    MSCHAPv2(0x81.toByte());

    companion object {
        internal val resolve = generateResolver(values(), ChapAlgorithm::value)
    }
}

internal abstract class LcpOption : ByteLengthDataUnit() {
    internal abstract val type: Byte

    override val validLengthRange = 2..Byte.MAX_VALUE

    internal fun writeHeader(bytes: ByteBuffer) {
        bytes.put(type)
        bytes.put(getTypedLength())
    }
}

internal class LcpMruOption : LcpOption() {
    override val type = LcpOptionType.MRU.value

    override val validLengthRange = 4..4

    internal var unitSize by Delegates.observable(DEFAULT_MRU) { _, _, new ->
        if (new < 0) throw DataUnitParsingError()
    }

    override fun read(bytes: IncomingBuffer) {
        setTypedLength(bytes.getByte())
        unitSize = bytes.getShort().toInt()
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.putShort(unitSize.toShort())
    }

    override fun update() {
        _length = validLengthRange.first
    }
}

internal class LcpAuthOption : LcpOption() {
    override val type = LcpOptionType.AUTH.value

    override val validLengthRange = 4..Byte.MAX_VALUE

    internal var protocol: Short = AuthProtocol.PAP.value

    internal var holder = ByteArray(0)

    override fun read(bytes: IncomingBuffer) {
        setTypedLength(bytes.getByte())
        protocol = bytes.getShort()
        holder = ByteArray(_length - validLengthRange.first).also { bytes.get(it) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.putShort(protocol)
        bytes.put(holder)
    }

    override fun update() {
        _length = holder.size + validLengthRange.first
    }
}

internal class LcpUnknownOption(unknownType: Byte) : LcpOption() {
    override val type = unknownType

    internal var holder = ByteArray(0)

    override fun read(bytes: IncomingBuffer) {
        setTypedLength(bytes.getByte())
        holder = ByteArray(_length - validLengthRange.first).also { bytes.get(it) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.put(holder)
    }

    override fun update() {
        _length = holder.size + validLengthRange.first
    }
}

internal abstract class LcpFrame : PppFrame() {
    override val protocol = PppProtocol.LCP.value
}

internal abstract class LcpConfigureFrame : LcpFrame() {
    internal var options = mutableListOf<LcpOption>()
    // contains all options to be sent or received

    private inline fun <reified T : LcpOption> delegateOption() =
        Delegates.observable<T?>(null) { _, old, new ->
            if (old != null) {
                if (new == null) { // erase option
                    for (i in options.indices) {
                        if (options[i] is T) {
                            options.removeAt(i)
                            break
                        }
                    }
                } else { // update option
                    for (i in options.indices) {
                        if (options[i] is T) {
                            options[i] = new
                            break
                        }
                    }
                }
            } else if (new != null) { // install option
                options.add(new)
            }
        }

    internal var optionMru by delegateOption<LcpMruOption>()
    internal var optionAuth by delegateOption<LcpAuthOption>()

    internal val hasUnknownOption: Boolean
        get() {
            options.forEach { if (it is LcpUnknownOption) return true }

            return false
        }

    internal fun extractUnknownOption(): MutableList<LcpOption> {
        val onlyUnknowns = mutableListOf<LcpOption>()
        this.options.forEach { if (it is LcpUnknownOption) onlyUnknowns.add(it) }
        return onlyUnknowns
    }

    override fun read(bytes: IncomingBuffer) {
        options.clear()
        readHeader(bytes)
        var remaining = _length - validLengthRange.first

        while (true) {
            when (remaining) {
                0 -> return
                in Int.MIN_VALUE..-1 -> throw DataUnitParsingError()
            }

            val type = bytes.getByte()
            val option: LcpOption = when (LcpOptionType.resolve(type)) {
                LcpOptionType.MRU -> LcpMruOption().also { optionMru = it }
                LcpOptionType.AUTH -> LcpAuthOption().also { optionAuth = it }
                else -> LcpUnknownOption(type).also { options.add(it) }
            }

            option.read(bytes)
            remaining -= option._length
        }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        options.forEach { it.write(bytes) }
    }

    override fun update() {
        _length = validLengthRange.first
        options.forEach {
            it.update()
            _length += it._length
        }
    }
}

internal class LcpConfigureRequest : LcpConfigureFrame() {
    override val code = LcpCode.CONFIGURE_REQUEST.value
}

internal class LcpConfigureAck : LcpConfigureFrame() {
    override val code = LcpCode.CONFIGURE_ACK.value
}

internal class LcpConfigureNak : LcpConfigureFrame() {
    override val code = LcpCode.CONFIGURE_NAK.value
}

internal class LcpConfigureReject : LcpConfigureFrame() {
    override val code = LcpCode.CONFIGURE_REJECT.value
}

internal abstract class LcpMagicNumberFrame : LcpFrame() {
    internal var magicNumber = 0

    internal var holder = ByteArray(0)

    override val validLengthRange = 8..Short.MAX_VALUE

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        magicNumber = bytes.getInt()
        holder = ByteArray(_length - validLengthRange.first).also { bytes.get(it) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.putInt(magicNumber)
        bytes.put(holder)
    }

    override fun update() {
        _length = validLengthRange.first + holder.size
    }
}

internal class LcpEchoRequest : LcpMagicNumberFrame() {
    override val code = LcpCode.ECHO_REQUEST.value
}

internal class LcpEchoReply : LcpMagicNumberFrame() {
    override val code = LcpCode.ECHO_REPLY.value
}

internal class LcpProtocolReject : LcpFrame() {
    internal var rejectedProtocol: Short = 0

    internal var holder = ByteArray(0)

    override val code = LcpCode.PROTOCOL_REJECT.value

    override val validLengthRange = 6..Short.MAX_VALUE

    override fun read(bytes: IncomingBuffer) {
        readHeader(bytes)
        rejectedProtocol = bytes.getShort()
        holder = ByteArray(_length - validLengthRange.first).also { bytes.get(it) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.putShort(rejectedProtocol)
        bytes.put(holder)
    }

    override fun update() {
        _length = validLengthRange.first + holder.size
    }

}
