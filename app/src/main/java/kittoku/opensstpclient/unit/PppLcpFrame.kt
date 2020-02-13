package kittoku.opensstpclient.unit

import kittoku.opensstpclient.DEFAULT_MRU
import kittoku.opensstpclient.misc.DataUnitParsingError
import kittoku.opensstpclient.misc.IncomingBuffer
import kittoku.opensstpclient.misc.generateResolver
import java.nio.ByteBuffer
import kotlin.math.min
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
    MS_CHAPv2(0x81.toByte());

    companion object {
        internal val resolve = generateResolver(values(), ChapAlgorithm::value)
    }
}

internal abstract class LcpOption<self : LcpOption<self>> : ByteLengthDataUnit(), Option<self> {
    internal abstract val type: Byte

    override val validLengthRange = 2..Byte.MAX_VALUE

    internal fun writeHeader(bytes: ByteBuffer) {
        bytes.put(type)
        bytes.put(getTypedLength())
    }
}

internal class LcpMruOption : LcpOption<LcpMruOption>() {
    override val type = LcpOptionType.MRU.value

    override val validLengthRange = 4..4

    internal var unitSize by Delegates.observable(DEFAULT_MRU.toShort()) { _, _, new ->
        if (new !in 1..4096) throw DataUnitParsingError()
    }

    override fun read(bytes: IncomingBuffer) {
        setTypedLength(bytes.getByte())
        unitSize = bytes.getShort()
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.putShort(unitSize)
    }

    override fun update() {
        _length = validLengthRange.first
    }

    override fun isMatchedTo(other: LcpMruOption): Boolean {
        return this.unitSize == other.unitSize
    }

    override fun copy(): LcpMruOption {
        val copied = LcpMruOption()
        copied.unitSize = this.unitSize
        return copied
    }
}

internal class LcpAuthOption : LcpOption<LcpAuthOption>() {
    override val type = LcpOptionType.AUTH.value

    override val validLengthRange = 4..Byte.MAX_VALUE

    internal var protocol: Short = AuthProtocol.PAP.value

    internal val holder = mutableListOf<Byte>()

    override fun read(bytes: IncomingBuffer) {
        setTypedLength(bytes.getByte())
        protocol = bytes.getShort()
        holder.clear()
        repeat(_length - validLengthRange.first) { holder.add(bytes.getByte()) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.putShort(protocol)
        holder.forEach { bytes.put(it) }
    }

    override fun update() {
        _length = holder.size + validLengthRange.first
    }

    override fun isMatchedTo(other: LcpAuthOption): Boolean {
        return this.protocol == other.protocol && this.holder == other.holder
    }

    override fun copy(): LcpAuthOption {
        val copied = LcpAuthOption()
        copied.protocol = this.protocol
        this.holder.forEach { copied.holder.add(it) }
        return copied
    }
}

internal class LcpUnknownOption(unknownType: Byte) : LcpOption<LcpUnknownOption>() {
    override val type = unknownType

    internal val holder = mutableListOf<Byte>()

    override fun read(bytes: IncomingBuffer) {
        holder.clear()
        setTypedLength(bytes.getByte())
        repeat(_length - validLengthRange.first) { holder.add(bytes.getByte()) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        holder.forEach { bytes.put(it) }
    }

    override fun update() {
        _length = holder.size + validLengthRange.first
    }

    override fun isMatchedTo(other: LcpUnknownOption): Boolean {
        // not meant to be used
        return this.holder == other.holder && this.type == other.type
    }

    override fun copy(): LcpUnknownOption {
        val copied = LcpUnknownOption(this.type)
        this.holder.forEach { copied.holder.add(it) }
        return copied
    }
}

internal abstract class LcpFrame : PppFrame() {
    override val protocol = PppProtocol.LCP.value
}

internal abstract class LcpConfigureFrame : LcpFrame() {
    internal var options = mutableListOf<LcpOption<*>>()
    // contains all options to be sent or received

    private inline fun <reified T : LcpOption<*>> delegateOption() =
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

    internal fun extractUnknownOption(): MutableList<LcpOption<*>> {
        val onlyUnknowns = mutableListOf<LcpOption<*>>()
        this.options.forEach { if (it is LcpUnknownOption) onlyUnknowns.add(it.copy()) }
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
            val option: LcpOption<*> = when (LcpOptionType.resolve(type)) {
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

internal abstract class LcpTerminateFrame : LcpFrame() {
    internal val holder = mutableListOf<Byte>()

    override fun read(bytes: IncomingBuffer) {
        holder.clear()
        readHeader(bytes)
        repeat(_length - validLengthRange.first) { holder.add(bytes.getByte()) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        holder.forEach { bytes.put(it) }
    }

    override fun update() {
        _length = validLengthRange.first + holder.size
    }
}

internal class LcpTerminateRequest : LcpTerminateFrame() {
    override val code = LcpCode.TERMINATE_REQUEST.value
}

internal class LcpTerminateAck : LcpTerminateFrame() {
    override val code = LcpCode.TERMINATE_ACK.value
}

internal class LcpCodeReject : LcpFrame() {
    override val code = LcpCode.CODE_REJECT.value

    internal var mru by Delegates.observable<Int>(validLengthRange.last - validLengthRange.first) { _, _, new ->
        if (new < validLengthRange.first) throw DataUnitParsingError()
    }

    internal val rejectedPacket = mutableListOf<Byte>()

    override fun read(bytes: IncomingBuffer) {
        rejectedPacket.clear()
        readHeader(bytes)
        repeat(_length - validLengthRange.first) { rejectedPacket.add(bytes.getByte()) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        rejectedPacket.slice(0..min(rejectedPacket.lastIndex, mru - 1)).forEach { bytes.put(it) }
    }

    override fun update() {
        _length = validLengthRange.first + min(rejectedPacket.size, mru)
    }
}

internal class LcpProtocolReject : LcpFrame() {
    override val code = LcpCode.PROTOCOL_REJECT.value

    override val validLengthRange = 6..Short.MAX_VALUE

    internal var mru by Delegates.observable<Int>(validLengthRange.last - validLengthRange.first) { _, _, new ->
        if (new < validLengthRange.first) throw DataUnitParsingError()
    }

    internal var rejectedProtocol: Short = 0

    internal val rejectedInformation = mutableListOf<Byte>()

    override fun read(bytes: IncomingBuffer) {
        rejectedInformation.clear()
        readHeader(bytes)
        repeat(_length - validLengthRange.first) { rejectedInformation.add(bytes.getByte()) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.putShort(rejectedProtocol)
        rejectedInformation.slice(0..min(rejectedInformation.lastIndex, mru - 1)).forEach { bytes.put(it) }
    }

    override fun update() {
        _length = validLengthRange.first + min(rejectedInformation.size, mru)
    }
}

internal abstract class LcpMagicNumberFrame : LcpFrame() {
    internal val holder = mutableListOf<Byte>()

    var magicNumber = 0

    override val validLengthRange = 8..Short.MAX_VALUE

    override fun read(bytes: IncomingBuffer) {
        holder.clear()
        readHeader(bytes)
        magicNumber = bytes.getInt()
        repeat(_length - validLengthRange.first) { holder.add(bytes.getByte()) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.putInt(magicNumber)
        holder.forEach { bytes.put(it) }
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

internal class LcpDiscardRequest : LcpMagicNumberFrame() {
    override val code = LcpCode.DISCARD_REQUEST.value
}

internal class LcpUnknownFrame(unknownCode: Byte) : LcpFrame() {
    override val code = unknownCode

    internal val holder = mutableListOf<Byte>()

    override fun read(bytes: IncomingBuffer) {
        holder.clear()
        setTypedLength(bytes.getShort())
        repeat(_length - validLengthRange.first) { holder.add(bytes.getByte()) }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        holder.forEach { bytes.put(it) }
    }

    override fun update() {
        _length = holder.size + validLengthRange.first
    }
}
