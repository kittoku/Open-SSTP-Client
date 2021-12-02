package kittoku.osc.unit

import kittoku.osc.DEFAULT_MRU
import kittoku.osc.misc.DataUnitParsingError
import kittoku.osc.misc.IncomingBuffer
import java.nio.ByteBuffer
import kotlin.properties.Delegates


internal const val LCP_CODE_CONFIGURE_REQUEST: Byte = 1
internal const val LCP_CODE_CONFIGURE_ACK: Byte = 2
internal const val LCP_CODE_CONFIGURE_NAK: Byte = 3
internal const val LCP_CODE_CONFIGURE_REJECT: Byte = 4
internal const val LCP_CODE_TERMINATE_REQUEST: Byte = 5
internal const val LCP_CODE_TERMINATE_ACK: Byte = 6
internal const val LCP_CODE_CODE_REJECT: Byte = 7
internal const val LCP_CODE_PROTOCOL_REJECT: Byte = 8
internal const val LCP_CODE_ECHO_REQUEST: Byte = 9
internal const val LCP_CODE_ECHO_REPLY: Byte = 10
internal const val LCP_CODE_DISCARD_REQUEST: Byte = 11

internal const val LCP_OPTION_TYPE_MRU: Byte = 1
internal const val LCP_OPTION_TYPE_AUTH: Byte = 3

internal const val AUTH_PROTOCOL_PAP = 0xC023.toShort()
internal const val AUTH_PROTOCOL_CHAP = 0xC223.toShort()

internal const val CHAP_ALGORITHM_MSCHAPv2 = 0x81.toByte()

internal abstract class LcpOption : ByteLengthDataUnit() {
    internal abstract val type: Byte

    override val validLengthRange = 2..Byte.MAX_VALUE

    internal fun writeHeader(bytes: ByteBuffer) {
        bytes.put(type)
        bytes.put(getTypedLength())
    }
}

internal class LcpMruOption : LcpOption() {
    override val type = LCP_OPTION_TYPE_MRU

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
    override val type = LCP_OPTION_TYPE_AUTH

    override val validLengthRange = 4..Byte.MAX_VALUE

    internal var protocol: Short = AUTH_PROTOCOL_PAP

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
    override val protocol = PPP_PROTOCOL_LCP
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
            val option: LcpOption = when (type) {
                LCP_OPTION_TYPE_MRU -> LcpMruOption().also { optionMru = it }
                LCP_OPTION_TYPE_AUTH -> LcpAuthOption().also { optionAuth = it }
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
    override val code = LCP_CODE_CONFIGURE_REQUEST
}

internal class LcpConfigureAck : LcpConfigureFrame() {
    override val code = LCP_CODE_CONFIGURE_ACK
}

internal class LcpConfigureNak : LcpConfigureFrame() {
    override val code = LCP_CODE_CONFIGURE_NAK
}

internal class LcpConfigureReject : LcpConfigureFrame() {
    override val code = LCP_CODE_CONFIGURE_REJECT
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
    override val code = LCP_CODE_ECHO_REQUEST
}

internal class LcpEchoReply : LcpMagicNumberFrame() {
    override val code = LCP_CODE_ECHO_REPLY
}

internal class LcpProtocolReject : LcpFrame() {
    internal var rejectedProtocol: Short = 0

    internal var holder = ByteArray(0)

    override val code = LCP_CODE_PROTOCOL_REJECT

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
