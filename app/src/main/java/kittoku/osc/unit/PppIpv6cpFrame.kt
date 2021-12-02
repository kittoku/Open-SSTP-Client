package kittoku.osc.unit

import kittoku.osc.misc.DataUnitParsingError
import kittoku.osc.misc.IncomingBuffer
import java.nio.ByteBuffer
import kotlin.properties.Delegates


internal const val IPv6CP_CODE_CONFIGURE_REQUEST: Byte = 1
internal const val IPv6CP_CODE_CONFIGURE_ACK: Byte = 2
internal const val IPv6CP_CODE_CONFIGURE_NAK: Byte = 3
internal const val IPv6CP_CODE_CONFIGURE_REJECT: Byte = 4
internal const val IPv6CP_CODE_TERMINATE_REQUEST: Byte = 5
internal const val IPv6CP_CODE_TERMINATE_ACK: Byte = 6
internal const val IPv6CP_CODE_CODE_REJECT: Byte = 7

internal const val IPv6CP_OPTION_TYPE_IDENTIFIER: Byte = 0x01

internal abstract class Ipv6cpOption : ByteLengthDataUnit() {
    internal abstract val type: Byte

    override val validLengthRange = 2..Byte.MAX_VALUE

    internal fun writeHeader(bytes: ByteBuffer) {
        bytes.put(type)
        bytes.put(getTypedLength())
    }
}

internal class Ipv6cpIdentifierOption : Ipv6cpOption() {
    override val type = IPv6CP_OPTION_TYPE_IDENTIFIER

    override val validLengthRange = 10..10

    internal val identifier = ByteArray(8)

    override fun read(bytes: IncomingBuffer) {
        setTypedLength(bytes.getByte())
        bytes.get(identifier)
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.put(identifier)
    }

    override fun update() {
        _length = validLengthRange.first
    }
}

internal class Ipv6cpUnknownOption(unknownType: Byte) : Ipv6cpOption() {
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

internal abstract class Ipv6cpFrame : PppFrame() {
    override val protocol = PPP_PROTOCOL_IPV6CP
}

internal abstract class Ipv6cpConfigureFrame : Ipv6cpFrame() {
    internal var options = mutableListOf<Ipv6cpOption>()
    // contains all options to be sent or received

    private inline fun <reified T : Ipv6cpOption> delegateOption() =
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

    internal var optionIdentifier by delegateOption<Ipv6cpIdentifierOption>()

    internal val hasUnknownOption: Boolean
        get() {
            options.forEach { if (it is Ipv6cpUnknownOption) return true }

            return false
        }

    internal fun extractUnknownOption(): MutableList<Ipv6cpOption> {
        val onlyUnknowns = mutableListOf<Ipv6cpOption>()
        this.options.forEach { if (it is Ipv6cpUnknownOption) onlyUnknowns.add(it) }
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
            val option: Ipv6cpOption = when (type) {
                IPv6CP_OPTION_TYPE_IDENTIFIER -> Ipv6cpIdentifierOption().also {
                    optionIdentifier = it
                }
                else -> Ipv6cpUnknownOption(type).also { options.add(it) }
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

internal class Ipv6cpConfigureRequest : Ipv6cpConfigureFrame() {
    override val code = IPv6CP_CODE_CONFIGURE_REQUEST
}

internal class Ipv6cpConfigureAck : Ipv6cpConfigureFrame() {
    override val code = IPv6CP_CODE_CONFIGURE_ACK
}

internal class Ipv6cpConfigureNak : Ipv6cpConfigureFrame() {
    override val code = IPv6CP_CODE_CONFIGURE_NAK
}

internal class Ipv6cpConfigureReject : Ipv6cpConfigureFrame() {
    override val code = IPv6CP_CODE_CONFIGURE_REJECT
}
