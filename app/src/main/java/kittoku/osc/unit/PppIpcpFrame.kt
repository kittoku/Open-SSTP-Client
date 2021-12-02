package kittoku.osc.unit

import kittoku.osc.misc.DataUnitParsingError
import kittoku.osc.misc.IncomingBuffer
import java.nio.ByteBuffer
import kotlin.properties.Delegates


internal const val IPCP_CODE_CONFIGURE_REQUEST: Byte = 1
internal const val IPCP_CODE_CONFIGURE_ACK: Byte = 2
internal const val IPCP_CODE_CONFIGURE_NAK: Byte = 3
internal const val IPCP_CODE_CONFIGURE_REJECT: Byte = 4
internal const val IPCP_CODE_TERMINATE_REQUEST: Byte = 5
internal const val IPCP_CODE_TERMINATE_ACK: Byte = 6
internal const val IPCP_CODE_CODE_REJECT: Byte = 7

internal const val IPCP_OPTION_TYPE_IP: Byte = 0x03
internal const val IPCP_OPTION_TYPE_DNS = 0x81.toByte()

internal abstract class IpcpOption : ByteLengthDataUnit() {
    internal abstract val type: Byte

    override val validLengthRange = 2..Byte.MAX_VALUE

    internal fun writeHeader(bytes: ByteBuffer) {
        bytes.put(type)
        bytes.put(getTypedLength())
    }
}

internal class IpcpIpOption : IpcpOption() {
    override val type = IPCP_OPTION_TYPE_IP

    override val validLengthRange = 6..6

    internal val address = ByteArray(4)

    override fun read(bytes: IncomingBuffer) {
        setTypedLength(bytes.getByte())
        bytes.get(address)
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.put(address)
    }

    override fun update() {
        _length = validLengthRange.first
    }
}

internal class IpcpDnsOption : IpcpOption() {
    override val type = IPCP_OPTION_TYPE_DNS

    override val validLengthRange = 6..6

    internal val address = ByteArray(4)

    override fun read(bytes: IncomingBuffer) {
        setTypedLength(bytes.getByte())
        bytes.get(address)
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        bytes.put(address)
    }

    override fun update() {
        _length = validLengthRange.first
    }
}

internal class IpcpUnknownOption(unknownType: Byte) : IpcpOption() {
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

internal abstract class IpcpFrame : PppFrame() {
    override val protocol = PPP_PROTOCOL_IPCP
}

internal abstract class IpcpConfigureFrame : IpcpFrame() {
    internal var options = mutableListOf<IpcpOption>()
    // contains all options to be sent or received

    private inline fun <reified T : IpcpOption> delegateOption() =
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

    internal var optionIp by delegateOption<IpcpIpOption>()
    internal var optionDns by delegateOption<IpcpDnsOption>()

    internal val hasUnknownOption: Boolean
        get() {
            options.forEach { if (it is IpcpUnknownOption) return true }

            return false
        }

    internal fun extractUnknownOption(): MutableList<IpcpOption> {
        val onlyUnknowns = mutableListOf<IpcpOption>()
        this.options.forEach { if (it is IpcpUnknownOption) onlyUnknowns.add(it) }
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
            val option: IpcpOption = when (type) {
                IPCP_OPTION_TYPE_IP -> IpcpIpOption().also { optionIp = it }
                IPCP_OPTION_TYPE_DNS -> IpcpDnsOption().also { optionDns = it }
                else -> IpcpUnknownOption(type).also { options.add(it) }
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

internal class IpcpConfigureRequest : IpcpConfigureFrame() {
    override val code = IPCP_CODE_CONFIGURE_REQUEST
}

internal class IpcpConfigureAck : IpcpConfigureFrame() {
    override val code = IPCP_CODE_CONFIGURE_ACK
}

internal class IpcpConfigureNak : IpcpConfigureFrame() {
    override val code = IPCP_CODE_CONFIGURE_NAK
}

internal class IpcpConfigureReject : IpcpConfigureFrame() {
    override val code = IPCP_CODE_CONFIGURE_REJECT
}
