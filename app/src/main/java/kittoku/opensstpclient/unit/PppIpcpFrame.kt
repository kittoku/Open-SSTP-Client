package kittoku.opensstpclient.unit

import kittoku.opensstpclient.misc.DataUnitParsingError
import kittoku.opensstpclient.misc.IncomingBuffer
import kittoku.opensstpclient.misc.generateResolver
import kittoku.opensstpclient.misc.isSame
import java.nio.ByteBuffer
import kotlin.math.min
import kotlin.properties.Delegates


internal enum class IpcpCode(val value: Byte) {
    CONFIGURE_REQUEST(1),
    CONFIGURE_ACK(2),
    CONFIGURE_NAK(3),
    CONFIGURE_REJECT(4),
    TERMINATE_REQUEST(5),
    TERMINATE_ACK(6),
    CODE_REJECT(7);

    companion object {
        internal val resolve = generateResolver(values(), IpcpCode::value)
    }
}

internal enum class IpcpOptionType(val value: Byte) {
    IP_ADDRESS(0x03),
    DNS_ADDRESS(0x81.toByte());

    companion object {
        internal val resolve = generateResolver(values(), IpcpOptionType::value)
    }
}

internal abstract class IpcpOption<self : IpcpOption<self>> : ByteLengthDataUnit(), Option<self> {
    internal abstract val type: Byte

    override val validLengthRange = 2..Byte.MAX_VALUE

    internal fun writeHeader(bytes: ByteBuffer) {
        bytes.put(type)
        bytes.put(getTypedLength())
    }
}

internal class IpcpIpAddressOption : IpcpOption<IpcpIpAddressOption>() {
    override val type = IpcpOptionType.IP_ADDRESS.value

    override val validLengthRange = 6..6

    internal val address = ByteArray(4)

    override fun read(bytes: IncomingBuffer) {
        setTypedLength(bytes.getByte())
        repeat(address.size) { address[it] = bytes.getByte() }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        repeat(address.size) { bytes.put(address[it]) }
    }

    override fun update() {
        _length = validLengthRange.first
    }

    override fun isMatchedTo(other: IpcpIpAddressOption): Boolean =
        this.address.isSame(other.address)

    override fun copy(): IpcpIpAddressOption {
        val copied = IpcpIpAddressOption()
        repeat(address.size) { copied.address[it] = this.address[it] }
        return copied
    }
}

internal class IpcpDnsAddressOption : IpcpOption<IpcpDnsAddressOption>() {
    override val type = IpcpOptionType.DNS_ADDRESS.value

    override val validLengthRange = 6..6

    internal val address = ByteArray(4)

    override fun read(bytes: IncomingBuffer) {
        setTypedLength(bytes.getByte())
        repeat(address.size) { address[it] = bytes.getByte() }
    }

    override fun write(bytes: ByteBuffer) {
        writeHeader(bytes)
        repeat(address.size) { bytes.put(address[it]) }
    }

    override fun update() {
        _length = validLengthRange.first
    }

    override fun isMatchedTo(other: IpcpDnsAddressOption): Boolean = this.address.isSame(other.address)

    override fun copy(): IpcpDnsAddressOption {
        val copied = IpcpDnsAddressOption()
        repeat(address.size) { copied.address[it] = this.address[it] }
        return copied
    }
}

internal class IpcpUnknownOption(unknownType: Byte) : IpcpOption<IpcpUnknownOption>() {
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

    override fun isMatchedTo(other: IpcpUnknownOption): Boolean {
        // not meant to be used
        return this.holder == other.holder && this.type == other.type
    }

    override fun copy(): IpcpUnknownOption {
        val copied = IpcpUnknownOption(this.type)
        this.holder.forEach { copied.holder.add(it) }
        return copied
    }
}

internal abstract class IpcpFrame : PppFrame() {
    override val protocol = PppProtocol.IPCP.value
}

internal abstract class IpcpConfigureFrame : IpcpFrame() {
    internal var options = mutableListOf<IpcpOption<*>>()
    // contains all options to be sent or received

    private inline fun <reified T : IpcpOption<*>> delegateOption() =
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

    internal var optionIpAddress by delegateOption<IpcpIpAddressOption>()
    internal var optionDnsAddress by delegateOption<IpcpDnsAddressOption>()

    internal val hasUnknownOption: Boolean
        get() {
            options.forEach { if (it is IpcpUnknownOption) return true }

            return false
        }

    internal fun extractUnknownOption(): MutableList<IpcpOption<*>> {
        val onlyUnknowns = mutableListOf<IpcpOption<*>>()
        this.options.forEach { if (it is IpcpUnknownOption) onlyUnknowns.add(it.copy()) }
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
            val option: IpcpOption<*> = when (IpcpOptionType.resolve(type)) {
                IpcpOptionType.IP_ADDRESS -> IpcpIpAddressOption().also { optionIpAddress = it }
                IpcpOptionType.DNS_ADDRESS -> IpcpDnsAddressOption().also { optionDnsAddress = it }
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
    override val code = IpcpCode.CONFIGURE_REQUEST.value
}

internal class IpcpConfigureAck : IpcpConfigureFrame() {
    override val code = IpcpCode.CONFIGURE_ACK.value
}

internal class IpcpConfigureNak : IpcpConfigureFrame() {
    override val code = IpcpCode.CONFIGURE_NAK.value
}

internal class IpcpConfigureReject : IpcpConfigureFrame() {
    override val code = IpcpCode.CONFIGURE_REJECT.value
}

internal abstract class IpcpTerminateFrame : IpcpFrame() {
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

internal class IpcpTerminateRequest : IpcpTerminateFrame() {
    override val code = IpcpCode.TERMINATE_REQUEST.value
}

internal class IpcpTerminateAck : IpcpTerminateFrame() {
    override val code = IpcpCode.TERMINATE_ACK.value
}

internal class IpcpCodeReject : IpcpFrame() {
    override val code = IpcpCode.CODE_REJECT.value

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
