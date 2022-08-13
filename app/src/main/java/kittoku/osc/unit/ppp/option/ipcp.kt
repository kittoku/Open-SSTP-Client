package kittoku.osc.unit.ppp.option

import kittoku.osc.extension.probeByte
import java.nio.ByteBuffer


internal const val OPTION_TYPE_IPCP_IP: Byte = 0x03
internal const val OPTION_TYPE_IPCP_DNS = 0x81.toByte()


internal class IpcpAddressOption(override val type: Byte) : Option() {
    internal val address = ByteArray(4)
    override val length = headerSize + address.size

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        buffer.get(address)
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        buffer.put(address)
    }
}

internal class IpcpOptionPack(givenLength: Int = 0) : OptionPack(givenLength) {
    internal var ipOption: IpcpAddressOption? = null
    internal var dnsOption: IpcpAddressOption? = null

    override val knownOptions: List<Option>
        get() = mutableListOf<Option>().also { options ->
            ipOption?.also { options.add(it) }
            dnsOption?.also { options.add(it) }
        }

    override fun retrieveOption(buffer: ByteBuffer): Option {
        val option = when (val type = buffer.probeByte(0)) {
            OPTION_TYPE_IPCP_IP -> IpcpAddressOption(type).also { ipOption = it }

            OPTION_TYPE_IPCP_DNS -> IpcpAddressOption(type).also { dnsOption = it }

            else -> UnknownOption(type)
        }

        option.read(buffer)

        return option
    }
}
