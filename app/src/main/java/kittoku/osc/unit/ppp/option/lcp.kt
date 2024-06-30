package kittoku.osc.unit.ppp.option

import kittoku.osc.debug.assertAlways
import kittoku.osc.extension.probeByte
import kittoku.osc.extension.toIntAsUShort
import java.nio.ByteBuffer


internal const val OPTION_TYPE_LCP_MRU: Byte = 1
internal const val OPTION_TYPE_LCP_AUTH: Byte = 3

internal const val CHAP_ALGORITHM_MSCHAPv2 = 0x81.toByte()


internal class MRUOption : Option() {
    override val type = OPTION_TYPE_LCP_MRU
    override val length = headerSize + Short.SIZE_BYTES

    internal var unitSize = 0

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        unitSize = buffer.short.toIntAsUShort()
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        buffer.putShort(unitSize.toShort())
    }
}

internal class AuthOption : Option() {
    override val type = OPTION_TYPE_LCP_AUTH
    internal var protocol: Short = 0
    internal var holder = ByteArray(0)
    override val length: Int
        get() = headerSize + Short.SIZE_BYTES + holder.size

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        protocol = buffer.getShort()

        val holderSize = givenLength - length
        assertAlways(holderSize >= 0)

        if (holderSize > 0) {
            holder = ByteArray(holderSize).also { buffer.get(it) }
        }
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        buffer.putShort(protocol)
        buffer.put(holder)
    }
}

internal class LCPOptionPack(givenLength: Int = 0) : OptionPack(givenLength) {
    internal var mruOption: MRUOption? = null
    internal var authOption: AuthOption? = null

    override val knownOptions: List<Option>
        get() = mutableListOf<Option>().also { options ->
            mruOption?.also { options.add(it) }
            authOption?.also { options.add(it) }
        }

    override fun retrieveOption(buffer: ByteBuffer): Option {
        val option = when (val type = buffer.probeByte(0)) {
            OPTION_TYPE_LCP_MRU -> MRUOption().also { mruOption = it }
            OPTION_TYPE_LCP_AUTH -> AuthOption().also { authOption = it }
            else -> UnknownOption(type)
        }

        option.read(buffer)

        return  option
    }
}
