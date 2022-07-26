package kittoku.osc.unit.ppp.option

import kittoku.osc.debug.assertAlways
import kittoku.osc.extension.probeByte
import kittoku.osc.extension.probeShort
import kittoku.osc.extension.toIntAsUShort
import java.nio.ByteBuffer


internal const val OPTION_TYPE_LCP_MRU: Byte = 1
internal const val OPTION_TYPE_LCP_AUTH: Byte = 3

internal const val AUTH_PROTOCOL_PAP = 0xC023.toShort()
internal const val AUTH_PROTOCOL_CHAP = 0xC223.toShort()

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

internal abstract class AuthOption : Option() {
    override val type = OPTION_TYPE_LCP_AUTH
    internal abstract val protocol: Short

    override fun readHeader(buffer: ByteBuffer) {
        super.readHeader(buffer)
        assertAlways(buffer.short == protocol)
    }

    override fun writeHeader(buffer: ByteBuffer) {
        super.writeHeader(buffer)
        buffer.putShort(protocol)
    }
}

internal class AuthOptionPAP : AuthOption() {
    override val protocol = AUTH_PROTOCOL_PAP
    override val length = headerSize + Short.SIZE_BYTES

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)
    }
}

internal class AuthOptionMSChapv2 : AuthOption() {
    override val protocol = AUTH_PROTOCOL_CHAP
    override val length = headerSize + Short.SIZE_BYTES + Byte.SIZE_BYTES
    internal val algorithm: Byte = CHAP_ALGORITHM_MSCHAPv2

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        assertAlways(buffer.get() == algorithm)
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

        buffer.put(algorithm)
    }
}

internal class AuthOptionUnknown(override val protocol: Short) : AuthOption() {
    override val length: Int
        get() = headerSize + Short.SIZE_BYTES + holder.size

    internal var holder = ByteArray(0)

    override fun read(buffer: ByteBuffer) {
        readHeader(buffer)

        val holderSize = givenLength - length
        assertAlways(holderSize >= 0)

        if (holderSize > 0) {
            holder = ByteArray(holderSize).also { buffer.get(it) }
        }
    }

    override fun write(buffer: ByteBuffer) {
        writeHeader(buffer)

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

    override fun filterOption(buffer: ByteBuffer): Option {
        return when (val type = buffer.probeByte(0)) {
            OPTION_TYPE_LCP_MRU -> {
                mruOption = MRUOption().also { it.read(buffer) }
                mruOption
            }

            OPTION_TYPE_LCP_AUTH -> {
                authOption = when (val protocol = buffer.probeShort(2)) {
                    AUTH_PROTOCOL_PAP -> AuthOptionPAP()
                    AUTH_PROTOCOL_CHAP -> {
                        if (buffer.probeByte(4) == CHAP_ALGORITHM_MSCHAPv2) {
                            AuthOptionMSChapv2()
                        } else {
                            AuthOptionUnknown(protocol)
                        }
                    }
                    else -> AuthOptionUnknown(protocol)
                }.also {
                    it.read(buffer)
                }

                authOption
            }

            else -> {
                UnknownOption(type)
            }
        }!!
    }
}
