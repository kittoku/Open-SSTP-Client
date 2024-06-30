package kittoku.osc.unit.ppp.option

import kittoku.osc.debug.assertAlways
import kittoku.osc.extension.toIntAsUByte
import kittoku.osc.unit.DataUnit
import java.nio.ByteBuffer


internal abstract class Option : DataUnit() {
    internal abstract val type: Byte

    protected val headerSize = 2
    protected var givenLength = 0

    protected open fun readHeader(buffer: ByteBuffer) {
        assertAlways(type == buffer.get())
        givenLength = buffer.get().toIntAsUByte()
    }

    protected open fun writeHeader(buffer: ByteBuffer) {
        buffer.put(type)
        buffer.put(length.toByte())
    }
}

internal class UnknownOption(unknownType: Byte) : Option() {
    override val type = unknownType
    override val length: Int
        get() = headerSize + holder.size

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

internal abstract class OptionPack(private val givenLength: Int) : DataUnit() {
    internal abstract val knownOptions: List<Option>
    internal var unknownOptions = listOf<UnknownOption>()
    internal val allOptions: List<Option>
        get() = knownOptions + unknownOptions

    internal var order: MutableMap<Byte, Int> = mutableMapOf()

    override val length: Int
        get() = allOptions.fold(0) {sum, option -> sum + option.length}

    protected abstract fun retrieveOption(buffer: ByteBuffer): Option

    private fun ensureValidOrder() {
        var nextIndex = order.values.maxOrNull() ?: 0

        allOptions.forEach {
            if (!order.containsKey(it.type)) {
                order[it.type] = nextIndex
                nextIndex++
            }
        }
    }

    override fun read(buffer: ByteBuffer) {
        var remaining = givenLength - length

        val currentOrder = mutableMapOf<Byte, Int>()
        val currentUnknownOptions = mutableListOf<UnknownOption>()

        var i = 0
        while (true) {
            assertAlways(remaining >= 0)
            if (remaining == 0) {
                break
            }

            retrieveOption(buffer).also {
                // if the option type is duplicated, the last option is preferred now
                currentOrder[it.type] = i
                remaining -= it.length

                if (it is UnknownOption) {
                    currentUnknownOptions.add(it)
                }
             }

            i++
        }

        order = currentOrder
        unknownOptions = currentUnknownOptions.toList()
    }

    override fun write(buffer: ByteBuffer) {
        ensureValidOrder()

        allOptions.sortedBy { option -> order[option.type] }.forEach { it.write(buffer) }
    }
}
