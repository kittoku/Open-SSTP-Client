package kittoku.osc.extension


internal fun ByteArray.toHexString(parse: Boolean = false): String {
    var output = ""

    forEachIndexed { index, byte ->
        output += String.format("%02X", byte.toInt() and 0xFF)

        if (parse) output += if (index % 16 == 15) "\n" else " "
    }

    return output
}

internal fun String.toHexByteArray(): ByteArray {
    if (length % 2 != 0) throw Exception("Fragmented Byte")

    val arrayLength = length / 2
    val output = ByteArray(arrayLength)

    repeat(arrayLength) {
        val start = it * 2
        output[it] = this.slice(start..start + 1).toInt(16).toByte()
    }

    return output
}
