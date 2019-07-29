package kittoku.opensstpclient.misc


internal class SstpParsingError(message: String?) : Exception(message)

internal class SstpClientKilled(message: String?) : Exception(message)

internal class PppParsingError(message: String?) : Exception(message)

internal class PppClientKilled(message: String?) : Exception(message)

internal fun ByteArray.toStringAsHex(limit: Int): String {
    val stringList: MutableList<String> = mutableListOf()

    for (i in 0 until size) {
        if (i == limit) break
        stringList.add(String.format("%2x", this[i]) + " ")

        if (i % 16 == 15) stringList.add("\n")
    }

    return stringList.joinToString(separator = "")
}

