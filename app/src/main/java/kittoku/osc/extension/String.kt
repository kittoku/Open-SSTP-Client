package kittoku.osc.extension


internal fun sum(vararg words: String): String {
    var result = ""

    words.forEach {
        result += it
    }

    return result
}
