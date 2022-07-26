package kittoku.osc.extension


internal fun Byte.toIntAsUByte(): Int {
    return this.toInt() and 0x000000FF
}
