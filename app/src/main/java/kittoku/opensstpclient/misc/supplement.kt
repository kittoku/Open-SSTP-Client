package kittoku.opensstpclient.misc

import kotlin.math.min


internal fun <K, V> generateResolver(array: Array<K>, map: (K) -> V): (V) -> K? {
    return fun(value: V): K? {
        return array.firstOrNull { map(it) == value }
    }
}

fun ByteArray.isSame(other: ByteArray): Boolean {
    if (this.size != other.size) return false

    this.zip(other).forEach {
        if (it.first != it.second) return false
    }

    return true
}

fun ByteArray.writeTo(other: ByteArray) {
    repeat(min(this.size, other.size)) {
        other[it] = this[it]
    }
}
