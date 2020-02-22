package kittoku.opensstpclient.misc

import kotlin.math.min


internal fun <K, V> generateResolver(array: Array<K>, map: (K) -> V): (V) -> K? {
    return fun(value: V): K? {
        return array.firstOrNull { map(it) == value }
    }
}

internal fun ByteArray.writeTo(other: ByteArray) {
    repeat(min(this.size, other.size)) {
        other[it] = this[it]
    }
}
