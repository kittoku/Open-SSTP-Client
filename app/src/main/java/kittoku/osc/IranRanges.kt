package kittoku.osc

import android.content.Context
import java.io.File
import java.net.HttpURLConnection
import java.net.URL


/**
 * Iranian IPv4 ranges that connect directly (experimental). The list is built by a workflow from the
 * public RIPE NCC registry; a built-in copy is bundled and a newer one is downloaded now and then.
 */
internal object IranRanges {
    const val KEY_ENABLED = "iran_sites_enabled"
    const val MAX_ROUTES = 20000

    private const val FILE_NAME = "iran_ranges.txt"
    private const val REMOTE_URL = "https://raw.githubusercontent.com/Banafshex/Banafsh-sstp/main/iran_ranges.txt"
    private const val CHECK_INTERVAL_MS = 7L * 24 * 60 * 60 * 1000
    private const val RETRY_INTERVAL_MS = 60L * 60 * 1000
    private const val MAX_ADDRESS = 0xFFFFFFFFL

    /** Parses lines like 5.22.0.0/17 into merged [start, end] pairs. */
    fun parse(text: String): List<LongArray> {
        val ranges = ArrayList<LongArray>()

        text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.forEach { line ->
            val parts = line.split("/")
            if (parts.size != 2) return@forEach

            val octets = parts[0].split(".").mapNotNull { it.toIntOrNull() }
            val length = parts[1].toIntOrNull() ?: return@forEach
            if (octets.size != 4 || octets.any { it !in 0..255 } || length !in 8..32) return@forEach

            val address = (octets[0].toLong() shl 24) or (octets[1].toLong() shl 16) or (octets[2].toLong() shl 8) or octets[3].toLong()
            val size = 1L shl (32 - length)
            val start = address and (size - 1).inv() and MAX_ADDRESS

            ranges.add(longArrayOf(start, start + size - 1))
        }

        ranges.sortBy { it[0] }

        val merged = ArrayList<LongArray>()
        ranges.forEach {
            val last = merged.lastOrNull()

            if (last != null && it[0] <= last[1] + 1) {
                if (it[1] > last[1]) last[1] = it[1]
            } else {
                merged.add(longArrayOf(it[0], it[1]))
            }
        }

        return merged
    }

    private fun addCidrs(start: Long, end: Long, out: MutableList<Pair<Long, Int>>) {
        var current = start

        while (current <= end) {
            var size = if (current == 0L) 1L shl 32 else (current and -current)
            while (size > end - current + 1) size = size shr 1

            out.add(current to (32 - java.lang.Long.numberOfTrailingZeros(size)))
            current += size
        }
    }

    /** The ranges themselves as CIDR blocks (used to exclude them on Android 13 and newer). */
    fun toCidrs(ranges: List<LongArray>): List<Pair<Long, Int>> {
        return ArrayList<Pair<Long, Int>>().also { out -> ranges.forEach { addCidrs(it[0], it[1], out) } }
    }

    /** Everything except the ranges, as CIDR blocks (used to route older Android versions). */
    fun complementCidrs(ranges: List<LongArray>): List<Pair<Long, Int>> {
        val out = ArrayList<Pair<Long, Int>>()
        var next = 0L

        ranges.forEach {
            if (it[0] > next) addCidrs(next, it[0] - 1, out)
            next = it[1] + 1
        }

        if (next <= MAX_ADDRESS) addCidrs(next, MAX_ADDRESS, out)

        return out
    }

    fun format(address: Long): String {
        return "${(address shr 24) and 255}.${(address shr 16) and 255}.${(address shr 8) and 255}.${address and 255}"
    }

    private fun file(context: Context) = File(context.filesDir, FILE_NAME)

    fun load(context: Context): List<LongArray> {
        val f = file(context)
        return if (f.exists()) parse(f.readText()) else emptyList()
    }

    // The bundled copy is used until a newer one has been downloaded.
    fun ensureSeeded(context: Context) {
        val ui = context.getSharedPreferences("banafsh_ui", Context.MODE_PRIVATE)

        try {
            val text = context.resources.openRawResource(R.raw.iran_ranges).bufferedReader(Charsets.UTF_8).use { it.readText() }
            val hash = text.hashCode()

            if (ui.getInt("iran_ranges_seed", 0) != hash) {
                if (parse(text).isNotEmpty() || !file(context).exists()) {
                    file(context).writeText(text)
                }

                ui.edit().putInt("iran_ranges_seed", hash).apply()
            }
        } catch (_: Exception) { }
    }

    // About once a week the list is refreshed from the repository.
    fun refreshIfDue(context: Context) {
        val ui = context.getSharedPreferences("banafsh_ui", Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()

        if (now - ui.getLong("iran_ranges_checked", 0L) < CHECK_INTERVAL_MS) return
        if (now - ui.getLong("iran_ranges_attempt", 0L) < RETRY_INTERVAL_MS) return

        ui.edit().putLong("iran_ranges_attempt", now).apply()

        Thread {
            try {
                val connection = URL(REMOTE_URL).openConnection() as HttpURLConnection
                connection.connectTimeout = 15000
                connection.readTimeout = 20000

                try {
                    val text = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }

                    if (parse(text).size >= 100) {
                        file(context).writeText(text)
                        ui.edit().putLong("iran_ranges_checked", System.currentTimeMillis()).apply()
                    }
                } finally {
                    connection.disconnect()
                }
            } catch (_: Exception) { }
        }.start()
    }
}
