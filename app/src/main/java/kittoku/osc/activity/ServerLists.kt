package kittoku.osc.activity

import kittoku.osc.Protocol
import org.json.JSONArray
import java.net.HttpURLConnection
import java.net.URL

// Each service has its own list file. SSTP: the full list first; the short list that older
// versions use stays as a fallback (for example before the first refresh that creates servers_v2.json).
internal fun listUrls(protocol: Protocol): List<String> {
    val base = "https://raw.githubusercontent.com/Banafshex/Banafsh-sstp/main/"

    return when (protocol) {
        Protocol.L2TP -> listOf(base + "servers_l2tp.json")
        Protocol.SSTP -> listOf(base + "servers_v2.json", base + "servers.json")
    }
}

/** The hosts of the first list of this service that loads, or null when none does. Blocks: call off the main thread. */
internal fun fetchServerHosts(protocol: Protocol): Set<String>? {
    for (url in listUrls(protocol)) {
        try {
            val connection = URL(url).openConnection() as HttpURLConnection
            connection.connectTimeout = 8000
            connection.readTimeout = 8000

            try {
                if (connection.responseCode != 200) continue

                val array = JSONArray(connection.inputStream.bufferedReader().use { it.readText() })
                val hosts = HashSet<String>()

                for (i in 0 until array.length()) {
                    val host = array.optJSONObject(i)?.optString("host").orEmpty()
                    if (host.isNotEmpty()) hosts.add(host)
                }

                if (hosts.isNotEmpty()) return hosts
            } finally {
                connection.disconnect()
            }
        } catch (_: Exception) {
        }
    }

    return null
}
