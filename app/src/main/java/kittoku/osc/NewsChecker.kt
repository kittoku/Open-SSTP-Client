package kittoku.osc

import android.content.SharedPreferences
import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.concurrent.Executors


internal data class NewsItem(val id: String, val title: String, val text: String, val url: String)

/** ok = the news file was read (even if there is no active news); item = the news to show, or null. */
internal class NewsResult(val ok: Boolean, val item: NewsItem?)

/** Short announcements written by the developer in news.json in the repository. */
internal object NewsChecker {
    private const val PRIMARY_URL = "https://raw.githubusercontent.com/Banafshex/Banafsh-sstp/main/news.json"
    private const val FALLBACK_URL = "https://cdn.jsdelivr.net/gh/Banafshex/Banafsh-sstp@main/news.json"
    const val KEY_CACHE = "news_cache"
    const val KEY_DISMISSED = "news_dismissed_id"

    private val executor = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    fun parse(text: String?, language: String): NewsItem? {
        if (text.isNullOrBlank()) return null

        return try {
            val json = JSONObject(text)

            if (!json.optBoolean("active", false)) return null

            val id = json.optString("id").trim()
            if (id.isEmpty()) return null

            val expires = json.optString("expires").trim()
            if (expires.isNotEmpty()) {
                val format = SimpleDateFormat("yyyy-MM-dd", Locale.US).apply { isLenient = false }
                val end = format.parse(expires)

                if (end != null && System.currentTimeMillis() > end.time + 24L * 60 * 60 * 1000) return null
            }

            val part = json.optJSONObject(if (language == "fa") "fa" else "en")
                ?: json.optJSONObject("en")
                ?: json.optJSONObject("fa")
                ?: return null

            val title = part.optString("title").trim()
            val body = part.optString("text").trim()
            if (title.isEmpty() && body.isEmpty()) return null

            val url = json.optString("url").trim().takeIf { it.startsWith("https://") || it.startsWith("http://") }.orEmpty()

            NewsItem(id, title, body, url)
        } catch (e: Exception) {
            null
        }
    }

    /** Reads the news file (blocking: call it off the main thread). */
    fun fetchBlocking(prefs: SharedPreferences, language: String): NewsResult {
        val text = UpdateChecker.httpGet(PRIMARY_URL) ?: UpdateChecker.httpGet(FALLBACK_URL)
            ?: return NewsResult(false, null)

        prefs.edit().putString(KEY_CACHE, text).apply()
        return NewsResult(true, parse(text, language))
    }

    fun fetchAsync(prefs: SharedPreferences, language: String, onResult: (NewsResult) -> Unit) {
        executor.execute {
            val result = fetchBlocking(prefs, language)
            main.post { onResult(result) }
        }
    }
}
