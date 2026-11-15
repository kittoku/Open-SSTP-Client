package kittoku.osc

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import android.widget.Toast
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL


internal data class ReleaseInfo(
    val version: String,
    val notes: String,
    val apkUrl: String,
    val apkSize: Long,
    val pageUrl: String
)

/** ok = GitHub answered properly (even if there is nothing newer); info = latest stable release, if it has an APK. */
internal class LatestResult(val ok: Boolean, val info: ReleaseInfo?)

internal object UpdateChecker {
    private const val API_URL = "https://api.github.com/repos/Banafshex/Banafsh-sstp/releases/latest"
    const val RELEASES_PAGE = "https://github.com/Banafshex/Banafsh-sstp/releases"

    fun httpGet(address: String, accept: String? = null): String? {
        var connection: HttpURLConnection? = null

        return try {
            connection = (URL(address).openConnection() as HttpURLConnection).apply {
                connectTimeout = 10_000
                readTimeout = 15_000
                setRequestProperty("User-Agent", "Banafsh-sstp")
                if (accept != null) setRequestProperty("Accept", accept)
            }

            if (connection.responseCode != 200) null
            else connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
        } catch (e: Exception) {
            null
        } finally {
            connection?.disconnect()
        }
    }

    fun fetchLatest(): LatestResult {
        val text = httpGet(API_URL, "application/vnd.github+json") ?: return LatestResult(false, null)

        return try {
            val json = JSONObject(text)

            // Only stable releases are offered to everybody.
            if (json.optBoolean("draft") || json.optBoolean("prerelease")) {
                return LatestResult(true, null)
            }

            val assets = json.getJSONArray("assets")
            var url = ""
            var size = 0L

            for (i in 0 until assets.length()) {
                val asset = assets.getJSONObject(i)

                if (asset.getString("name").endsWith(".apk")) {
                    url = asset.getString("browser_download_url")
                    size = asset.optLong("size")
                    break
                }
            }

            if (url.isEmpty()) {
                LatestResult(true, null)
            } else {
                LatestResult(
                    true,
                    ReleaseInfo(
                        json.getString("tag_name").removePrefix("v"),
                        json.optString("body"),
                        url,
                        size,
                        json.optString("html_url", RELEASES_PAGE)
                    )
                )
            }
        } catch (e: Exception) {
            LatestResult(false, null)
        }
    }

    private fun parseVersion(version: String): Pair<List<Int>, Boolean> {
        val clean = version.trim().removePrefix("v")
        val numbers = clean.substringBefore('-').split('.').map { it.toIntOrNull() ?: 0 }

        return numbers to clean.contains('-')
    }

    /** 1.1.0 is newer than 1.0.1, and 1.1.0 is newer than 1.1.0-beta.1. */
    fun isNewer(remote: String, local: String): Boolean {
        val (r, remotePre) = parseVersion(remote)
        val (l, localPre) = parseVersion(local)

        for (i in 0 until maxOf(r.size, l.size)) {
            val a = r.getOrElse(i) { 0 }
            val b = l.getOrElse(i) { 0 }

            if (a != b) return a > b
        }

        return localPre && !remotePre
    }

    /** The release text may hold a Persian and an English part (<!--fa--> and <!--en--> markers). */
    fun pickNotes(notes: String, language: String): String {
        val body = notes.substringBefore("\n---").trim()
        val faIndex = body.indexOf("<!--fa-->")
        val enIndex = body.indexOf("<!--en-->")

        if (faIndex < 0 || enIndex < 0) return body.replace(Regex("<!--.*?-->"), "").trim()

        val fa = if (faIndex < enIndex) body.substring(faIndex + 9, enIndex) else body.substring(faIndex + 9)
        val en = if (enIndex < faIndex) body.substring(enIndex + 9, faIndex) else body.substring(enIndex + 9)

        return (if (language == "fa") fa else en).trim()
    }

    /** Returns the downloaded file, or null if it failed or was cancelled. */
    fun download(context: Context, info: ReleaseInfo, onProgress: (Long, Long) -> Unit, isCancelled: () -> Boolean): File? {
        val dir = File(context.cacheDir, "updates").apply { mkdirs() }
        dir.listFiles()?.forEach { it.delete() }

        val file = File(dir, "Banafsh-sstp-${info.version}.apk")
        var connection: HttpURLConnection? = null

        try {
            connection = (URL(info.apkUrl).openConnection() as HttpURLConnection).apply {
                connectTimeout = 15_000
                readTimeout = 20_000
                instanceFollowRedirects = true
                setRequestProperty("User-Agent", "Banafsh-sstp")
            }

            if (connection.responseCode != 200) return null

            val total = connection.contentLengthLong.takeIf { it > 0 } ?: info.apkSize

            connection.inputStream.use { input ->
                file.outputStream().use { output ->
                    val buffer = ByteArray(32 * 1024)
                    var done = 0L

                    while (true) {
                        if (isCancelled()) {
                            file.delete()
                            return null
                        }

                        val read = input.read(buffer)
                        if (read < 0) break

                        output.write(buffer, 0, read)
                        done += read
                        onProgress(done, total)
                    }
                }
            }

            if (info.apkSize > 0 && file.length() != info.apkSize) {
                file.delete()
                return null
            }

            return file
        } catch (e: Exception) {
            file.delete()
            return null
        } finally {
            connection?.disconnect()
        }
    }
}

internal object UpdateInstaller {
    private const val ACTION = "kittoku.osc.update_result"

    /** Hands the APK to Android's installer. Android 12+ may skip the confirmation for self-updates. */
    fun install(context: Context, apk: File): Boolean {
        return try {
            val installer = context.packageManager.packageInstaller
            val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
            params.setAppPackageName(context.packageName)

            if (Build.VERSION.SDK_INT >= 31) {
                params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
            }

            val id = installer.createSession(params)

            installer.openSession(id).use { session ->
                apk.inputStream().use { input ->
                    session.openWrite("banafsh.apk", 0, apk.length()).use { output ->
                        input.copyTo(output)
                        session.fsync(output)
                    }
                }

                val intent = Intent(context, UpdateResultReceiver::class.java).setAction(ACTION)
                val flags = PendingIntent.FLAG_UPDATE_CURRENT or
                        (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)

                session.commit(PendingIntent.getBroadcast(context, id, intent, flags).intentSender)
            }

            true
        } catch (e: Exception) {
            false
        }
    }
}

/** Receives the installer's answer: opens Android's confirmation screen when it is needed. */
class UpdateResultReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                val confirm = if (Build.VERSION.SDK_INT >= 33) {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                }

                confirm?.let {
                    it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    context.startActivity(it)
                }
            }

            PackageInstaller.STATUS_SUCCESS -> { }

            else -> Toast.makeText(context, R.string.bs_update_install_failed, Toast.LENGTH_LONG).show()
        }
    }
}
