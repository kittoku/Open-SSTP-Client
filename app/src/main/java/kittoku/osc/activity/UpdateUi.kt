package kittoku.osc.activity

import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.os.ConfigurationCompat
import kittoku.osc.BuildConfig
import kittoku.osc.R
import kittoku.osc.ReleaseInfo
import kittoku.osc.UpdateChecker
import kittoku.osc.UpdateInstaller
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean


/** Checks GitHub for a newer release and downloads / installs it inside the app. */
internal object UpdateUi {
    const val KEY_DISMISSED = "update_dismissed_version"
    private const val KEY_LAST_CHECK = "update_last_check"
    private const val KEY_FOUND = "update_found"
    private const val DAY = 24L * 60 * 60 * 1000

    private val executor = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    fun language(activity: AppCompatActivity): String {
        return ConfigurationCompat.getLocales(activity.resources.configuration)[0]?.language ?: "en"
    }

    private fun loadFound(prefs: SharedPreferences): ReleaseInfo? {
        val text = prefs.getString(KEY_FOUND, null) ?: return null

        return try {
            val json = JSONObject(text)
            val info = ReleaseInfo(
                json.getString("v"),
                json.optString("n"),
                json.getString("u"),
                json.optLong("s"),
                json.optString("p")
            )

            if (UpdateChecker.isNewer(info.version, BuildConfig.VERSION_NAME)) info else null
        } catch (e: Exception) {
            null
        }
    }

    /** The newer release that the Home card should show (not the one the user already put off). */
    fun pendingCard(prefs: SharedPreferences): ReleaseInfo? {
        return loadFound(prefs)?.takeIf { prefs.getString(KEY_DISMISSED, "") != it.version }
    }

    fun checkIfDue(prefs: SharedPreferences, onChanged: () -> Unit) {
        if (System.currentTimeMillis() - prefs.getLong(KEY_LAST_CHECK, 0L) < DAY) return

        runCheck(prefs) { _, _ -> onChanged() }
    }

    // Blocking: asks GitHub and remembers the result. Returns (newer release or null, whether GitHub answered).
    private fun doCheck(prefs: SharedPreferences): Pair<ReleaseInfo?, Boolean> {
        val result = UpdateChecker.fetchLatest()
        var newer: ReleaseInfo? = null

        if (result.ok) {
            val editor = prefs.edit().putLong(KEY_LAST_CHECK, System.currentTimeMillis())
            val info = result.info

            if (info != null && UpdateChecker.isNewer(info.version, BuildConfig.VERSION_NAME)) {
                newer = info
                editor.putString(
                    KEY_FOUND,
                    JSONObject()
                        .put("v", info.version)
                        .put("n", info.notes)
                        .put("u", info.apkUrl)
                        .put("s", info.apkSize)
                        .put("p", info.pageUrl)
                        .toString()
                )
            } else {
                editor.remove(KEY_FOUND)
            }

            editor.apply()
        }

        return newer to result.ok
    }

    /** For background work: checks about once a day (blocking). */
    fun checkBlockingIfDue(prefs: SharedPreferences) {
        if (System.currentTimeMillis() - prefs.getLong(KEY_LAST_CHECK, 0L) < DAY) return

        doCheck(prefs)
    }

    private fun runCheck(prefs: SharedPreferences, onDone: (ReleaseInfo?, Boolean) -> Unit) {
        executor.execute {
            val (newer, ok) = doCheck(prefs)
            main.post { onDone(newer, ok) }
        }
    }

    /** Menu action: always checks right now and tells the user the result. */
    fun checkNow(activity: AppCompatActivity, prefs: SharedPreferences) {
        Toast.makeText(activity, R.string.bs_update_checking, Toast.LENGTH_SHORT).show()

        runCheck(prefs) { info, ok ->
            if (activity.isFinishing || activity.isDestroyed) return@runCheck

            when {
                info != null -> showUpdateDialog(activity, prefs, info) { }
                ok -> Toast.makeText(activity, R.string.bs_update_uptodate, Toast.LENGTH_LONG).show()
                else -> Toast.makeText(activity, R.string.bs_update_check_failed, Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun cleanNotes(notes: String): String {
        return notes.lines().joinToString("\n") {
            var line = it.trim().replace(Regex("^#+\\s*"), "")
            if (line.startsWith("- ")) line = "• " + line.substring(2)
            line
        }.replace(Regex("\n{3,}"), "\n\n").trim()
    }

    fun showUpdateDialog(activity: AppCompatActivity, prefs: SharedPreferences, info: ReleaseInfo, onLater: () -> Unit) {
        val notes = cleanNotes(UpdateChecker.pickNotes(info.notes, language(activity)).take(1200))

        GlassDialog.show(
            activity,
            R.drawable.ic_gd_update,
            activity.getString(R.string.bs_update_title, info.version),
            body = notes.ifEmpty { activity.getString(R.string.bs_update_no_notes) },
            primaryText = activity.getString(R.string.bs_update_now),
            onPrimary = { startDownload(activity, info) },
            secondaryText = activity.getString(R.string.bs_update_later),
            onClose = { byPrimary ->
                if (!byPrimary) {
                    prefs.edit().putString(KEY_DISMISSED, info.version).apply()
                    onLater()
                }
            }
        )
    }

    private fun startDownload(activity: AppCompatActivity, info: ReleaseInfo) {
        if (Build.VERSION.SDK_INT >= 26 && !activity.packageManager.canRequestPackageInstalls()) {
            showInstallPermissionDialog(activity)
            return
        }

        val density = activity.resources.displayMetrics.density
        val dp = { value: Int -> (value * density).toInt() }
        val cancelled = AtomicBoolean(false)

        val label = TextView(activity).apply {
            text = activity.getString(R.string.bs_update_downloading, 0)
            textSize = 15f
        }

        val bar = ProgressBar(activity, null, android.R.attr.progressBarStyleHorizontal).apply { max = 100 }

        val box = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(20), dp(24), dp(8))
            addView(label)
            addView(
                bar,
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
                    .apply { topMargin = dp(14) }
            )
        }

        val dialog = AlertDialog.Builder(activity)
            .setTitle(activity.getString(R.string.bs_update_title, info.version))
            .setView(box)
            .setCancelable(false)
            .setNegativeButton(R.string.bs_cancel) { _, _ -> cancelled.set(true) }
            .show()

        executor.execute {
            var lastPercent = -1

            val file = UpdateChecker.download(
                activity.applicationContext,
                info,
                { done, total ->
                    val percent = if (total > 0) (done * 100 / total).toInt() else 0

                    if (percent != lastPercent) {
                        lastPercent = percent
                        main.post {
                            bar.progress = percent
                            label.text = activity.getString(R.string.bs_update_downloading, percent)
                        }
                    }
                },
                { cancelled.get() }
            )

            main.post {
                if (activity.isFinishing || activity.isDestroyed) return@post

                if (cancelled.get()) {
                    dialog.dismiss()
                    return@post
                }

                if (file == null) {
                    dialog.dismiss()
                    showDownloadFailed(activity)
                    return@post
                }

                label.setText(R.string.bs_update_installing)
                bar.isIndeterminate = true

                if (UpdateInstaller.install(activity.applicationContext, file)) {
                    // Android may show its own confirmation on top; this dialog is no longer needed.
                    main.postDelayed({ if (dialog.isShowing) dialog.dismiss() }, 2500)
                } else {
                    dialog.dismiss()
                    Toast.makeText(activity, R.string.bs_update_install_failed, Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun showInstallPermissionDialog(activity: AppCompatActivity) {
        AlertDialog.Builder(activity)
            .setTitle(R.string.bs_update_perm_title)
            .setMessage(R.string.bs_update_perm_body)
            .setPositiveButton(R.string.bs_update_perm_continue) { _, _ ->
                if (Build.VERSION.SDK_INT >= 26) {
                    activity.startActivity(
                        Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${activity.packageName}"))
                    )
                }
            }
            .setNegativeButton(R.string.bs_cancel, null)
            .show()
    }

    private fun showDownloadFailed(activity: AppCompatActivity) {
        AlertDialog.Builder(activity)
            .setMessage(R.string.bs_update_failed)
            .setPositiveButton(R.string.bs_update_open_page) { _, _ ->
                try {
                    activity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(UpdateChecker.RELEASES_PAGE)))
                } catch (_: Exception) { }
            }
            .setNegativeButton(R.string.bs_cancel, null)
            .show()
    }
}


/** The update and news pop-ups: they open from a notification or when the app starts. */
internal object Popups {
    private var showing = false

    fun showPending(activity: AppCompatActivity, prefs: SharedPreferences) {
        if (showing || activity.isFinishing || activity.isDestroyed) return

        val update = UpdateUi.pendingCard(prefs)

        if (update != null) {
            showing = true
            UpdateUi.showUpdateDialog(activity, prefs, update) {
                showing = false
                showPending(activity, prefs)
            }
            return
        }

        val news = kittoku.osc.NewsChecker.parse(
            prefs.getString(kittoku.osc.NewsChecker.KEY_CACHE, null),
            UpdateUi.language(activity)
        ) ?: return

        if (prefs.getString(kittoku.osc.NewsChecker.KEY_DISMISSED, "") == news.id) return

        showing = true
        val hasUrl = news.url.isNotEmpty()

        GlassDialog.show(
            activity,
            R.drawable.ic_gd_bell,
            news.title.ifEmpty { activity.getString(R.string.bs_title) },
            body = news.text,
            primaryText = if (hasUrl) activity.getString(R.string.bs_news_open) else null,
            onPrimary = {
                try {
                    activity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(news.url)))
                } catch (_: Exception) { }
            },
            secondaryText = activity.getString(R.string.bs_close),
            onClose = {
                showing = false
                prefs.edit().putString(kittoku.osc.NewsChecker.KEY_DISMISSED, news.id).apply()
            }
        )
    }
}
