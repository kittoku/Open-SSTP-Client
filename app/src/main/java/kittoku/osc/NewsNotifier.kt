package kittoku.osc

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.os.ConfigurationCompat
import androidx.preference.PreferenceManager
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ListenableWorker
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequest
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import kittoku.osc.activity.MainActivity
import kittoku.osc.activity.UpdateUi
import java.util.concurrent.TimeUnit


/** Checks the news file and new releases in the background and shows an ordinary (dismissible) notification. */
internal object NewsNotifier {
    private const val CHANNEL_ID = "banafsh_news"
    private const val NEWS_NOTIFICATION_ID = 7001
    private const val UPDATE_NOTIFICATION_ID = 7002
    private const val KEY_NEWS_NOTIFIED = "news_notified_id"
    private const val KEY_UPDATE_NOTIFIED = "update_notified_version"

    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= 26) {
            val manager = context.getSystemService(NotificationManager::class.java) ?: return

            if (manager.getNotificationChannel(CHANNEL_ID) == null) {
                manager.createNotificationChannel(
                    NotificationChannel(CHANNEL_ID, context.getString(R.string.bs_channel_news), NotificationManager.IMPORTANCE_DEFAULT)
                )
            }
        }
    }

    // Android runs background work at most every 15 minutes.
    fun schedule(context: Context) {
        val request = PeriodicWorkRequest.Builder(NewsWorker::class.java, 15, TimeUnit.MINUTES)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .build()

        WorkManager.getInstance(context).enqueueUniquePeriodicWork("banafsh_news", ExistingPeriodicWorkPolicy.KEEP, request)
    }

    private fun language(context: Context): String {
        val app = AppCompatDelegate.getApplicationLocales()
        if (!app.isEmpty) return app[0]?.language ?: "en"

        return ConfigurationCompat.getLocales(context.resources.configuration)[0]?.language ?: "en"
    }

    private fun canNotify(context: Context): Boolean {
        return Build.VERSION.SDK_INT < 33 ||
                ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
    }

    private fun show(context: Context, id: Int, title: String, text: String) {
        val intent = Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)

        val pending = PendingIntent.getActivity(context, id, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_baseline_vpn_lock_24)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setAutoCancel(true)
            .setContentIntent(pending)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .build()

        @Suppress("MissingPermission")
        NotificationManagerCompat.from(context).notify(id, notification)
    }

    /** Blocking: call it off the main thread. */
    fun checkAndNotify(context: Context) {
        try {
            val prefs = PreferenceManager.getDefaultSharedPreferences(context)
            if (!canNotify(context)) return

            ensureChannel(context)

            val news = NewsChecker.fetchBlocking(prefs, language(context))
            val item = news.item

            if (news.ok && item != null &&
                prefs.getString(NewsChecker.KEY_DISMISSED, "") != item.id &&
                prefs.getString(KEY_NEWS_NOTIFIED, "") != item.id
            ) {
                show(context, NEWS_NOTIFICATION_ID, item.title.ifEmpty { context.getString(R.string.bs_title) }, item.text)
                prefs.edit().putString(KEY_NEWS_NOTIFIED, item.id).apply()
            }

            UpdateUi.checkBlockingIfDue(prefs)
            val update = UpdateUi.pendingCard(prefs)

            if (update != null && prefs.getString(KEY_UPDATE_NOTIFIED, "") != update.version) {
                show(
                    context,
                    UPDATE_NOTIFICATION_ID,
                    context.getString(R.string.bs_notify_update_title),
                    context.getString(R.string.bs_notify_update_text, update.version)
                )
                prefs.edit().putString(KEY_UPDATE_NOTIFIED, update.version).apply()
            }
        } catch (_: Exception) { }
    }
}

class NewsWorker(context: Context, params: WorkerParameters) : Worker(context, params) {
    override fun doWork(): ListenableWorker.Result {
        NewsNotifier.checkAndNotify(applicationContext)
        return ListenableWorker.Result.success()
    }
}
