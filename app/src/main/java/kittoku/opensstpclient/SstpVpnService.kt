package kittoku.opensstpclient

import android.R.drawable.ic_media_pause
import android.R.drawable.ic_notification_overlay
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.preference.PreferenceManager
import androidx.core.app.NotificationCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager


internal enum class VpnAction(val value: String) {
    ACTION_CONNECT("kittoku.opensstpclient.START"),
    ACTION_DISCONNECT("kittoku.opensstpclient.STOP"),
    ACTION_UPDATE("kittoku.opensstpclient.UPDATE")
}

internal class SstpVpnService : VpnService() {
    private val TAG = "SstpVpnService"
    private val CHANNEL_ID = "OpenSSTPClient"
    private var controlClient: ControlClient?  = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return if (VpnAction.ACTION_DISCONNECT.value == intent?.action ?: false) {
            controlClient?.kill(null)
            controlClient = null
            Service.START_NOT_STICKY
        } else {
            controlClient?.kill(null)
            controlClient = ControlClient(this).also {
                if (!it.prepareSetting()) {
                    notifySwitchOff()
                    return Service.START_NOT_STICKY
                }
                beForegrounded()
                it.run()
            }

            Service.START_STICKY
        }
    }

    private fun beForegrounded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, CHANNEL_ID, NotificationManager.IMPORTANCE_DEFAULT)
            val notificationManager: NotificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }

        val intent = Intent(
            applicationContext,
            SstpVpnService::class.java
        ).setAction(VpnAction.ACTION_DISCONNECT.value)
        val pendingIntent = PendingIntent.getService(applicationContext, 0, intent, 0)
        val builder = NotificationCompat.Builder(applicationContext, CHANNEL_ID).also {
            it.setSmallIcon(ic_notification_overlay)
            it.setContentText("Open SSTP Client connecting")
            it.priority = NotificationCompat.PRIORITY_DEFAULT
            it.addAction(ic_media_pause, "DISCONNECT", pendingIntent)
        }

        startForeground(1, builder.build())
    }

    override fun onDestroy() {
        controlClient?.kill(null)
    }

    internal fun notifySwitchOff() {
        PreferenceManager.getDefaultSharedPreferences(applicationContext).also {
            it.edit().putBoolean(PreferenceKey.SWITCH.value, false).apply()
        }
        LocalBroadcastManager.getInstance(applicationContext)
            .sendBroadcast(Intent(VpnAction.ACTION_UPDATE.value))
    }
}
