package kittoku.opensstpclient

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import androidx.core.app.NotificationCompat


internal enum class VpnAction(val value: String) {
    ACTION_CONNECT("kittoku.opensstpclient.CONNECT"),
    ACTION_DISCONNECT("kittoku.opensstpclient.DISCONNECT"),
}

internal class SstpVpnService : VpnService() {
    internal val CHANNEL_ID = "OpenSSTPClient"
    private var controlClient: ControlClient?  = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return if (VpnAction.ACTION_DISCONNECT.value == intent?.action ?: false) {
            controlClient?.kill(null)
            controlClient = null
            Service.START_NOT_STICKY
        } else {
            controlClient?.kill(null)
            controlClient = ControlClient(this).also {
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
            it.setSmallIcon(R.drawable.ic_baseline_vpn_lock_24)
            it.setContentText("Disconnect SSTP connection")
            it.priority = NotificationCompat.PRIORITY_DEFAULT
            it.setContentIntent(pendingIntent)
            it.setAutoCancel(true)
        }

        startForeground(1, builder.build())
    }

    override fun onDestroy() {
        controlClient?.kill(null)
    }
}
