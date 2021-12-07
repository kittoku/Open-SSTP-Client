package kittoku.osc

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.TileService
import androidx.core.app.NotificationCompat
import androidx.preference.PreferenceManager
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.setBooleanPrefValue


internal const val ACTION_VPN_CONNECT = "kittoku.osc.connect"
internal const val ACTION_VPN_DISCONNECT = "kittoku.osc.disconnect"

internal class SstpVpnService : VpnService() {
    private lateinit var prefs: SharedPreferences
    private lateinit var listener: SharedPreferences.OnSharedPreferenceChangeListener
    internal val CHANNEL_ID = "OpenSSTPClient"
    private var controlClient: ControlClient?  = null

    private fun setRootState(state: Boolean) {
        setBooleanPrefValue(state, OscPreference.ROOT_STATE, prefs)
    }

    private fun requestTileListening() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            TileService.requestListeningState(
                applicationContext,
                ComponentName(applicationContext, SstpTileService::class.java)
            )
        }
    }

    override fun onCreate() {
        prefs = PreferenceManager.getDefaultSharedPreferences(applicationContext)

        listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key == OscPreference.ROOT_STATE.name) {
                val newState = getBooleanPrefValue(OscPreference.ROOT_STATE, prefs)

                setBooleanPrefValue(newState, OscPreference.HOME_CONNECTOR, prefs)
                requestTileListening()
            }
        }

        prefs.registerOnSharedPreferenceChangeListener(listener)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return if (ACTION_VPN_DISCONNECT == intent?.action ?: false) {
            controlClient?.kill(null)
            controlClient = null

            stopSelf()

            Service.START_NOT_STICKY
        } else {
            controlClient?.kill(null)
            controlClient = ControlClient(this).also {
                beForegrounded()
                it.run()
            }

            setRootState(true)

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
        ).setAction(ACTION_VPN_DISCONNECT)
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
        setRootState(false)
        prefs.unregisterOnSharedPreferenceChangeListener(listener)
    }
}
