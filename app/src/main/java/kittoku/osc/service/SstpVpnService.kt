package kittoku.osc.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ComponentName
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.TileService
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.documentfile.provider.DocumentFile
import androidx.preference.PreferenceManager
import kittoku.osc.R
import kittoku.osc.client.ClientBridge
import kittoku.osc.client.control.ControlClient
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getURIPrefValue
import kittoku.osc.preference.accessor.resetReconnectionLife
import kittoku.osc.preference.accessor.setBooleanPrefValue
import java.text.SimpleDateFormat
import java.util.*


internal const val ACTION_VPN_CONNECT = "kittoku.osc.connect"
internal const val ACTION_VPN_RECONNECT = "kittoku.osc.reconnect"
internal const val ACTION_VPN_DISCONNECT = "kittoku.osc.disconnect"

internal const val NOTIFICATION_CHANNEL_NAME = "kittoku.osc.notification.channel"
internal const val NOTIFICATION_ERROR_ID = 1
internal const val NOTIFICATION_RECONNECT_ID = 2
internal const val NOTIFICATION_DISCONNECT_ID = 3

internal class SstpVpnService : VpnService() {
    private lateinit var prefs: SharedPreferences
    private lateinit var listener: SharedPreferences.OnSharedPreferenceChangeListener
    private lateinit var notificationManager: NotificationManagerCompat

    internal var logUri: Uri? = null
    private var controlClient: ControlClient?  = null

    private fun setRootState(state: Boolean) {
        setBooleanPrefValue(state, OscPreference.ROOT_STATE, prefs)
    }

    private fun requestTileListening() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            TileService.requestListeningState(this,
                ComponentName(this, SstpTileService::class.java)
            )
        }
    }

    override fun onCreate() {
        notificationManager = NotificationManagerCompat.from(this)

        prefs = PreferenceManager.getDefaultSharedPreferences(this)

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
        return when (intent?.action) {
            ACTION_VPN_CONNECT -> {
                controlClient?.kill(false, null)

                beForegrounded()
                resetReconnectionLife(prefs)
                if (getBooleanPrefValue(OscPreference.LOG_DO_SAVE_LOG, prefs)) {
                    prepareLogFile()
                }

                controlClient = ControlClient(ClientBridge(this)).also {
                    it.launchJobMain()
                }

                setRootState(true)

                Service.START_STICKY
            }

            ACTION_VPN_RECONNECT -> {
                controlClient = ControlClient(ClientBridge(this)).also {
                    it.launchJobMain()
                }

                Service.START_STICKY
            }

            else -> {
                controlClient?.disconnect()
                controlClient = null
                logUri = null

                stopForeground(true)
                stopSelf()

                Service.START_NOT_STICKY
            }
        }
    }

    internal fun makeNotification(id: Int, message: String) {
        NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_NAME).also {
            it.setSmallIcon(R.drawable.ic_baseline_vpn_lock_24)
            it.setContentText(message)
            it.priority = NotificationCompat.PRIORITY_DEFAULT
            it.setAutoCancel(true)

            notificationManager.notify(id, it.build())
        }
    }

    internal fun cancelNotification(id: Int) {
        notificationManager.cancel(id)
    }

    private fun prepareLogFile() {
        val currentDateTime = SimpleDateFormat("yyyyMMddHHmmss", Locale.getDefault()).format(Date())
        val filename = "log_osc_${currentDateTime}.txt"

        val prefURI = getURIPrefValue(OscPreference.LOG_DIR, prefs)
        if (prefURI == null) {
            makeNotification(NOTIFICATION_ERROR_ID, "LOG: ERR_NULL_PREFERENCE")
            return
        }

        val dirURI = DocumentFile.fromTreeUri(this, prefURI)
        if (dirURI == null) {
            makeNotification(NOTIFICATION_ERROR_ID, "LOG: ERR_NULL_DIRECTORY")
            return
        }

        val fileURI = dirURI.createFile("text/plain", filename)
        if (fileURI == null) {
            makeNotification(NOTIFICATION_ERROR_ID, "LOG: ERR_NULL_FILE")
            return
        }

        logUri = fileURI.uri
    }

    private fun beForegrounded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
             NotificationChannel(
                NOTIFICATION_CHANNEL_NAME,
                NOTIFICATION_CHANNEL_NAME,
                NotificationManager.IMPORTANCE_DEFAULT
            ).also {
                notificationManager.createNotificationChannel(it)
            }
        }

        val pendingIntent = PendingIntent.getService(
            this,
            0,
            Intent(this, SstpVpnService::class.java).setAction(ACTION_VPN_DISCONNECT),
            PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_NAME).also {
            it.priority = NotificationCompat.PRIORITY_DEFAULT
            it.setAutoCancel(true)
            it.setSmallIcon(R.drawable.ic_baseline_vpn_lock_24)
            it.addAction(R.drawable.ic_baseline_close_24, "DISCONNECT", pendingIntent)
        }

        startForeground(NOTIFICATION_DISCONNECT_ID, builder.build())
    }

    override fun onDestroy() {
        controlClient?.kill(false, null)
        setRootState(false)
        prefs.unregisterOnSharedPreferenceChangeListener(listener)
    }
}
