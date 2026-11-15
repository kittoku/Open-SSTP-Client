package kittoku.osc.service

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.TileService
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.documentfile.provider.DocumentFile
import androidx.preference.PreferenceManager
import kittoku.osc.R
import kittoku.osc.activity.MainActivity
import kittoku.osc.SharedBridge
import kittoku.osc.control.Controller
import kittoku.osc.control.LogWriter
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getIntPrefValue
import kittoku.osc.preference.accessor.getURIPrefValue
import kittoku.osc.preference.accessor.resetReconnectionLife
import kittoku.osc.preference.accessor.setBooleanPrefValue
import kittoku.osc.preference.accessor.setIntPrefValue
import kittoku.osc.NewsNotifier
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.suspendCancellableCoroutine
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.resume


internal const val ACTION_VPN_CONNECT = "kittoku.osc.connect"
internal const val ACTION_VPN_DISCONNECT = "kittoku.osc.disconnect"
internal const val ACTION_REFRESH_STATUS = "kittoku.osc.refresh_status"
internal const val PREF_WAITING_NETWORK = "waiting_network"

internal const val NOTIFICATION_ERROR_CHANNEL = "ERROR"
internal const val NOTIFICATION_RECONNECT_CHANNEL = "RECONNECT"
internal const val NOTIFICATION_DISCONNECT_CHANNEL = "DISCONNECT"
internal const val NOTIFICATION_CERTIFICATE_CHANNEL = "CERTIFICATE"
internal const val NOTIFICATION_STATUS_CHANNEL = "STATUS"

internal const val NOTIFICATION_ERROR_ID = 1
internal const val NOTIFICATION_RECONNECT_ID = 2
internal const val NOTIFICATION_DISCONNECT_ID = 3
internal const val NOTIFICATION_CERTIFICATE_ID = 4


internal class SstpVpnService : VpnService() {
    override fun attachBaseContext(newBase: android.content.Context) {
        super.attachBaseContext(kittoku.osc.LocaleFix.wrap(newBase))
    }

    private lateinit var prefs: SharedPreferences
    private lateinit var listener: SharedPreferences.OnSharedPreferenceChangeListener
    private lateinit var notificationManager: NotificationManagerCompat
    internal lateinit var scope: CoroutineScope

    internal var logWriter: LogWriter? = null
    private var controller: Controller?  = null

    private var jobReconnect: Job? = null
    @Volatile private var statusEnabled = false
    @Volatile private var lastStatus = ""

    private var networkWatcher: ConnectivityManager.NetworkCallback? = null
    private var newsJob: Job? = null
    private val networkAddresses = ConcurrentHashMap<Network, Set<String>>()
    @Volatile private var fastReconnect = false

    private fun setRootState(state: Boolean) {
        setBooleanPrefValue(state, OscPrefKey.ROOT_STATE, prefs)
    }

    private fun requestTileListening() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            TileService.requestListeningState(this,
                ComponentName(this, SstpTileService::class.java)
            )
        }
    }

    companion object {
        // False after the process was killed, so the screen can tell a stale "connected" state.
        @Volatile
        internal var isRunning = false
    }

    override fun onCreate() {
        isRunning = true
        notificationManager = NotificationManagerCompat.from(this)

        prefs = PreferenceManager.getDefaultSharedPreferences(this)

        listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key == OscPrefKey.ROOT_STATE.name) {
                val newState = getBooleanPrefValue(OscPrefKey.ROOT_STATE, prefs)

                setBooleanPrefValue(newState, OscPrefKey.HOME_CONNECTOR, prefs)
                requestTileListening()
            }
        }

        prefs.registerOnSharedPreferenceChangeListener(listener)

        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_VPN_CONNECT -> {
                startConnection()

                START_STICKY
            }

            ACTION_REFRESH_STATUS -> {
                // The user swiped the status notification away: show it again.
                if (statusEnabled) {
                    refreshStatusNotification()
                    START_STICKY
                } else {
                    stopSelf()
                    START_NOT_STICKY
                }
            }

            null -> {
                // The system restarted the service after killing the process.
                // If the user had not disconnected, connect again instead of closing.
                if (getBooleanPrefValue(OscPrefKey.ROOT_STATE, prefs) &&
                    getBooleanPrefValue(OscPrefKey.RECONNECTION_ENABLED, prefs)
                ) {
                    startConnection()

                    START_STICKY
                } else {
                    close()

                    START_NOT_STICKY
                }
            }

            else -> {
                // ensure that reconnection has been completely canceled or done
                runBlocking { jobReconnect?.cancelAndJoin() }

                controller?.disconnect()
                controller = null

                close()

                START_NOT_STICKY
            }
        }
    }

    private fun startConnection() {
        jobReconnect?.cancel()
        controller?.kill(false, null)
        statusEnabled = true
        clearErrorNotification()

        beForegrounded()
        resetReconnectionLife(prefs)
        if (getBooleanPrefValue(OscPrefKey.LOG_DO_SAVE_LOG, prefs)) {
            prepareLogWriter()
        }

        logWriter?.write("Establish VPN connection")

        startNetworkWatcher()
        startNewsLoop()
        initializeClient()

        setRootState(true)
    }

    private fun initializeClient() {
        setWaitingNetwork(false)
        updateStatus(getString(R.string.bs_status_connecting))

        controller = Controller(SharedBridge(this)).also {
            it.launchJobMain()
        }
    }

    private fun prepareLogWriter() {
        val currentDateTime = SimpleDateFormat("yyyyMMddHHmmss", Locale.getDefault()).format(Date())
        val filename = "log_osc_${currentDateTime}.txt"

        val prefURI = getURIPrefValue(OscPrefKey.LOG_DIR, prefs)
        if (prefURI == null) {
            notifyError("LOG: ERR_NULL_PREFERENCE")
            return
        }

        val dirURI = DocumentFile.fromTreeUri(this, prefURI)
        if (dirURI == null) {
            notifyError("LOG: ERR_NULL_DIRECTORY")
            return
        }

        val fileURI = dirURI.createFile("text/plain", filename)
        if (fileURI == null) {
            notifyError("LOG: ERR_NULL_FILE")
            return
        }

        val stream = contentResolver.openOutputStream(fileURI.uri, "wa")
        if (stream == null) {
            notifyError("LOG: ERR_NULL_STREAM")
            return
        }

        logWriter = LogWriter(stream)
    }

    internal fun launchJobReconnect() {
        jobReconnect = scope.launch {
            try {
                if (!hasUnderlyingNetwork()) {
                    // No internet at all: do not spend a reconnection attempt, just wait for a network.
                    setWaitingNetwork(true)
                    updateStatus(getString(R.string.bs_status_waiting_network))
                    logWriter?.report("Waiting for a network")

                    awaitUnderlyingNetwork()
                    setWaitingNetwork(false)
                    delay(3_000L)
                } else {
                    getIntPrefValue(OscPrefKey.RECONNECTION_LIFE, prefs).also {
                        val life = it - 1
                        setIntPrefValue(life, OscPrefKey.RECONNECTION_LIFE, prefs)

                        val message = "Reconnection will be tried (LIFE = $life)"
                        updateStatus(getString(R.string.bs_status_reconnecting))
                        logWriter?.report(message)
                    }

                    val interval = if (fastReconnect) 1_000L else getIntPrefValue(OscPrefKey.RECONNECTION_INTERVAL, prefs) * 1000L
                    fastReconnect = false

                    delay(interval)
                }

                initializeClient()
            } catch (_: CancellationException) { }
            finally {
                cancelNotification(NOTIFICATION_RECONNECT_ID)
            }
        }
    }

    private fun setWaitingNetwork(waiting: Boolean) {
        prefs.edit().putBoolean(PREF_WAITING_NETWORK, waiting).apply()
    }

    @Suppress("DEPRECATION")
    private fun hasUnderlyingNetwork(): Boolean {
        val manager = getSystemService(ConnectivityManager::class.java) ?: return true

        return manager.allNetworks.any { network ->
            val caps = manager.getNetworkCapabilities(network)

            caps != null &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        }
    }

    private suspend fun awaitUnderlyingNetwork() {
        val manager = getSystemService(ConnectivityManager::class.java) ?: return
        val request = underlyingNetworkRequest()
        var callback: ConnectivityManager.NetworkCallback? = null

        try {
            suspendCancellableCoroutine<Unit> { continuation ->
                callback = object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) {
                        if (continuation.isActive) continuation.resume(Unit)
                    }
                }

                manager.registerNetworkCallback(request, callback!!)
            }
        } finally {
            callback?.also {
                try {
                    manager.unregisterNetworkCallback(it)
                } catch (_: IllegalArgumentException) { }
            }
        }
    }

    private fun underlyingNetworkRequest(): NetworkRequest {
        return NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
    }

    private fun cleanAddress(address: String?): String? = address?.substringBefore('%')

    /** If the network carrying the tunnel disappears, reconnect right away instead of waiting for the echo timeout. */
    private fun startNetworkWatcher() {
        if (networkWatcher != null) return

        val manager = getSystemService(ConnectivityManager::class.java) ?: return

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                networkAddresses[network] = linkProperties.linkAddresses
                    .mapNotNull { cleanAddress(it.address.hostAddress) }
                    .toSet()
            }

            override fun onLost(network: Network) {
                val addresses = networkAddresses.remove(network)

                if (!statusEnabled || jobReconnect?.isActive == true) return
                if (!getBooleanPrefValue(OscPrefKey.RECONNECTION_ENABLED, prefs)) return

                val current = controller ?: return
                val local = cleanAddress(current.bridge.sslTerminal?.localAddress)

                // Ignore the loss of a network that the tunnel is not using.
                if (local != null && addresses != null && !addresses.contains(local)) return

                scope.launch { logWriter?.report("Network lost; reconnecting") }
                fastReconnect = true
                current.kill(true, null)
            }
        }

        try {
            manager.registerNetworkCallback(underlyingNetworkRequest(), callback)
            networkWatcher = callback
        } catch (_: Exception) { }
    }

    // While the VPN is on, news and updates are checked every five minutes.
    private fun startNewsLoop() {
        newsJob?.cancel()
        newsJob = scope.launch {
            while (true) {
                delay(5 * 60 * 1000L)
                NewsNotifier.checkAndNotify(applicationContext)
            }
        }
    }

    private fun stopNetworkWatcher() {
        networkWatcher?.also {
            try {
                getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(it)
            } catch (_: Exception) { }
        }

        networkWatcher = null
        networkAddresses.clear()
    }

    private fun beForegrounded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            arrayOf(
                NOTIFICATION_ERROR_CHANNEL,
                NOTIFICATION_RECONNECT_CHANNEL,
                NOTIFICATION_DISCONNECT_CHANNEL,
                NOTIFICATION_CERTIFICATE_CHANNEL,
            ).map {
                NotificationChannel(it, it, NotificationManager.IMPORTANCE_DEFAULT)
            }.also {
                notificationManager.createNotificationChannels(it)
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // A quiet channel for the permanent status notification (no sound on every update).
            NotificationChannel(
                NOTIFICATION_STATUS_CHANNEL,
                getString(R.string.bs_channel_status),
                NotificationManager.IMPORTANCE_LOW
            ).also {
                notificationManager.createNotificationChannel(it)
            }
        }

        startForeground(
            NOTIFICATION_DISCONNECT_ID,
            buildStatusNotification(getString(R.string.bs_status_connecting))
        )
    }

    private fun buildStatusNotification(status: String): Notification {
        val disconnectIntent = PendingIntent.getService(
            this,
            0,
            Intent(this, SstpVpnService::class.java).setAction(ACTION_VPN_DISCONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // If the user swipes the notification away it is shown again.
        val refreshIntent = PendingIntent.getService(
            this,
            2,
            Intent(this, SstpVpnService::class.java).setAction(ACTION_REFRESH_STATUS),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // Tapping the notification opens the app.
        val openIntent = PendingIntent.getActivity(
            this,
            1,
            Intent(this, MainActivity::class.java)
                .setAction(Intent.ACTION_MAIN)
                .addCategory(Intent.CATEGORY_LAUNCHER)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, NOTIFICATION_STATUS_CHANNEL).also {
            it.priority = NotificationCompat.PRIORITY_LOW
            it.setOngoing(true)
            it.setOnlyAlertOnce(true)
            it.setShowWhen(false)
            it.setSmallIcon(R.drawable.ic_baseline_vpn_lock_24)
            it.setContentTitle(getString(R.string.app_name))
            it.setContentText(status)
            it.setContentIntent(openIntent)
            it.setDeleteIntent(refreshIntent)
            it.addAction(R.drawable.ic_baseline_close_24, getString(R.string.bs_disconnect), disconnectIntent)
        }.build()
    }

    /** Shows what the connection is doing (connecting, getting IP, connected...) in the permanent notification. */
    internal fun updateStatus(status: String) {
        lastStatus = status

        // After the service is closed a late update must not bring the notification back.
        if (statusEnabled) {
            tryNotify(buildStatusNotification(status), NOTIFICATION_DISCONNECT_ID)
        }
    }

    private fun refreshStatusNotification() {
        val status = lastStatus.ifEmpty { getString(R.string.bs_status_connecting) }

        try {
            startForeground(NOTIFICATION_DISCONNECT_ID, buildStatusNotification(status))
        } catch (_: Exception) {
            tryNotify(buildStatusNotification(status), NOTIFICATION_DISCONNECT_ID)
        }
    }

    internal fun notifyMessage(message: String, id: Int, channel: String) {
        NotificationCompat.Builder(this, channel).also {
            it.setSmallIcon(R.drawable.ic_baseline_vpn_lock_24)
            it.setContentText(message)
            it.priority = NotificationCompat.PRIORITY_DEFAULT
            it.setAutoCancel(true)

            tryNotify(it.build(), id)
        }
    }

    internal fun notifyError(message: String) {
        notifyMessage(message, NOTIFICATION_ERROR_ID, NOTIFICATION_ERROR_CHANNEL)
    }

    internal fun tryNotify(notification: Notification, id: Int) {
        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
        ) {
            notificationManager.notify(id, notification)
        }
    }

    internal fun cancelNotification(id: Int) {
        notificationManager.cancel(id)
    }

    /** An old error must not stay in the notification shade after a new attempt or a successful connection. */
    internal fun clearErrorNotification() {
        cancelNotification(NOTIFICATION_ERROR_ID)
    }

    internal fun close() {
        statusEnabled = false
        stopNetworkWatcher()
        setWaitingNetwork(false)
        stopForeground(true)
        stopSelf()
    }

    override fun onDestroy() {
        isRunning = false
        logWriter?.write("Terminate VPN connection")
        logWriter?.close()
        logWriter = null

        controller?.kill(false, null)
        controller = null

        stopNetworkWatcher()

        scope.cancel()

        setRootState(false)
        prefs.unregisterOnSharedPreferenceChangeListener(listener)
    }
}
