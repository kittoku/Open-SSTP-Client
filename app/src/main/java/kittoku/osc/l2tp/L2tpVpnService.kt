package kittoku.osc.l2tp

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.arcansecurity.vpn.l2tpipsec.core.crypto.DhGroup
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspIntegrity
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeHash
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.L2tpIpsecTunnel
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.Phase1Proposal
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.Phase2Proposal
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelErrorKind
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelInfo
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelListener
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelState
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelStats
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.VpnConfig
import com.arcansecurity.vpn.l2tpipsec.core.util.LogLevel
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import kittoku.osc.R
import kittoku.osc.activity.MainActivity
import java.net.InetAddress
import java.net.UnknownHostException
import android.util.Log as AndroidLog

/**
 * The algorithm sets tried one after another. VPN Gate runs SoftEther, whose IPsec server accepts
 * only HMAC-SHA1-96 or HMAC-MD5-96 for ESP, so the library's SHA-256 default would be refused.
 */
internal object L2tpProposals {
    class Proposal(val name: String, val phase1: Phase1Proposal, val phase2: Phase2Proposal)

    val all = listOf(
        Proposal(
            "AES-256, SHA1, MODP-1024",
            Phase1Proposal(IkeEncryption.AES_CBC_256, IkeHash.SHA1, DhGroup.MODP_1024),
            Phase2Proposal(EspEncryption.ESP_AES_CBC_256, EspIntegrity.HMAC_SHA1_96, null),
        ),
        Proposal(
            "3DES, SHA1, MODP-1024",
            Phase1Proposal(IkeEncryption.TRIPLE_DES_CBC, IkeHash.SHA1, DhGroup.MODP_1024),
            Phase2Proposal(EspEncryption.ESP_3DES, EspIntegrity.HMAC_SHA1_96, null),
        ),
        Proposal(
            "AES-256, SHA-256, MODP-2048",
            Phase1Proposal(IkeEncryption.AES_CBC_256, IkeHash.SHA2_256, DhGroup.MODP_2048),
            Phase2Proposal(EspEncryption.ESP_AES_CBC_256, EspIntegrity.HMAC_SHA1_96, null),
        ),
    )
}

/** Runs the L2TP/IPsec stack of :l2tp-core inside a VpnService and reports to [Callbacks] (the bridge). */
class L2tpVpnService : VpnService() {

    /** What the bridge wants routed. Passed in memory: thousands of entries do not fit in an Intent. */
    class RouteSpec(
        /** "a.b.c.d/len" entries to route; empty means everything. */
        val routes: List<String> = emptyList(),
        /** Android 13 and newer: everything is routed except these ranges. */
        val excludedRoutes: List<String> = emptyList(),
    )

    interface Callbacks {
        fun onTunnelState(state: TunnelState, detail: String?)
        fun onTunnelConnected(info: TunnelInfo)
        fun onTunnelStats(stats: TunnelStats)
        fun onTunnelFailed(kind: TunnelErrorKind, message: String)
        /** [userRequested]: the notification button, the app, or Android revoking the VPN asked for it. */
        fun onTunnelEnded(userRequested: Boolean)
        fun onLog(line: String)
    }

    companion object {
        const val ACTION_CONNECT = "kittoku.osc.l2tp.ACTION_CONNECT"
        const val ACTION_DISCONNECT = "kittoku.osc.l2tp.ACTION_DISCONNECT"

        const val EXTRA_HOST = "host"
        const val EXTRA_USER = "user"
        const val EXTRA_PASSWORD = "password"
        const val EXTRA_PSK = "psk"
        const val EXTRA_PROPOSAL = "proposal"
        const val EXTRA_DNS = "dns"
        const val EXTRA_EXCLUDED_APPS = "excluded_apps"

        private const val CHANNEL_ID = "banafsh_l2tp"
        private const val NOTIFICATION_ID = 4721
        private const val FORCE_CLOSE_DELAY_MS = 3000L
        private const val TAG = "L2tpVpnService"

        @Volatile
        var callbacks: Callbacks? = null

        @Volatile
        var routeSpec: RouteSpec = RouteSpec()

        @Volatile
        var isRunning = false
            private set
    }

    private val mainHandler = Handler(Looper.getMainLooper())

    @Volatile private var worker: Thread? = null
    @Volatile private var tunnel: L2tpIpsecTunnel? = null
    @Volatile private var factory: AndroidUdpSocketFactory? = null
    @Volatile private var stopRequested = false

    // Detailed handshake traces help to see why a server refused; per-packet traces would only flood the log.
    @Volatile private var debugLogging = true

    private val tunDescriptor = java.util.concurrent.atomic.AtomicReference<ParcelFileDescriptor?>(null)

    private val logger = object : VpnLogger {
        override fun log(level: LogLevel, tag: String, message: String, error: Throwable?) {
            val line = "$level $tag: $message" + (error?.let { " (${it.javaClass.simpleName}: ${it.message})" } ?: "")

            when (level) {
                LogLevel.DEBUG -> AndroidLog.d(TAG, line)
                LogLevel.INFO -> AndroidLog.i(TAG, line)
                LogLevel.WARN -> AndroidLog.w(TAG, line)
                LogLevel.ERROR -> AndroidLog.e(TAG, line)
            }
            callbacks?.onLog(line)
        }

        override fun isEnabled(level: LogLevel): Boolean = level != LogLevel.DEBUG || debugLogging
    }

    private val tunnelListener = object : TunnelListener {
        override fun onStateChanged(state: TunnelState, detail: String?) {
            mainHandler.post { callbacks?.onTunnelState(state, detail) }
        }

        override fun onConnected(info: TunnelInfo) {
            debugLogging = false
            mainHandler.post {
                callbacks?.onTunnelConnected(info)
                updateNotification(getString(R.string.bs_l2tp_connected))
            }
        }

        override fun onStats(stats: TunnelStats) {
            mainHandler.post { callbacks?.onTunnelStats(stats) }
        }

        override fun onFailed(kind: TunnelErrorKind, message: String, cause: Throwable?) {
            // Closing the tunnel on purpose also ends PPP and the sockets: that is not a failure.
            if (stopRequested) return
            mainHandler.post { callbacks?.onTunnelFailed(kind, message) }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Started with startForegroundService: the notification is owed whatever the action is.
        enterForeground(getString(R.string.bs_l2tp_connecting))

        when (intent?.action) {
            ACTION_CONNECT -> if (worker == null) startWorker(intent) else logger.log(LogLevel.WARN, TAG, "Connect while running: ignored", null)
            ACTION_DISCONNECT -> stopTunnel()
            else -> stopSelf()
        }

        return START_NOT_STICKY
    }

    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    // ---- the tunnel ---------------------------------------------------------------------------

    private fun startWorker(intent: Intent) {
        val host = intent.getStringExtra(EXTRA_HOST).orEmpty()
        val proposal = L2tpProposals.all[intent.getIntExtra(EXTRA_PROPOSAL, 0).coerceIn(0, L2tpProposals.all.size - 1)]
        val dns = intent.getStringExtra(EXTRA_DNS).orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() }

        val config = try {
            VpnConfig(
                serverHost = host,
                presharedKey = intent.getStringExtra(EXTRA_PSK).orEmpty(),
                username = intent.getStringExtra(EXTRA_USER).orEmpty(),
                password = intent.getStringExtra(EXTRA_PASSWORD).orEmpty(),
                phase1 = proposal.phase1,
                phase2 = proposal.phase2,
                dnsOverride = dns,
                connectTimeoutMs = 15_000,
            )
        } catch (e: IllegalArgumentException) {
            callbacks?.onTunnelFailed(TunnelErrorKind.INTERNAL, e.message ?: "Invalid settings")
            callbacks?.onTunnelEnded(false)
            stopSelf()
            return
        }

        val spec = routeSpec
        val excluded = intent.getStringArrayExtra(EXTRA_EXCLUDED_APPS)?.toList().orEmpty()

        stopRequested = false
        debugLogging = true
        isRunning = true

        worker = Thread({ runTunnel(config, spec, excluded) }, "L2tpTunnel").also { it.start() }
    }

    private fun runTunnel(config: VpnConfig, spec: RouteSpec, excluded: List<String>) {
        try {
            val address = try {
                InetAddress.getByName(config.serverHost)
            } catch (e: UnknownHostException) {
                mainHandler.post { callbacks?.onTunnelFailed(TunnelErrorKind.DNS_FAILURE, "Could not resolve the server name") }
                return
            }

            val socketFactory = AndroidUdpSocketFactory(this, address, logger)
            factory = socketFactory

            val tunProvider = L2tpTunProvider(
                service = this,
                routes = spec.routes,
                excludedRoutes = spec.excludedRoutes,
                excludedApps = excluded,
                onEstablished = { descriptor ->
                    tunDescriptor.getAndSet(descriptor)?.let { stale -> runCatching { stale.close() } }
                },
                configureIntent = openAppIntent(),
                logger = logger,
            )

            val instance = L2tpIpsecTunnel(
                config = config,
                socketFactory = socketFactory,
                tunProvider = tunProvider,
                listener = tunnelListener,
                logger = logger,
            )
            tunnel = instance

            // Returns when the tunnel ends for any reason; failures were reported through the listener.
            instance.run()
        } catch (t: Throwable) {
            if (!stopRequested) {
                mainHandler.post { callbacks?.onTunnelFailed(TunnelErrorKind.INTERNAL, t.message ?: t.toString()) }
            }
        } finally {
            tunnel = null
            runCatching { factory?.closeAll() }
            factory = null
            tunDescriptor.getAndSet(null)?.let { runCatching { it.close() } }

            worker = null
            isRunning = false

            val byUser = stopRequested
            mainHandler.post {
                callbacks?.onTunnelEnded(byUser)
                stopSelf()
            }
        }
    }

    private fun stopTunnel() {
        stopRequested = true

        val running = tunnel
        if (running != null) {
            running.stop()

            // A blocking receive cannot be interrupted: if the worker has not finished soon, close the sockets under it.
            mainHandler.postDelayed({ runCatching { factory?.closeAll() } }, FORCE_CLOSE_DELAY_MS)
        } else if (worker == null) {
            stopSelf()
        } else {
            runCatching { factory?.closeAll() }
        }
    }

    // ---- notification ---------------------------------------------------------------------------

    private fun openAppIntent(): PendingIntent {
        return PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
    }

    private fun buildNotification(text: String): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && manager.getNotificationChannel(CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, getString(R.string.bs_l2tp_channel), NotificationManager.IMPORTANCE_LOW)
            )
        }

        val disconnect = Intent(this, L2tpVpnService::class.java).setAction(ACTION_DISCONNECT)
        val disconnectIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            PendingIntent.getForegroundService(this, 1, disconnect, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        } else {
            PendingIntent.getService(this, 1, disconnect, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        }

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_baseline_vpn_lock_24)
            .setContentTitle(getString(R.string.bs_protocol_l2tp))
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openAppIntent())
            .addAction(0, getString(R.string.bs_l2tp_disconnect), disconnectIntent)
            .build()
    }

    private fun enterForeground(text: String) {
        val notification = buildNotification(text)

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            AndroidLog.e(TAG, "Could not enter the foreground", e)
        }
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, buildNotification(text))
    }
}
