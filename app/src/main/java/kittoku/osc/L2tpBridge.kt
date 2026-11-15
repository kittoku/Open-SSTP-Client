package kittoku.osc

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.documentfile.provider.DocumentFile
import androidx.preference.PreferenceManager
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelErrorKind
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelInfo
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelState
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelStats
import kittoku.osc.control.LogWriter
import kittoku.osc.l2tp.L2tpProposals
import kittoku.osc.l2tp.L2tpVpnService
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getIntPrefValue
import kittoku.osc.preference.accessor.getSetPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue
import kittoku.osc.preference.accessor.getURIPrefValue
import kittoku.osc.preference.accessor.setBooleanPrefValue
import kittoku.osc.preference.accessor.setStringPrefValue
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Log file used from the tunnel threads and the main thread. */
private class L2tpLogSink(private val writer: LogWriter) {
    private var closed = false

    @Synchronized
    fun write(message: String) {
        if (closed) return
        try {
            writer.write(message)
            writer.flush()
        } catch (_: Exception) {
        }
    }

    @Synchronized
    fun close() {
        if (closed) return
        closed = true
        try {
            writer.close()
        } catch (_: Exception) {
        }
    }
}

/**
 * Connects the experimental L2TP/IPsec tunnel to the screens the other protocols use: it writes the
 * preferences the home screen and the tile watch (ROOT_STATE, HOME_CONNECTOR, HOME_STATUS), tries
 * the next algorithm set when a server refuses the first, repeats the connection after a drop, and
 * writes a log file next to the SSTP one.
 */
internal object L2tpBridge : L2tpVpnService.Callbacks {
    private const val UI_PREFS = "banafsh_ui"
    private const val KEY_ACTIVE = "l2tp_active"

    // VPN Gate: every public server answers to these (the pre-shared key, the user and the password are all "vpn").
    private const val VPN_GATE_SECRET = "vpn"

    private const val RESTART_DELAY_MS = 2000L
    private const val NEXT_PROPOSAL_DELAY_MS = 1000L

    // Only a server that answers and refuses is worth another algorithm set; silence would stay silence.
    private val REFUSALS = setOf(
        TunnelErrorKind.IKE_PROPOSAL_REJECTED,
        TunnelErrorKind.IKE_AUTH_FAILED,
        TunnelErrorKind.IPSEC_SA_FAILED,
    )

    private val handler = Handler(Looper.getMainLooper())

    private var appContext: Context? = null
    private var registered = false

    @Volatile private var userStopped = true
    @Volatile private var restarting = false
    @Volatile private var retryPending = false
    @Volatile private var established = false
    private var retriesLeft = 0
    private var attempt = 0
    private var proposalIndex = 0
    private var lastFailure: String? = null
    private var lastFailureKind: TunnelErrorKind? = null
    private var silenceRetried = false
    private var lastTrafficLogAt = 0L

    @Volatile private var logSink: L2tpLogSink? = null

    private val retryTask = Runnable {
        retryPending = false

        val app = appContext ?: return@Runnable
        if (userStopped) return@Runnable

        if (ProtocolSwitch.get(app) != Protocol.L2TP) {
            // The user chose another service while we were waiting: do not come back with this one.
            finish(app, PreferenceManager.getDefaultSharedPreferences(app))
            return@Runnable
        }

        begin(app)
    }

    fun init(context: Context) {
        appContext = context.applicationContext

        if (!registered) {
            registered = true
            L2tpVpnService.callbacks = this

            // The process died while L2TP was active: its saved "connected" state is stale.
            val app = appContext!!
            if (isActive(app) && !L2tpVpnService.isRunning) {
                finish(app, PreferenceManager.getDefaultSharedPreferences(app), logIt = false)
            }
        }
    }

    private fun ui(context: Context) = context.getSharedPreferences(UI_PREFS, Context.MODE_PRIVATE)

    private fun isActive(context: Context) = ui(context).getBoolean(KEY_ACTIVE, false)

    private fun setActive(context: Context, active: Boolean) {
        ui(context).edit().putBoolean(KEY_ACTIVE, active).apply()
    }

    fun isRunning(): Boolean = retryPending || restarting || L2tpVpnService.isRunning

    fun clearActive(context: Context) {
        setActive(context.applicationContext, false)
    }

    // ---- start / stop -----------------------------------------------------------------------

    fun connect(context: Context) {
        val app = context.applicationContext
        init(app)
        val prefs = PreferenceManager.getDefaultSharedPreferences(app)

        handler.removeCallbacksAndMessages(null)
        retryPending = false
        userStopped = false
        established = false
        attempt = 0
        proposalIndex = 0
        lastFailure = null
        lastFailureKind = null
        silenceRetried = false

        retriesLeft = if (getBooleanPrefValue(OscPrefKey.RECONNECTION_ENABLED, prefs)) {
            getIntPrefValue(OscPrefKey.RECONNECTION_COUNT, prefs)
        } else 0

        setActive(app, true)
        setBooleanPrefValue(true, OscPrefKey.ROOT_STATE, prefs)
        setBooleanPrefValue(true, OscPrefKey.HOME_CONNECTOR, prefs)
        setStringPrefValue("", OscPrefKey.HOME_STATUS, prefs)

        closeLog()
        logSink = openSink(app, prefs)
        log("L2TP/IPsec connect requested")
        log("Device: Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}), ABIs ${Build.SUPPORTED_ABIS.joinToString()}, ${Build.MANUFACTURER} ${Build.MODEL}")

        if (L2tpVpnService.isRunning) {
            // Still connected to an old server: drop it first so the new one is really used.
            restarting = true
            sendDisconnect(app)
            handler.postDelayed({
                restarting = false
                if (!userStopped) begin(app)
            }, RESTART_DELAY_MS)
        } else {
            begin(app)
        }
    }

    fun disconnect(context: Context) {
        val app = context.applicationContext
        init(app)
        val prefs = PreferenceManager.getDefaultSharedPreferences(app)

        userStopped = true
        restarting = false
        retryPending = false
        handler.removeCallbacksAndMessages(null)
        log("Disconnect requested by the user")

        if (L2tpVpnService.isRunning) {
            // The end-of-tunnel report that follows clears the saved state.
            sendDisconnect(app)
        } else {
            finish(app, prefs)
        }
    }

    private fun begin(app: Context) {
        val prefs = PreferenceManager.getDefaultSharedPreferences(app)

        attempt++
        established = false
        lastFailure = null
        lastFailureKind = null

        try {
            val host = getStringPrefValue(OscPrefKey.HOME_HOSTNAME, prefs)
            val spec = routeSpec(app, prefs)
            L2tpVpnService.routeSpec = spec
            val excluded = excludedApps(prefs)
            val proposal = L2tpProposals.all[proposalIndex]
            val dns = DnsPresets.addresses(prefs).joinToString(",")

            log(
                "Attempt $attempt: $host, user=vpn, algorithms: ${proposal.name} (set ${proposalIndex + 1} of ${L2tpProposals.all.size}), " +
                    "routes=${spec.routes.size}, excludedRoutes=${spec.excludedRoutes.size}, bypassApps=${excluded.size}, dns=${dns.ifEmpty { "(from the server)" }}"
            )

            ContextCompat.startForegroundService(
                app,
                Intent(app, L2tpVpnService::class.java)
                    .setAction(L2tpVpnService.ACTION_CONNECT)
                    .putExtra(L2tpVpnService.EXTRA_HOST, host)
                    .putExtra(L2tpVpnService.EXTRA_USER, getStringPrefValue(OscPrefKey.HOME_USERNAME, prefs).ifEmpty { VPN_GATE_SECRET })
                    .putExtra(L2tpVpnService.EXTRA_PASSWORD, getStringPrefValue(OscPrefKey.HOME_PASSWORD, prefs).ifEmpty { VPN_GATE_SECRET })
                    .putExtra(L2tpVpnService.EXTRA_PSK, VPN_GATE_SECRET)
                    .putExtra(L2tpVpnService.EXTRA_PROPOSAL, proposalIndex)
                    .putExtra(L2tpVpnService.EXTRA_DNS, dns)
                    .putExtra(L2tpVpnService.EXTRA_EXCLUDED_APPS, excluded.toTypedArray())
            )
        } catch (e: Exception) {
            log("Attempt $attempt: could not start the L2TP service: $e")
            finish(app, prefs)
        }
    }

    private fun sendDisconnect(app: Context) {
        ContextCompat.startForegroundService(
            app,
            Intent(app, L2tpVpnService::class.java).setAction(L2tpVpnService.ACTION_DISCONNECT)
        )
    }

    // ---- reports from the service (main thread, except onLog) ---------------------------------------

    override fun onTunnelState(state: TunnelState, detail: String?) {
        val app = appContext ?: return
        if (!isActive(app)) return

        log("State: $state" + if (!detail.isNullOrEmpty()) " ($detail)" else "")

        val prefs = PreferenceManager.getDefaultSharedPreferences(app)

        when (state) {
            TunnelState.RESOLVING,
            TunnelState.IKE_PHASE1,
            TunnelState.IKE_PHASE2,
            TunnelState.L2TP_TUNNEL,
            TunnelState.L2TP_SESSION,
            TunnelState.PPP_NEGOTIATION,
            TunnelState.RECONNECTING -> {
                setBooleanPrefValue(true, OscPrefKey.ROOT_STATE, prefs)
                setBooleanPrefValue(true, OscPrefKey.HOME_CONNECTOR, prefs)
                if (state != TunnelState.RECONNECTING) setStringPrefValue("", OscPrefKey.HOME_STATUS, prefs)
            }

            else -> Unit
        }
    }

    override fun onTunnelConnected(info: TunnelInfo) {
        val app = appContext ?: return
        if (!isActive(app)) return

        established = true
        lastFailure = null
        retriesLeft = reconnectionCount(PreferenceManager.getDefaultSharedPreferences(app))

        log(
            "Connected: address ${info.assignedAddress}, dns ${info.dnsServers.joinToString(",").ifEmpty { "(none)" }}, mtu ${info.mtu}, " +
                "NAT ${info.natDetected}, UDP encapsulation ${info.udpEncapsulated}, phase 1 ${info.phase1Description}, " +
                "phase 2 ${info.phase2Description}, PPP ${info.pppAuthDescription}"
        )

        val prefs = PreferenceManager.getDefaultSharedPreferences(app)
        val host = getStringPrefValue(OscPrefKey.HOME_HOSTNAME, prefs)

        setBooleanPrefValue(true, OscPrefKey.ROOT_STATE, prefs)
        setBooleanPrefValue(true, OscPrefKey.HOME_CONNECTOR, prefs)
        setStringPrefValue("L2TP/IPsec\n$host\n${info.assignedAddress}", OscPrefKey.HOME_STATUS, prefs)
    }

    override fun onTunnelStats(stats: TunnelStats) {
        val now = SystemClock.elapsedRealtime()
        if (now - lastTrafficLogAt < 5000L) return
        lastTrafficLogAt = now

        log("Traffic: sent ${stats.bytesOut} B / ${stats.packetsOut} pkts, received ${stats.bytesIn} B / ${stats.packetsIn} pkts")
    }

    override fun onTunnelFailed(kind: TunnelErrorKind, message: String) {
        lastFailure = "$kind: $message"
        lastFailureKind = kind
        log("Failed: $kind: $message")
    }

    override fun onLog(line: String) {
        logSink?.write("[${SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US).format(Date())}] $line")
    }

    override fun onTunnelEnded(userRequested: Boolean) {
        val app = appContext ?: return
        if (!isActive(app) || restarting) return

        // The notification button and Android's own "disconnect" end the tunnel without going through disconnect().
        if (userRequested) userStopped = true

        val prefs = PreferenceManager.getDefaultSharedPreferences(app)
        log("The tunnel ended" + (if (userStopped) " (asked by the user)" else ""))

        if (!userStopped) {
            // The server refused during the IPsec negotiation: try the next algorithm set at once.
            // (Failures later on, in L2TP or PPP, or on the network itself, would fail the same way again.)
            if (!established && lastFailureKind in REFUSALS && proposalIndex + 1 < L2tpProposals.all.size) {
                proposalIndex++
                scheduleRetry(NEXT_PROPOSAL_DELAY_MS, prefs, "Trying the next algorithm set")
                return
            }

            // No answer at all: one more try with the same set (a single lost packet looks the same).
            if (!established && lastFailureKind == TunnelErrorKind.IKE_NO_RESPONSE && !silenceRetried) {
                silenceRetried = true
                scheduleRetry(NEXT_PROPOSAL_DELAY_MS, prefs, "No answer: trying once more")
                return
            }

            // It was up and dropped: use the app's reconnection settings.
            if (established && retriesLeft > 0 && VpnService.prepare(app) == null) {
                retriesLeft--
                val seconds = getIntPrefValue(OscPrefKey.RECONNECTION_INTERVAL, prefs).coerceAtLeast(1)
                scheduleRetry(seconds * 1000L, prefs, "Reconnecting")
                return
            }

            val failure = lastFailure.orEmpty()

            when {
                lastFailureKind == TunnelErrorKind.IKE_NO_RESPONSE ->
                    Toast.makeText(app, R.string.bs_l2tp_no_response, Toast.LENGTH_LONG).show()

                // The server accepted the login but refuses to hand out an address.
                failure.contains("IPCP", ignoreCase = true) ->
                    Toast.makeText(app, R.string.bs_l2tp_no_address, Toast.LENGTH_LONG).show()

                failure.isNotEmpty() ->
                    Toast.makeText(app, app.getString(R.string.bs_l2tp_failed, failure), Toast.LENGTH_LONG).show()
            }
        }

        finish(app, prefs)
    }

    private fun scheduleRetry(delayMs: Long, prefs: SharedPreferences, why: String) {
        retryPending = true
        log("$why in ${delayMs / 1000.0} s")

        // The screen shows "connecting" while we wait.
        setBooleanPrefValue(true, OscPrefKey.HOME_CONNECTOR, prefs)
        setStringPrefValue("", OscPrefKey.HOME_STATUS, prefs)

        handler.postDelayed(retryTask, delayMs)
    }

    private fun finish(app: Context, prefs: SharedPreferences, logIt: Boolean = true) {
        if (logIt) log("L2TP/IPsec session finished")
        closeLog()

        handler.removeCallbacks(retryTask)
        retryPending = false
        userStopped = true

        setActive(app, false)
        setBooleanPrefValue(false, OscPrefKey.ROOT_STATE, prefs)
        setBooleanPrefValue(false, OscPrefKey.HOME_CONNECTOR, prefs)
        setStringPrefValue("", OscPrefKey.HOME_STATUS, prefs)
    }

    private fun reconnectionCount(prefs: SharedPreferences): Int {
        return if (getBooleanPrefValue(OscPrefKey.RECONNECTION_ENABLED, prefs)) {
            getIntPrefValue(OscPrefKey.RECONNECTION_COUNT, prefs)
        } else 0
    }

    // ---- settings -> what the service needs ------------------------------------------------------

    // Same rule as the other tunnels: Iranian apps and the apps the user picked connect directly.
    private fun excludedApps(prefs: SharedPreferences): List<String> {
        if (!prefs.getBoolean(IranApps.KEY_ENABLED, true)) return emptyList()

        val packages = HashSet<String>()
        prefs.getStringSet(IranApps.KEY_LIST, null)?.let { packages.addAll(it) }
        packages.addAll(getSetPrefValue(OscPrefKey.ROUTE_SELECTED_APPS, prefs))

        return packages.toList()
    }

    // "Iranian sites connect directly" switch. Android 13 and newer: the ranges are excluded from one default
    // route (like SSTP does). Older Android: everything except the ranges is routed. Empty: everything.
    private fun routeSpec(app: Context, prefs: SharedPreferences): L2tpVpnService.RouteSpec {
        if (!prefs.getBoolean(IranRanges.KEY_ENABLED, false)) return L2tpVpnService.RouteSpec()

        val ranges = IranRanges.load(app)
        if (ranges.isEmpty()) return L2tpVpnService.RouteSpec()

        return try {
            if (Build.VERSION.SDK_INT >= 33) {
                val excluded = IranRanges.toCidrs(ranges)
                if (excluded.size > IranRanges.MAX_ROUTES) L2tpVpnService.RouteSpec()
                else L2tpVpnService.RouteSpec(excludedRoutes = excluded.map { (a, l) -> "${IranRanges.format(a)}/$l" })
            } else {
                val routes = IranRanges.complementCidrs(ranges)
                if (routes.size > IranRanges.MAX_ROUTES) L2tpVpnService.RouteSpec()
                else L2tpVpnService.RouteSpec(routes = routes.map { (a, l) -> "${IranRanges.format(a)}/$l" })
            }
        } catch (_: Exception) {
            L2tpVpnService.RouteSpec()
        }
    }

    // ---- log file (same folder as the other logs) -----------------------------------------------------

    private fun openSink(app: Context, prefs: SharedPreferences): L2tpLogSink? {
        if (!getBooleanPrefValue(OscPrefKey.LOG_DO_SAVE_LOG, prefs)) return null

        return try {
            val uri = getURIPrefValue(OscPrefKey.LOG_DIR, prefs) ?: return null
            val dir = DocumentFile.fromTreeUri(app, uri) ?: return null
            val stamp = SimpleDateFormat("yyyyMMddHHmmss", Locale.getDefault()).format(Date())
            val file = dir.createFile("text/plain", "log_osc_${stamp}_l2tp.txt") ?: return null
            val stream = app.contentResolver.openOutputStream(file.uri, "wa") ?: return null
            L2tpLogSink(LogWriter(stream))
        } catch (_: Exception) {
            null
        }
    }

    private fun log(message: String) {
        logSink?.write("[${SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US).format(Date())}] $message")
    }

    private fun closeLog() {
        val sink = logSink ?: return
        logSink = null
        sink.close()
    }
}
