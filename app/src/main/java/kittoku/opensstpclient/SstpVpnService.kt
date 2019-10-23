package kittoku.opensstpclient

import android.R.drawable.ic_media_pause
import android.R.drawable.ic_secure
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.preference.PreferenceManager
import android.support.v4.app.NotificationCompat
import kittoku.opensstpclient.misc.DualClientStatus
import kittoku.opensstpclient.misc.LayerBridge
import kittoku.opensstpclient.misc.NetworkSetting
import kittoku.opensstpclient.misc.PppCredential
import kittoku.opensstpclient.packet.IpClient
import kittoku.opensstpclient.packet.PppClient
import kittoku.opensstpclient.packet.SslClient
import kittoku.opensstpclient.packet.SstpClient
import kotlinx.coroutines.*
import kotlin.coroutines.CoroutineContext


internal enum class VpnAction(val value: String) {
    ACTION_CONNECT("kittoku.opensstpclient.START"),
    ACTION_DISCONNECT("kittoku.opensstpclient.STOP")
}

internal class SstpVpnService : VpnService(), CoroutineScope {
    private val TAG = "SstpVpnService"
    private val CHANNEL_ID = "OpenSSTPClient"

    private val job = Job()
    private var vpnClient: VpnClient?  = null

    override val coroutineContext: CoroutineContext
        get() = Dispatchers.Default + job

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return if (VpnAction.ACTION_DISCONNECT.value == intent?.action ?: false) {
            vpnClient?.close()
            Service.START_NOT_STICKY
        } else {
            vpnClient?.close()
            beForegrounded()
            vpnClient = VpnClient(this).run()
            Service.START_STICKY
        }
    }

    private fun beForegrounded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, CHANNEL_ID, NotificationManager.IMPORTANCE_DEFAULT)
            val notificationManager: NotificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }

        val intent = Intent(this, SstpVpnService::class.java).setAction(VpnAction.ACTION_DISCONNECT.value)
        val pendingIntent = PendingIntent.getService(this, 0, intent, 0)
        //val action = NotificationCompat.Action(ic_media_pause, "DISCONNECT", pendingIntent)
        val builder = NotificationCompat.Builder(this, CHANNEL_ID).apply {
            setContentText("Open SSTP Client connecting")
            priority = NotificationCompat.PRIORITY_DEFAULT
            addAction(ic_media_pause, "DISCONNECT", pendingIntent)
        }

        startForeground(1, builder.build())
    }

    override fun onDestroy() { vpnClient?.close() }
}

private class VpnClient(val vpnService: SstpVpnService): CoroutineScope {
    private val job = Job()

    override val coroutineContext: CoroutineContext
        get() = Dispatchers.Default + job

    private val prefs = PreferenceManager.getDefaultSharedPreferences(vpnService.applicationContext)
    private val networkSetting = NetworkSetting(
        host = prefs.getString(PreferenceKey.HOST.value, null)!!,
        credential = PppCredential(prefs.getString(PreferenceKey.USERNAME.value, null)!!,
            prefs.getString(PreferenceKey.PASSWORD.value, null)!!))

    private val sslSstpBridge = LayerBridge()
    private val sstpPppBridge = LayerBridge()
    private val pppIpBridge = LayerBridge()
    private val status = DualClientStatus()
    private val builder = vpnService.Builder()

    private val sslClient = SslClient(vpnService, sslSstpBridge, networkSetting, false)
    private val sstpClient = SstpClient(sslSstpBridge, sstpPppBridge, networkSetting, status)
    private val pppClient = PppClient(sstpPppBridge, pppIpBridge, networkSetting, status)
    private val ipClient = IpClient(builder, pppIpBridge, networkSetting)

    private lateinit var sslJob: Job
    private lateinit var sstpJob: Job
    private lateinit var pppJob: Job
    private lateinit var ipJob: Job

    private fun launchJob(f: suspend () -> Unit): Job {
        return launch {
            try { f() }
            catch (e: Exception) { vpnService.stopSelf() }
        }
    }

    fun run(): VpnClient {
        sslJob = launchJob(sslClient::run)
        sstpJob = launchJob(sstpClient::run)
        pppJob = launchJob(pppClient::run)
        ipJob = launchJob(ipClient::run)

        return this
    }

    fun close() {
        launch {
            sslClient.job.cancelAndJoin()
            sstpClient.job.cancelAndJoin()
            pppClient.job.cancelAndJoin()
            ipClient.job.cancelAndJoin()

            sslJob.cancelAndJoin()
            sstpJob.cancelAndJoin()
            pppJob.cancelAndJoin()
            ipJob.cancelAndJoin()

            sslClient.release()
            ipClient.release()
        }

        vpnService.stopForeground(true)
    }
}