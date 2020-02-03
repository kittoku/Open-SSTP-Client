package kittoku.opensstpclient

import android.R.drawable.ic_media_pause
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
import kittoku.opensstpclient.layer.*
import kittoku.opensstpclient.misc.IncomingBuffer
import kittoku.opensstpclient.misc.NetworkSetting
import kittoku.opensstpclient.misc.SuicideException
import kittoku.opensstpclient.misc.inform
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.nio.ByteBuffer


internal enum class VpnAction(val value: String) {
    ACTION_CONNECT("kittoku.opensstpclient.START"),
    ACTION_DISCONNECT("kittoku.opensstpclient.STOP")
}

internal class SstpVpnService : VpnService() {
    private val TAG = "SstpVpnService"
    private val CHANNEL_ID = "OpenSSTPClient"
    private var controlClient: ControlClient?  = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return if (VpnAction.ACTION_DISCONNECT.value == intent?.action ?: false) {
            controlClient?.killIntendedly()
            Service.START_NOT_STICKY
        } else {
            controlClient?.killIntendedly()
            beForegrounded()
            controlClient = ControlClient(this).also { it.run() }
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
        val builder = NotificationCompat.Builder(this, CHANNEL_ID).also {
            it.setContentText("Open SSTP Client connecting")
            it.priority = NotificationCompat.PRIORITY_DEFAULT
            it.addAction(ic_media_pause, "DISCONNECT", pendingIntent)
        }

        startForeground(1, builder.build())
    }

    override fun onDestroy() { controlClient?.killIntendedly() }
}

internal class ControlClient(internal val vpnService: SstpVpnService)
    : CoroutineScope by CoroutineScope(Dispatchers.Default + SupervisorJob()) {
    internal val prefs = PreferenceManager.getDefaultSharedPreferences(vpnService.applicationContext)
    internal val networkSetting = NetworkSetting(
        prefs.getString(PreferenceKey.HOST.value, null)!!,
        prefs.getString(PreferenceKey.USERNAME.value, null)!!,
        prefs.getString(PreferenceKey.PASSWORD.value, null)!!
    )
    internal val status = DualClientStatus()
    internal val builder = vpnService.Builder()
    internal val incomingBuffer = IncomingBuffer(INCOMING_BUFFER_SIZE)
    internal val outgoingBuffer = ByteBuffer.allocate(OUTGOING_BUFFER_SIZE)

    internal val sslTerminal = SslTerminal(this)
    private val sstpClient = SstpClient(this)
    private val pppClient = PppClient(this)
    internal val ipTerminal = IpTerminal(this)

    private var jobIncoming: Job? = null
    private var jobOutgoing: Job? = null

    private val mutex = Mutex()
    private var isClosing = false
    private var isIntendedToClose = false

    private val handler = CoroutineExceptionHandler { _, exception ->
        launch {
            mutex.withLock {
                if (!isClosing) {
                    if (exception is SuicideException) {
                        if (isIntendedToClose) {
                            inform("Terminate VPN connection", null)
                        } else {
                            inform("Terminate VPN connection", exception)
                        }
                    } else {
                        inform("An unexpected event occurred", exception)
                    }

                    jobIncoming?.cancel()
                    jobOutgoing?.cancel()

                    sslTerminal.release()
                    ipTerminal.release()

                    jobIncoming?.join()
                    jobOutgoing?.join()

                    vpnService.stopForeground(true)
                }

                isClosing = true
            }
        }
    }

    internal fun run() {
        inform("Establish VPN connection", null)
        jobIncoming = launch(handler) {
            while (isActive) {
                sstpClient.proceed()
                pppClient.proceed()

                if (isIntendedToClose) {
                    status.sstp = SstpStatus.CALL_DISCONNECT_IN_PROGRESS_1
                }
            }
        }

        jobOutgoing = launch(handler) {
            while (isActive) {
                if (sstpClient.waitingControlUnits.any()) {
                    sstpClient.sendControlUnit()
                    continue
                }

                if (pppClient.waitingControlUnits.any()) pppClient.sendControlUnit()
                else pppClient.sendDataUnit()

                sstpClient.sendDataUnit()
            }
        }
    }

    internal fun killIntendedly() {
        isIntendedToClose = true
    }
}
