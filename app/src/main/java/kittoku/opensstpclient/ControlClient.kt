package kittoku.opensstpclient

import android.content.Intent
import android.preference.PreferenceManager
import android.support.v4.content.LocalBroadcastManager
import android.widget.Toast
import kittoku.opensstpclient.layer.*
import kittoku.opensstpclient.misc.IncomingBuffer
import kittoku.opensstpclient.misc.NetworkSetting
import kittoku.opensstpclient.misc.SuicideException
import kittoku.opensstpclient.misc.inform
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.nio.ByteBuffer


internal class ControlClient(internal val vpnService: SstpVpnService) :
    CoroutineScope by CoroutineScope(Dispatchers.IO + SupervisorJob()) {
    internal lateinit var networkSetting: NetworkSetting
    internal val status = DualClientStatus()
    internal val builder = vpnService.Builder()
    internal val incomingBuffer = IncomingBuffer(INCOMING_BUFFER_SIZE, this)
    internal val outgoingBuffer = ByteBuffer.allocate(OUTGOING_BUFFER_SIZE)

    internal lateinit var sslTerminal: SslTerminal
    private lateinit var sstpClient: SstpClient
    private lateinit var pppClient: PppClient
    internal lateinit var ipTerminal: IpTerminal

    private var jobIncoming: Job? = null
    private var jobOutgoing: Job? = null

    private val mutex = Mutex()
    private var isClosing = false

    private val handler = CoroutineExceptionHandler { _, exception ->
        if (!isClosing) kill(exception)
    }

    internal fun kill(exception: Throwable?) {
        launch {
            mutex.withLock {
                if (!isClosing) {
                    isClosing = true

                    if (exception != null) {
                        inform("An unexpected event occurred", exception)
                    }

                    jobIncoming?.join()
                    jobOutgoing?.join()

                    sslTerminal.release()
                    ipTerminal.release()

                    vpnService.stopForeground(true)
                    LocalBroadcastManager.getInstance(vpnService)
                        .sendBroadcast(Intent(VpnAction.ACTION_SWITCHOFF.value))

                    inform("Terminate VPN connection", null)

                }
            }
        }
    }

    private fun makeToast(cause: String) {
        Toast.makeText(vpnService.applicationContext, "INVALID SETTING: $cause", Toast.LENGTH_LONG)
            .show()
    }

    internal fun prepareSetting(): Boolean {
        val prefs = PreferenceManager.getDefaultSharedPreferences(vpnService.applicationContext)

        val host = prefs.getString(PreferenceKey.HOST.value, null)
        if (host == null) {
            makeToast("Host is missing")
            return false
        }

        val username = prefs.getString(PreferenceKey.USERNAME.value, null)
        if (username == null) {
            makeToast("Username is missing")
            return false
        }

        val password = prefs.getString(PreferenceKey.PASSWORD.value, null)
        if (password == null) {
            makeToast("Password is missing")
            return false
        }

        val port = prefs.getString(PreferenceKey.PORT.value, null)?.toIntOrNull()
        if (port != null && port !in 0..65535) {
            makeToast("The given port is out of 0-65535")
            return false
        }

        val mru = prefs.getString(PreferenceKey.MRU.value, null)?.toIntOrNull()
        if (mru != null && mru !in MIN_MRU..MAX_MRU) {
            makeToast("The given MRU is out of $MIN_MRU-$MAX_MRU")
            return false
        }

        val mtu = prefs.getString(PreferenceKey.MTU.value, null)?.toIntOrNull()
        if (mtu != null && mtu !in MIN_MTU..MAX_MTU) {
            makeToast("The given MTU is out of $MIN_MTU-$MAX_MTU")
            return false
        }

        val prefix = prefs.getString(PreferenceKey.PREFIX.value, null)?.toIntOrNull()
        if (prefix != null && prefix !in 0..32) {
            makeToast("The given address prefix is out of 0-32")
            return false
        }

        val isPapAcceptable = prefs.getBoolean(PreferenceKey.PAP.value, true)
        val isMschapv2Acceptable = prefs.getBoolean(PreferenceKey.MSCHAPv2.value, true)
        if (!(isPapAcceptable || isMschapv2Acceptable)) {
            makeToast("No authentication protocol was accepted")
        }

        val isHvIgnored = prefs.getBoolean(PreferenceKey.HV_IGNORED.value, false)
        val isDecryptable = prefs.getBoolean(PreferenceKey.DECRYPTABLE.value, false)


        networkSetting = NetworkSetting(
            host, username, password, port, mru, mtu, prefix,
            isPapAcceptable, isMschapv2Acceptable, isHvIgnored, isDecryptable
        )

        return true
    }

    private fun prepareLayers() {
        sslTerminal = SslTerminal(this)
        sstpClient = SstpClient(this)
        pppClient = PppClient(this)
        ipTerminal = IpTerminal(this)
    }

    internal fun run() {
        inform("Establish VPN connection", null)
        prepareLayers()

        jobIncoming = launch(handler) {
            while (isActive) {
                sstpClient.proceed()
                pppClient.proceed()

                if (isClosing) {
                    status.sstp = SstpStatus.CALL_DISCONNECT_IN_PROGRESS_1
                }
            }
        }

        jobOutgoing = launch(handler) {
            while (isActive) {
                if (isClosing) {
                    withTimeoutOrNull(10_000) {
                        while (isActive) {
                            if (jobIncoming?.isCompleted == false) {
                                delay(100)
                                continue
                            }

                            if (sstpClient.waitingControlUnits.any()) {
                                sstpClient.sendControlUnit()
                            } else break
                        }
                    }

                    throw SuicideException()
                }

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
}
