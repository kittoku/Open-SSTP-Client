package kittoku.opensstpclient

import android.preference.PreferenceManager
import android.widget.Toast
import kittoku.opensstpclient.layer.*
import kittoku.opensstpclient.misc.IncomingBuffer
import kittoku.opensstpclient.misc.NetworkSetting
import kittoku.opensstpclient.misc.SuicideException
import kittoku.opensstpclient.misc.inform
import kittoku.opensstpclient.unit.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.nio.ByteBuffer
import java.util.concurrent.LinkedBlockingQueue


internal class ControlClient(internal val vpnService: SstpVpnService) :
    CoroutineScope by CoroutineScope(Dispatchers.IO + SupervisorJob()) {
    internal lateinit var networkSetting: NetworkSetting
    internal val status = DualClientStatus()
    internal val builder = vpnService.Builder()
    internal val controlQueue = LinkedBlockingQueue<Any>()
    internal val incomingBuffer = IncomingBuffer(INCOMING_BUFFER_SIZE, this)

    internal lateinit var sslTerminal: SslTerminal
    private lateinit var sstpClient: SstpClient
    private lateinit var pppClient: PppClient
    internal lateinit var ipTerminal: IpTerminal

    private var jobIncoming: Job? = null
    private var jobControl: Job? = null
    internal var jobData: Job? = null

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
                    controlQueue.add(0)

                    if (exception != null && exception !is SuicideException) {
                        inform("An unexpected event occurred", exception)
                    }

                    ipTerminal.release()
                    jobData?.cancel()

                    jobIncoming?.join()

                    withTimeoutOrNull(10_000) {
                        while (isActive) {
                            if (jobIncoming?.isCompleted == false) delay(100)
                            else break
                        }
                    }
                    sslTerminal.release()
                    jobControl?.cancel()

                    inform("Terminate VPN connection", null)
                    vpnService.notifySwitchOff()
                    vpnService.stopForeground(true)
                }
            }
        }
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

        jobControl = launch(handler) {
            val controlBuffer = ByteBuffer.allocate(CONTROL_BUFFER_SIZE)

            while (isActive) {
                val candidate = controlQueue.take()
                if (candidate == 0) break

                controlBuffer.clear()
                when (candidate) {
                    is ControlPacket -> {
                        candidate.write(controlBuffer)
                    }

                    is PppFrame -> {
                        controlBuffer.putShort(PacketType.DATA.value)
                        controlBuffer.putShort((candidate._length + 8).toShort())
                        candidate.write(controlBuffer)
                    }

                    else -> throw Exception("Invalid Control Unit")
                }
                controlBuffer.flip()

                sslTerminal.send(controlBuffer)
            }
        }

        jobData = launch(handler, CoroutineStart.LAZY) {
            val channel = Channel<ByteBuffer>(0)
            val readBufferAlpha = ByteBuffer.allocate(networkSetting.currentMtu)
            val readBufferBeta = ByteBuffer.allocate(networkSetting.currentMtu)
            var isBlockingAlpha = true

            launch { // buffer packets
                val dataBuffer = ByteBuffer.allocate(DATA_BUFFER_SIZE)
                val minCapacity = networkSetting.currentMtu + 8

                fun encapsulate(src: ByteBuffer) {
                    dataBuffer.putShort(PacketType.DATA.value)
                    dataBuffer.putShort((src.limit() + 8).toShort())
                    dataBuffer.putShort(PPP_HEADER)
                    dataBuffer.putShort(PppProtocol.IP.value)
                    dataBuffer.put(src)
                }

                while (isActive) {
                    dataBuffer.clear()
                    encapsulate(channel.receive())

                    while (isActive) {
                        delay(1)
                        val polled = channel.poll()
                        if (polled != null) {
                            encapsulate(polled)
                            if (dataBuffer.remaining() < minCapacity) break
                        } else break
                    }

                    dataBuffer.flip()
                    sslTerminal.send(dataBuffer)
                }
            }

            suspend fun read(dst: ByteBuffer) {
                dst.clear()
                dst.position(
                    ipTerminal.ipInput.read(
                        dst.array(),
                        0,
                        networkSetting.currentMtu
                    )
                )
                dst.flip()

                if (dst.limit() > 0) channel.send(dst)
                else delay(100)
            }

            while (isActive) {
                isBlockingAlpha = if (isBlockingAlpha) {
                    read(readBufferAlpha)
                    false
                } else {
                    read(readBufferBeta)
                    true
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

        val host = prefs.getString(PreferenceKey.HOST.value, "") as String
        if (host == "") {
            makeToast("Host is missing")
            return false
        }

        val username = prefs.getString(PreferenceKey.USERNAME.value, "") as String

        val password = prefs.getString(PreferenceKey.PASSWORD.value, "") as String

        val port = prefs.getString(PreferenceKey.PORT.value, "")?.toIntOrNull()
        if (port != null && port !in 0..65535) {
            makeToast("The given port is out of 0-65535")
            return false
        }

        val mru = prefs.getString(PreferenceKey.MRU.value, "")?.toIntOrNull()
        if (mru != null && mru !in MIN_MRU..MAX_MRU) {
            makeToast("The given MRU is out of $MIN_MRU-$MAX_MRU")
            return false
        }

        val mtu = prefs.getString(PreferenceKey.MTU.value, "")?.toIntOrNull()
        if (mtu != null && mtu !in MIN_MTU..MAX_MTU) {
            makeToast("The given MTU is out of $MIN_MTU-$MAX_MTU")
            return false
        }

        val prefix = prefs.getString(PreferenceKey.PREFIX.value, "")?.toIntOrNull()
        if (prefix != null && prefix !in 0..32) {
            makeToast("The given address prefix is out of 0-32")
            return false
        }

        val ssl = sslMap[prefs.getInt(PreferenceKey.SSL.value, 0)]
        if (ssl == null) {
            makeToast("No valid SSL protocol was chosen")
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
            host, username, password, port, mru, mtu, prefix, ssl,
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
}
