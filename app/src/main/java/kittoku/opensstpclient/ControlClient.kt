package kittoku.opensstpclient

import android.content.Intent
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import androidx.preference.PreferenceManager
import kittoku.opensstpclient.fragment.BoolPreference
import kittoku.opensstpclient.layer.*
import kittoku.opensstpclient.misc.*
import kittoku.opensstpclient.unit.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.BufferedOutputStream
import java.nio.ByteBuffer
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.LinkedBlockingQueue


internal class ControlClient(internal val vpnService: SstpVpnService) :
    CoroutineScope by CoroutineScope(Dispatchers.IO + SupervisorJob()) {
    internal val networkSetting = NetworkSetting(
        PreferenceManager.getDefaultSharedPreferences(vpnService.applicationContext)
    )
    internal val status = DualClientStatus()
    internal val builder = vpnService.Builder()
    internal val controlQueue = LinkedBlockingQueue<Any>()
    internal val incomingBuffer = IncomingBuffer(INCOMING_BUFFER_SIZE, this)
    private val observer = NetworkObserver(vpnService)
    internal var logStream: BufferedOutputStream? = null

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
                    logStream?.close()

                    notifySwitchOff()
                    observer.close()
                    vpnService.stopForeground(true)
                }
            }
        }
    }

    internal fun run() {
        if (networkSetting.LOG_DO_SAVE_LOG) {
            prepareLog()
        }
        inform("Establish VPN connection", null)
        prepareLayers()

        launchJobIncoming()
        launchJobControl()
        launchJobData()
    }

    private fun launchJobIncoming() {
        jobIncoming = launch(handler) {
            while (isActive) {
                sstpClient.proceed()
                pppClient.proceed()

                if (isClosing) {
                    status.sstp = SstpStatus.CALL_DISCONNECT_IN_PROGRESS_1
                }
            }
        }
    }

    private fun launchJobControl() {
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
    }

    private fun launchJobData() {
        jobData = launch(handler, CoroutineStart.LAZY) {
            val channel = Channel<ByteBuffer>(0)
            val readBufferAlpha = ByteBuffer.allocate(networkSetting.currentMtu)
            val readBufferBeta = ByteBuffer.allocate(networkSetting.currentMtu)
            var isBlockingAlpha = true

            launch { // buffer packets
                val dataBuffer = ByteBuffer.allocate(DATA_BUFFER_SIZE)
                val minCapacity = networkSetting.currentMtu + 8

                val ipv4Version: Int = (0x4).shl(28)
                val ipv6Version: Int = (0x6).shl(28)
                val versionMask: Int = (0xF).shl(28)

                fun encapsulate(src: ByteBuffer): Boolean // true if data protocol is enabled
                {
                    val header = src.getInt(0)
                    val version = when (header and versionMask) {
                        ipv4Version -> {
                            if (!networkSetting.PPP_IPv4_ENABLED) return false
                            PppProtocol.IP.value
                        }

                        ipv6Version -> {
                            if (!networkSetting.PPP_IPv6_ENABLED) return false
                            PppProtocol.IPV6.value
                        }

                        else -> throw Exception("Invalid data protocol was detected")
                    }

                    dataBuffer.putShort(PacketType.DATA.value)
                    dataBuffer.putShort((src.limit() + 8).toShort())
                    dataBuffer.putShort(PPP_HEADER)
                    dataBuffer.putShort(version)
                    dataBuffer.put(src)

                    return true
                }

                while (isActive) {
                    dataBuffer.clear()
                    if (!encapsulate(channel.receive())) continue

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

    private fun prepareLayers() {
        sslTerminal = SslTerminal(this)
        sstpClient = SstpClient(this)
        pppClient = PppClient(this)
        ipTerminal = IpTerminal(this)
    }

    private fun prepareLog() {
        val currentTime = SimpleDateFormat("yyyyMMddHHmmss", Locale.getDefault()).format(Date())
        val filename = "log_osc_${currentTime}.txt"
        val uri = Uri.parse(networkSetting.LOG_DIR)
        DocumentFile.fromTreeUri(vpnService, uri)!!.createFile("text/plain", filename).also {
            logStream = BufferedOutputStream(vpnService.contentResolver.openOutputStream(it!!.uri))
        }
    }

    private fun notifySwitchOff() {
        PreferenceManager.getDefaultSharedPreferences(vpnService.applicationContext).also {
            it.edit().putBoolean(BoolPreference.HOME_CONNECTOR.name, false).apply()
        }

        LocalBroadcastManager.getInstance(vpnService.applicationContext)
            .sendBroadcast(Intent(VpnAction.ACTION_SWITCH_OFF.value))
    }
}
