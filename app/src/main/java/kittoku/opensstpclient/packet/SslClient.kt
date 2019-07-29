package kittoku.opensstpclient.packet

import android.net.VpnService
import kittoku.opensstpclient.BUFFER_SIZE_SSL
import kittoku.opensstpclient.POLLING_TIME_CHANNEL_READ
import kittoku.opensstpclient.POLLING_TIME_STREAM_READ
import kittoku.opensstpclient.misc.AbstractTerminal
import kittoku.opensstpclient.misc.LayerBridge
import kittoku.opensstpclient.misc.NetworkSetting
import kittoku.opensstpclient.misc.completeWrite
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.nio.channels.Pipe
import java.security.cert.X509Certificate
import javax.net.SocketFactory
import javax.net.ssl.*


internal class SslClient : AbstractTerminal {
    private val fromSstp: Pipe.SourceChannel
    private val toSstp: Pipe.SinkChannel
    private val vpnService: VpnService
    private val doTest: Boolean
    private lateinit var socket: SSLSocket

    constructor(vpnService: VpnService, bridge: LayerBridge, networkSetting: NetworkSetting)
            : super(bridge, networkSetting, BUFFER_SIZE_SSL) {
        fromSstp = bridge.fromHigher
        toSstp = bridge.toHigher
        this.vpnService = vpnService
        this.doTest = false
    }

    constructor(vpnService: VpnService, bridge: LayerBridge, networkSetting: NetworkSetting, doTest: Boolean)
            : super(bridge, networkSetting, BUFFER_SIZE_SSL) {
        // this constructor is used for test
        fromSstp = bridge.fromHigher
        toSstp = bridge.toHigher
        this.vpnService = vpnService
        this.doTest = doTest
    }

    private fun createSocket(): SSLSocket {
        val sf: SocketFactory = SSLSocketFactory.getDefault()
        val socket: SSLSocket = sf.createSocket(networkSetting.host, 443) as SSLSocket
        val session: SSLSession = socket.session
        val hv: HostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier()
        hv.verify(networkSetting.host, session)
        networkSetting.serverCertificate = session.peerCertificates[0]
        socket.startHandshake()

        return socket
    }

    private fun getSpoiledTrustManager(): Array<TrustManager> {
        class Manager : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> {
                return emptyArray()
            }
        }

        return arrayOf(Manager())
    }

    private fun createNullSocket(): SSLSocket {
        val manager: Array<TrustManager> = getSpoiledTrustManager()
        val sslContext: SSLContext = SSLContext.getInstance("SSL")
        sslContext.init(null, manager, null)

        val sf: SSLSocketFactory = sslContext.socketFactory

        val socket = sf.createSocket(networkSetting.host, 443) as SSLSocket
        networkSetting.serverCertificate = socket.session.peerCertificates[0]
        socket.startHandshake()

        return socket
    }

    private fun establishHttpLayer() {
        socket = if (doTest) createNullSocket() else createSocket()
        val input = InputStreamReader(socket.inputStream, "US-ASCII")
        val output = OutputStreamWriter(socket.outputStream, "US-ASCII")

        val HTTP_REQUEST: String = arrayListOf(
            "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1",
            "SSTPCORRELATIONID: {${networkSetting.guid}}",
            "Content-Length: 18446744073709551615",
            "Host: ${networkSetting.host}"
        ).joinToString(separator = "\r\n", postfix = "\r\n\r\n")

        output.write(HTTP_REQUEST)
        output.flush()

        val received: MutableList<Byte> = mutableListOf(0, 0, 0)
        val terminal: List<Byte> = listOf(0x0D, 0x0A, 0x0D, 0x0A) // \r\n\r\n

        while (true) {
            val c: Int = input.read()
            received.add(c.toByte())

            if (received.subList(received.size - 4, received.size) == terminal) break
        }

        vpnService.protect(socket)
    }

    override fun runOutgoing() {
        launch {
            while (true) {
                outgoingBuffer.clear()
                if (fromSstp.read(outgoingBuffer) > 0 ) {
                    socket.outputStream.write(outgoingBuffer.array(), 0, outgoingBuffer.position())
                    socket.outputStream.flush()
                } else delay(POLLING_TIME_CHANNEL_READ)
            }
        }
    }

    override suspend fun run() {
        establishHttpLayer()
        runOutgoing()

        while (isActive) {
            incomingBuffer.clear()
            withTimeout(POLLING_TIME_STREAM_READ) {
                incomingBuffer.limit(socket.inputStream.read(incomingBuffer.array()))
            }
            toSstp.completeWrite(incomingBuffer)
        }
    }

    override fun release() {
        if (::socket.isInitialized) socket.close()
    }
}