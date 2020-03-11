package kittoku.opensstpclient.layer

import kittoku.opensstpclient.ControlClient
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.nio.ByteBuffer
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory


internal class SslTerminal(parent: ControlClient) : Terminal(parent) {
    private val mutex = Mutex()
    internal lateinit var socket: SSLSocket

    private fun createSocket() {
        socket = SSLSocketFactory.getDefault().createSocket(
            parent.networkSetting.host,
            parent.networkSetting.port ?: 443
        ) as SSLSocket

        parent.networkSetting.sslProtocol.also {
            if (it != "DEFAULT") {
                socket.enabledProtocols = arrayOf(it)
            }
        }

        if (parent.networkSetting.isDecryptable) {
            socket.enabledCipherSuites = arrayOf(
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "TLS_RSA_WITH_AES_256_CBC_SHA"
            )
        }

        HttpsURLConnection.getDefaultHostnameVerifier().also {
            if (!it.verify(
                    parent.networkSetting.host,
                    socket.session
                ) && !parent.networkSetting.isHvIgnored
            ) {
                throw Exception("Failed to verify the hostname")
            }
        }

        parent.networkSetting.serverCertificate = socket.session.peerCertificates[0]
        socket.startHandshake()
    }

    private fun establishHttpLayer() {
        val input = InputStreamReader(socket.inputStream, "US-ASCII")
        val output = OutputStreamWriter(socket.outputStream, "US-ASCII")
        val HTTP_REQUEST = arrayOf(
            "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1",
            "Content-Length: 18446744073709551615",
            "Host: ${parent.networkSetting.host}",
            "SSTPCORRELATIONID: {${parent.networkSetting.guid}}"
        ).joinToString(separator = "\r\n", postfix = "\r\n\r\n")

        output.write(HTTP_REQUEST)
        output.flush()

        val received = mutableListOf<Byte>(0, 0, 0)
        val terminal = listOf<Byte>(0x0D, 0x0A, 0x0D, 0x0A) // \r\n\r\n

        socket.soTimeout = 10_000
        while (true) {
            val c: Int = input.read()
            received.add(c.toByte())

            if (received.subList(received.size - 4, received.size) == terminal) break
        }

        socket.soTimeout = 1_000
        parent.vpnService.protect(socket)
    }

    internal fun initializeSocket() {
        createSocket()
        establishHttpLayer()
    }

    internal suspend fun send(bytes: ByteBuffer) {
        mutex.withLock {
            socket.outputStream.write(bytes.array(), 0, bytes.limit())
        }
    }

    override fun release() {
        if (::socket.isInitialized) socket.close()
    }
}
