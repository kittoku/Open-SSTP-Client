package kittoku.opensstpclient.layer

import kittoku.opensstpclient.ControlClient
import kotlinx.coroutines.withTimeout
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.security.cert.X509Certificate
import javax.net.ssl.*


internal class SslTerminal(parent: ControlClient) : Terminal(parent) {
    internal lateinit var socket: SSLSocket

    private fun createSocket() {
        socket = SSLSocketFactory.getDefault().createSocket(
            parent.networkSetting.host,
            parent.networkSetting.port ?: 443
        ) as SSLSocket
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

    private fun getSpoiledTrustManager(): Array<TrustManager> {
        class Manager : X509TrustManager {
            override fun checkClientTrusted(
                chain: Array<out X509Certificate>?,
                authType: String?
            ) {
            }

            override fun checkServerTrusted(
                chain: Array<out X509Certificate>?,
                authType: String?
            ) {
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> {
                return emptyArray()
            }
        }

        return arrayOf(Manager())
    }

    private fun createNullSocket() {
        SSLContext.getInstance("TLSv1.2").also {
            it.init(null, getSpoiledTrustManager(), null)
            socket = it.socketFactory.createSocket(
                parent.networkSetting.host,
                parent.networkSetting.port ?: 443
            ) as SSLSocket
        }

        socket.enabledCipherSuites = arrayOf(
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA")
        parent.networkSetting.serverCertificate = socket.session.peerCertificates[0]
        socket.startHandshake()
    }

    private suspend fun establishHttpLayer() {
        val input = InputStreamReader(socket.inputStream, "US-ASCII")
        val output = OutputStreamWriter(socket.outputStream, "US-ASCII")
        val HTTP_REQUEST = arrayListOf(
            "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1",
            "Content-Length: 18446744073709551615",
            "Host: ${parent.networkSetting.host}",
            "SSTPCORRELATIONID: {${parent.networkSetting.guid}}"
        ).joinToString(separator = "\r\n", postfix = "\r\n\r\n")

        output.write(HTTP_REQUEST)
        output.flush()

        val received = mutableListOf<Byte>(0, 0, 0)
        val terminal = listOf<Byte>(0x0D, 0x0A, 0x0D, 0x0A) // \r\n\r\n

        withTimeout(10_000) {
            while (true) {
                val c: Int = input.read()
                received.add(c.toByte())

                if (received.subList(received.size - 4, received.size) == terminal) break
            }
        }

        parent.vpnService.protect(socket)

    }

    internal suspend fun initializeSocket() {
        if (parent.networkSetting.isDecryptable) createNullSocket() else createSocket()
        establishHttpLayer()
    }

    override fun release() {
        if (::socket.isInitialized) socket.close()
    }
}
