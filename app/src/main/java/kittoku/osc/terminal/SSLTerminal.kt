package kittoku.osc.terminal

import androidx.documentfile.provider.DocumentFile
import kittoku.osc.client.ClientBridge
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.*
import kittoku.osc.unit.DataUnit
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.BufferedInputStream
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.*


internal class SSLTerminal(private val bridge: ClientBridge) {
    private val mutex = Mutex()
    private var socket: SSLSocket? = null

    private val selectedVersion = getStringPrefValue(OscPreference.SSL_VERSION, bridge.prefs)
    private val enabledSuites = getSetPrefValue(OscPreference.SSL_SUITES, bridge.prefs)

    init {
        createSocket()
        establishHttpLayer()
    }

    private fun createTrustManagers(): Array<TrustManager> {
        val document = DocumentFile.fromTreeUri(
            bridge.service,
            getURIPrefValue(OscPreference.SSL_CERT_DIR, bridge.prefs)!!
        )!!

        val certFactory = CertificateFactory.getInstance("X.509")
        val keyStore = KeyStore.getDefaultType().let {
            KeyStore.getInstance(it)
        }
        keyStore.load(null, null)

        for (file in document.listFiles()) {
            if (file.isFile) {
                val stream =
                    BufferedInputStream(bridge.service.contentResolver.openInputStream(file.uri))
                val ca = certFactory.generateCertificate(stream) as X509Certificate
                keyStore.setCertificateEntry(file.name, ca)
                stream.close()
            }
        }

        val tmFactory = TrustManagerFactory.getDefaultAlgorithm().let {
            TrustManagerFactory.getInstance(it)
        }
        tmFactory.init(keyStore)

        return tmFactory.trustManagers
    }

    private fun createSocket() {
        val socketFactory = if (getBooleanPrefValue(OscPreference.SSL_DO_ADD_CERT, bridge.prefs)) {
            val context = SSLContext.getInstance(selectedVersion) as SSLContext
            context.init(null, createTrustManagers(), null)
            context.socketFactory
        } else {
            SSLSocketFactory.getDefault()
        }

        socket = socketFactory.createSocket(
            bridge.HOME_HOSTNAME,
            getIntPrefValue(OscPreference.SSL_PORT, bridge.prefs)
        ) as SSLSocket

        if (selectedVersion != "DEFAULT") {
            socket!!.enabledProtocols = arrayOf(selectedVersion)
        }

        if (getBooleanPrefValue(OscPreference.SSL_DO_SELECT_SUITES, bridge.prefs)) {
            val sortedSuites = socket!!.supportedCipherSuites.filter {
                enabledSuites.contains(it)
            }

            socket!!.enabledCipherSuites = sortedSuites.toTypedArray()
        }

        if (getBooleanPrefValue(OscPreference.SSL_DO_VERIFY, bridge.prefs)) {
            HttpsURLConnection.getDefaultHostnameVerifier().also {
                if (!it.verify(bridge.HOME_HOSTNAME, socket!!.session)) {
                    throw Exception("Failed to verify the hostname")
                }
            }
        }

        socket!!.startHandshake()
    }

    private fun establishHttpLayer() {
        val input = InputStreamReader(socket!!.inputStream, "US-ASCII")
        val output = OutputStreamWriter(socket!!.outputStream, "US-ASCII")
        val request = arrayOf(
            "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1",
            "Content-Length: 18446744073709551615",
            "Host: ${bridge.HOME_HOSTNAME}",
            "SSTPCORRELATIONID: {${bridge.guid}}"
        ).joinToString(separator = "\r\n", postfix = "\r\n\r\n")

        output.write(request)
        output.flush()

        val received = mutableListOf<Byte>(0, 0, 0)
        val terminal = listOf<Byte>(0x0D, 0x0A, 0x0D, 0x0A) // \r\n\r\n

        socket!!.soTimeout = 10_000
        while (true) {
            val c: Int = input.read()
            received.add(c.toByte())

            if (received.subList(received.size - 4, received.size) == terminal) break
        }

        socket!!.soTimeout = 1_000
        bridge.service.protect(socket)
    }

    internal fun getSession(): SSLSession {
        return socket!!.session
    }

    internal fun getServerCertificate(): ByteArray {
        return socket!!.session.peerCertificates[0].encoded
    }

    internal fun receive(maxRead: Int, buffer: ByteBuffer) {
        try {
            val readSize = socket!!.inputStream.read(buffer.array(), buffer.limit(), maxRead)
            buffer.limit(buffer.limit() + readSize)
        } catch (e: SocketTimeoutException) { }
    }

    internal suspend fun send(buffer: ByteBuffer) {
        mutex.withLock {
            socket!!.outputStream.write(buffer.array(), 0, buffer.limit())
            socket!!.outputStream.flush()
        }
    }

    internal suspend fun sendDataUnit(unit: DataUnit) {
        ByteBuffer.allocate(unit.length).also {
            unit.write(it)
            it.flip()
            send(it)
        }
    }

    internal fun close() {
        socket?.close()
    }
}
