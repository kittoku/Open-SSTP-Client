package kittoku.osc.terminal

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.util.Base64
import androidx.core.app.NotificationCompat
import androidx.documentfile.provider.DocumentFile
import kittoku.osc.ControlMessage
import kittoku.osc.R
import kittoku.osc.Result
import kittoku.osc.SharedBridge
import kittoku.osc.Where
import kittoku.osc.activity.BLANK_ACTIVITY_TYPE_SAVE_CERT
import kittoku.osc.activity.BlankActivity
import kittoku.osc.activity.EXTRA_KEY_CERT
import kittoku.osc.activity.EXTRA_KEY_FILENAME
import kittoku.osc.activity.EXTRA_KEY_TYPE
import kittoku.osc.extension.capacityAfterLimit
import kittoku.osc.extension.slide
import kittoku.osc.extension.toIntAsUByte
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getIntPrefValue
import kittoku.osc.preference.accessor.getSetPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue
import kittoku.osc.preference.accessor.getURIPrefValue
import kittoku.osc.service.NOTIFICATION_CERTIFICATE_CHANNEL
import kittoku.osc.service.NOTIFICATION_CERTIFICATE_ID
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.yield
import java.io.BufferedInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.cert.CertPathValidatorException
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLSession
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory


private const val HTTP_DELIMITER = "\r\n"
private const val HTTP_SUFFIX = "\r\n\r\n"

internal const val SSL_REQUEST_INTERVAL = 10_000L

internal class SSLTerminal(private val bridge: SharedBridge) {
    private val mutex = Mutex()

    private var socket: Socket? = null
    private lateinit var socketInputStream: InputStream
    private lateinit var socketOutputStream: OutputStream
    private lateinit var inboundBuffer: ByteBuffer
    private lateinit var outboundBuffer: ByteBuffer

    private lateinit var engine: SSLEngine

    private var jobInitialize: Job? = null

    private val doUseProxy = getBooleanPrefValue(OscPrefKey.PROXY_DO_USE_PROXY, bridge.prefs)
    private val sslHostname = getStringPrefValue(OscPrefKey.HOME_HOSTNAME, bridge.prefs)
    private val sslPort = getIntPrefValue(OscPrefKey.SSL_PORT, bridge.prefs)
    private val selectedVersion = getStringPrefValue(OscPrefKey.SSL_VERSION, bridge.prefs)
    private val enabledSuites = getSetPrefValue(OscPrefKey.SSL_SUITES, bridge.prefs)

    internal suspend fun initialize() {
        jobInitialize = bridge.service.scope.launch(bridge.handler) {
            if (!establishSSL()) return@launch

            if (!establishHttp()) return@launch

            bridge.controlMailbox.send(ControlMessage(Where.SSL, Result.PROCEEDED))
        }
    }

    private suspend fun createTrustManagers(): Array<TrustManager>? {
        val document = DocumentFile.fromTreeUri(
            bridge.service,
            getURIPrefValue(OscPrefKey.SSL_CERT_DIR, bridge.prefs)!!
        )!!

        val certFactory = CertificateFactory.getInstance("X.509")
        val keyStore = KeyStore.getDefaultType().let {
            KeyStore.getInstance(it)
        }
        keyStore.load(null, null)

        for (file in document.listFiles()) {
            if (file.isFile) {
                val stream = BufferedInputStream(bridge.service.contentResolver.openInputStream(file.uri))
                val ca: X509Certificate

                try {
                    ca = certFactory.generateCertificate(stream) as X509Certificate
                } catch (e: CertificateException) {
                    bridge.controlMailbox.send(ControlMessage(Where.CERT, Result.ERR_PARSING_FAILED, generateParsingCertLog(file.name, e)))

                    return null
                }

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

    private suspend fun establishSSL(): Boolean {
        val sslContext = if (getBooleanPrefValue(OscPrefKey.SSL_DO_SPECIFY_CERT, bridge.prefs)) {
            val managers = createTrustManagers() ?: return false

            SSLContext.getInstance(selectedVersion).also {
                it.init(null, managers, null)
            }
        } else {
            SSLContext.getDefault()
        }

        engine = sslContext.createSSLEngine(sslHostname, sslPort)
        engine.useClientMode = true

        if (selectedVersion != "DEFAULT") {
            engine.enabledProtocols = arrayOf(selectedVersion)
        }

        if (getBooleanPrefValue(OscPrefKey.SSL_DO_SELECT_SUITES, bridge.prefs)) {
            val sortedSuites = engine.supportedCipherSuites.filter {
                enabledSuites.contains(it)
            }

            engine.enabledCipherSuites = sortedSuites.toTypedArray()
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && getBooleanPrefValue(OscPrefKey.SSL_DO_USE_CUSTOM_SNI, bridge.prefs)) {
            engine.sslParameters = engine.sslParameters.also {
                it.serverNames = listOf(SNIHostName(getStringPrefValue(OscPrefKey.SSL_CUSTOM_SNI, bridge.prefs)))
            }
        }

        val socketHostname = if (doUseProxy) getStringPrefValue(OscPrefKey.PROXY_HOSTNAME, bridge.prefs) else sslHostname
        val socketPort = if (doUseProxy) getIntPrefValue(OscPrefKey.PROXY_PORT, bridge.prefs) else sslPort
        socket = Socket(socketHostname, socketPort).also {
            socketInputStream = it.getInputStream()
            socketOutputStream = it.getOutputStream()
        }

        if (doUseProxy) {
            if (!establishProxy()) {
                return false
            }
        }

        inboundBuffer = ByteBuffer.allocate(engine.session.packetBufferSize).also { it.limit(0) }
        outboundBuffer = ByteBuffer.allocate(engine.session.packetBufferSize)

        try {
            startSSLHandshake()
        } catch (e: CertificateException) {
            val cause = e.cause
            if (cause is CertPathValidatorException) {
                notifyUntrustedCertificate(cause.certPath.certificates[0])

                bridge.controlMailbox.send(ControlMessage(Where.CERT_PATH, Result.ERR_VERIFICATION_FAILED, generateCertPathLog(cause)))

                return false
            } else {
                throw e
            }
        }

        if (getBooleanPrefValue(OscPrefKey.SSL_DO_VERIFY, bridge.prefs)) {
            HttpsURLConnection.getDefaultHostnameVerifier().also {
                if (!it.verify(sslHostname, engine.session)) {
                    bridge.controlMailbox.send(ControlMessage(Where.SSL, Result.ERR_VERIFICATION_FAILED))
                    return false
                }
            }
        }

        return true
    }

    private suspend fun startSSLHandshake() {
        val tempBuffer = ByteBuffer.allocate(0)

        engine.beginHandshake()

        while (true) {
            yield()

            when (engine.handshakeStatus) {
                SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                    val result = send(tempBuffer)
                    if (result.handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED) {
                        break
                    }
                }

                SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                    val result = receive(tempBuffer)
                    if (result.handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED) {
                        break
                    }
                }

                else -> {
                    throw NotImplementedError(engine.handshakeStatus.name)
                }
            }
        }
    }

    private suspend fun establishProxy(): Boolean {
        val username = getStringPrefValue(OscPrefKey.PROXY_USERNAME, bridge.prefs)
        val password = getStringPrefValue(OscPrefKey.PROXY_PASSWORD, bridge.prefs)

        val request = mutableListOf(
            "CONNECT ${sslHostname}:${sslPort} HTTP/1.1",
            "Host: ${sslHostname}:${sslPort}",
            "SSTPVERSION: 1.0"
        ).also {
            if (username.isNotEmpty() || password.isNotEmpty()) {
                val encoded = Base64.encode(
                    "$username:$password".toByteArray(Charsets.US_ASCII),
                    Base64.NO_WRAP
                ).toString(Charsets.US_ASCII)

                it.add("Proxy-Authorization: Basic $encoded")
            }
        }.joinToString(separator = HTTP_DELIMITER, postfix = HTTP_SUFFIX).toByteArray(Charsets.US_ASCII)

        socketOutputStream.write(request)
        socketOutputStream.flush()

        var response = ""
        while (true) {
            response += socketInputStream.read().toChar()

            if (response.endsWith(HTTP_SUFFIX)) {
                break
            }
        }

        val responseHeader = response.split(HTTP_DELIMITER)[0]

        if (responseHeader.contains("403")) {
            bridge.controlMailbox.send(ControlMessage(Where.PROXY, Result.ERR_AUTHENTICATION_FAILED))
            return false
        }

        if (!responseHeader.contains("200")) {
            bridge.controlMailbox.send(ControlMessage(Where.PROXY, Result.ERR_UNEXPECTED_MESSAGE))
            return false
        }

        return true
    }

    private suspend fun establishHttp(): Boolean {
        val buffer = ByteBuffer.allocate(getApplicationBufferSize())

        val request = arrayOf(
            "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1",
            "Content-Length: 18446744073709551615",
            "Host: $sslHostname",
            "SSTPCORRELATIONID: {${bridge.guid}}"
        ).joinToString(separator = HTTP_DELIMITER, postfix = HTTP_SUFFIX).toByteArray(Charsets.US_ASCII)

        buffer.put(request)
        buffer.flip()

        send(buffer)

        buffer.position(0)
        buffer.limit(0)

        var response = ""
        outer@ while (true) {
            receive(buffer)

            for (i in 0 until buffer.remaining()) {
                response += buffer.get().toIntAsUByte().toChar()

                if (response.endsWith(HTTP_SUFFIX)) {
                    break@outer
                }
            }
        }

        if (!response.split(HTTP_DELIMITER)[0].contains("200")) {
            bridge.controlMailbox.send(ControlMessage(Where.SSL, Result.ERR_UNEXPECTED_MESSAGE))
            return false
        }


        socket!!.soTimeout = 1_000
        bridge.service.protect(socket)
        return true
    }

    private fun generateParsingCertLog(filename: String?, exception: CertificateException): String {
        var log = "[FAILED FILE]\n$filename\n\n"

        log += "[STACK TRACE]\n${exception.stackTraceToString()}"

        return log
    }

    private fun generateCertPathLog(exception: CertPathValidatorException): String {
        var log = "[MESSAGE]\n${exception.message}\n\n"

        if (Build.VERSION.SDK_INT >= 24) {
            log += "[REASON]\n${exception.reason}\n\n"
        }

        log += "[CERT PATH]\n"
        exception.certPath.certificates.forEachIndexed { i, cert ->
            log += "-----CERT at $i-----\n"
            log += "$cert\n"
            log += "-----END CERT-----\n\n"
        }

        log += "[FAILED CERT INDEX]\n"
        log += if (exception.index == -1) "NOT DEFINED" else exception.index.toString()
        log += "\n\n"

        log += "[STACK TRACE]\n${exception.stackTraceToString()}"

        return log
    }

    private fun notifyUntrustedCertificate(cert: Certificate) {
        val basename = if (cert is X509Certificate) {
            cert.subjectX500Principal.name
        } else {
            "server"
        }

        val saveIntent = Intent(bridge.service, BlankActivity::class.java).also {
            it.putExtra(EXTRA_KEY_TYPE, BLANK_ACTIVITY_TYPE_SAVE_CERT)
            it.putExtra(EXTRA_KEY_CERT, cert.encoded)
            it.putExtra(EXTRA_KEY_FILENAME, "$basename.crt")
        }

        val pendingIntent = PendingIntent.getActivity(
            bridge.service,
            0,
            saveIntent,
            PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE
        )

        NotificationCompat.Builder(bridge.service, NOTIFICATION_CERTIFICATE_CHANNEL).also {
            it.priority = NotificationCompat.PRIORITY_DEFAULT
            it.setSmallIcon(R.drawable.ic_baseline_vpn_lock_24)
            it.setAutoCancel(true)
            it.setContentTitle("You can download the untrusted server certificate")
            it.setContentText("WARNING: untrusted certificates could have your device vulnerable")
            it.setStyle(NotificationCompat.BigTextStyle())
            it.setContentIntent(pendingIntent)
        }.build().also {
            bridge.service.tryNotify(it, NOTIFICATION_CERTIFICATE_ID)
        }
    }

    internal fun getSession(): SSLSession {
        return engine.session
    }

    internal fun getServerCertificate(): ByteArray {
        return engine.session.peerCertificates[0].encoded
    }

    internal fun getApplicationBufferSize(): Int {
        return engine.session.applicationBufferSize
    }

    internal fun receive(buffer: ByteBuffer): SSLEngineResult {
        var startPayload: Int
        var result: SSLEngineResult

        while (true) {
            startPayload = buffer.position()
            buffer.position(buffer.limit())
            buffer.limit(buffer.capacity())

            result = engine.unwrap(inboundBuffer, buffer)

            when (result.status) {
                SSLEngineResult.Status.OK -> {
                    break
                }

                SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                    buffer.limit(buffer.position())
                    buffer.position(startPayload)

                    buffer.slide()
                }

                SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                    buffer.limit(buffer.position())
                    buffer.position(startPayload)

                    inboundBuffer.slide()

                    try {
                        val readSize = socketInputStream.read(
                            inboundBuffer.array(),
                            inboundBuffer.limit(),
                            inboundBuffer.capacityAfterLimit
                        )

                        inboundBuffer.limit(inboundBuffer.limit() + readSize)
                    } catch (_: SocketTimeoutException) { }
                }

                else -> {
                    throw NotImplementedError(result.status.name)
                }
            }
        }

        buffer.limit(buffer.position())
        buffer.position(startPayload)

        return result
    }

    internal suspend fun send(buffer: ByteBuffer): SSLEngineResult {
        mutex.withLock {
            var result: SSLEngineResult

            while (true) {
                outboundBuffer.clear()

                result = engine.wrap(buffer, outboundBuffer)
                if (result.status != SSLEngineResult.Status.OK) {
                    throw NotImplementedError(result.status.name)
                }

                socketOutputStream.write(
                    outboundBuffer.array(),
                    0,
                    outboundBuffer.position()
                )

                if (!buffer.hasRemaining()) {
                    socketOutputStream.flush()

                    break
                }
            }

            return result
        }
    }

    internal fun close() {
        jobInitialize?.cancel()
        socket?.close()
    }
}
