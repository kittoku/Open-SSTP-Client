package kittoku.osc

import android.annotation.SuppressLint
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * Checks from the user's own network whether a server really answers as an SSTP server.
 * Nothing is sent except the standard SSTP opening request, and no login is attempted.
 * The certificate is deliberately not verified here: VPN Gate servers use self-signed
 * certificates, and this probe never sends any user data.
 */
@SuppressLint("CustomX509TrustManager", "TrustAllX509TrustManager")
internal object ServerTester {
    const val FAILED = -1

    private const val TOTAL_TIMEOUT_MS = 4000L

    private val watchdog = ScheduledThreadPoolExecutor(1, ThreadFactory { r ->
        Thread(r, "server-test-watchdog").also { it.isDaemon = true }
    }).also { it.removeOnCancelPolicy = true }

    private val trustAll = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    /** Returns the TCP connect time in milliseconds, or [FAILED]. Blocks, so call it off the main thread. */
    fun test(host: String, port: Int): Int {
        val raw = Socket()
        // One deadline for the whole check: closing the socket aborts any blocked step.
        val timer = watchdog.schedule({ runCatching { raw.close() } }, TOTAL_TIMEOUT_MS, TimeUnit.MILLISECONDS)

        return try {
            val start = System.nanoTime()
            raw.connect(InetSocketAddress(host, port), TOTAL_TIMEOUT_MS.toInt())
            val connectMs = ((System.nanoTime() - start) / 1_000_000).toInt().coerceAtLeast(1)

            raw.soTimeout = TOTAL_TIMEOUT_MS.toInt()

            val context = SSLContext.getInstance("TLS")
            context.init(null, arrayOf(trustAll), SecureRandom())
            val ssl = context.socketFactory.createSocket(raw, host, port, true) as SSLSocket
            ssl.startHandshake()

            val request = "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n" +
                    "Content-Length: 18446744073709551615\r\n" +
                    "Host: $host\r\n" +
                    "SSTPCORRELATIONID: {${UUID.randomUUID()}}\r\n\r\n"

            ssl.outputStream.write(request.toByteArray(Charsets.US_ASCII))
            ssl.outputStream.flush()

            val head = ByteArray(12)
            var read = 0
            while (read < head.size) {
                val n = ssl.inputStream.read(head, read, head.size - read)
                if (n < 0) break
                read += n
            }

            // A real SSTP server answers "HTTP/1.1 200".
            if (String(head, 0, read, Charsets.US_ASCII).startsWith("HTTP/1.1 200")) connectMs else FAILED
        } catch (e: Exception) {
            FAILED
        } finally {
            timer.cancel(false)
            runCatching { raw.close() }
        }
    }
}
