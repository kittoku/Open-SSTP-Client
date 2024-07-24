package kittoku.osc.control

import android.os.Build
import kittoku.osc.Result
import kittoku.osc.Where
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.BufferedOutputStream
import java.io.OutputStream
import java.security.cert.CertPathValidatorException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale


internal class LogWriter(logOutput: OutputStream) {
    private val mutex = Mutex()
    private val outputStream = BufferedOutputStream(logOutput)
    private val currentTime: String
        get() = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault()).format(Date())

    internal fun write(message: String) {
        // use directly if it's cannot be race condition, like onCreate and onDestroy
        outputStream.write("[$currentTime] $message\n".toByteArray(Charsets.UTF_8))
    }

    internal suspend fun report(message: String) {
        mutex.withLock { write(message) }
    }

    internal suspend fun logCertPathValidatorException(exception: CertPathValidatorException) {
        var log = "${Where.CERT_PATH}: ${Result.ERR_VERIFICATION_FAILED}\n"

        log += "[MESSAGE]\n${exception.message}\n\n"

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

        log += "[STACK TRACE]\n${exception.stackTraceToString()}\n"

        report(log)
    }

    internal fun close() {
        outputStream.flush()
        outputStream.close()
    }
}
