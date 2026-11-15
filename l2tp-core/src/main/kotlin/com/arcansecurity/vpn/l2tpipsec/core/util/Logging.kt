package com.arcansecurity.vpn.l2tpipsec.core.util

enum class LogLevel { DEBUG, INFO, WARN, ERROR }

/**
 * Sink for the stack's diagnostics. The Android app forwards it to `android.util.Log` and to the
 * in-app log screen; unit tests capture it or discard it.
 *
 * Nothing that reaches a sink is private. logcat is readable by the platform, and the log screen
 * has a "copy" and a "share" action, so a message is a publication channel rather than a debugging
 * aid kept to oneself. Callers are responsible for reducing a credential to [redacted] *before*
 * handing it over; a sink cannot repair a message that already contains one.
 */
fun interface VpnLogger {
    fun log(level: LogLevel, tag: String, message: String, error: Throwable?)

    /**
     * Whether a message at this level would be kept. Overriding it lets [Log.d] skip building a
     * string that the sink is only going to drop: the data path traces per packet, so on a phone
     * that formatting is real work done for nothing.
     */
    fun isEnabled(level: LogLevel): Boolean = true

    companion object {
        val NONE = object : VpnLogger {
            override fun log(level: LogLevel, tag: String, message: String, error: Throwable?) = Unit
            override fun isEnabled(level: LogLevel) = false
        }

        val STDOUT = VpnLogger { level, tag, message, error ->
            println("[$level] $tag: $message")
            error?.printStackTrace()
        }
    }
}

/** Convenience wrapper binding a [VpnLogger] to a fixed tag. */
class Log(private val tag: String, private val sink: VpnLogger) {
    /**
     * Debug traces take a lambda because they sit on the hot path — the message is only built if
     * something is actually going to keep it.
     */
    fun d(message: () -> String) {
        if (sink.isEnabled(LogLevel.DEBUG)) sink.log(LogLevel.DEBUG, tag, message(), null)
    }

    fun i(message: String) = sink.log(LogLevel.INFO, tag, message, null)
    fun w(message: String, error: Throwable? = null) = sink.log(LogLevel.WARN, tag, message, error)
    fun e(message: String, error: Throwable? = null) = sink.log(LogLevel.ERROR, tag, message, error)
}

/**
 * Stands in for a value that must stay unreadable in anything a human can see: a log line, an
 * exception message, a `toString()` a crash reporter serialises.
 *
 * It reports only whether the secret is set, which is the part that is actually worth knowing when
 * a connection fails. The length is withheld on purpose. Printing it is tempting — it looks
 * harmless and it catches a stray space at the end of a pasted pre-shared key — but the length is
 * exactly the parameter that decides how expensive guessing the key is, and a trace shared into a
 * support ticket should not narrow that search.
 */
fun redacted(secret: String?): String = if (secret.isNullOrEmpty()) "<unset>" else "<redacted>"
