package kittoku.opensstpclient.misc

import kittoku.opensstpclient.unit.*
import java.security.cert.Certificate
import java.util.*


internal class NetworkSetting(
    internal val host: String,
    internal val username: String,
    internal val password: String
) {
    internal lateinit var serverCertificate: Certificate
    internal lateinit var hashProtocol: HashProtocol
    internal lateinit var nonce: ByteArray
    internal val guid = UUID.randomUUID().toString()

    internal var mru = LcpMruOption()
    internal var auth = LcpAuthOption()
    internal var ipAddress = IpcpIpAddressOption()
    internal var dnsAddress = IpcpDnsAddressOption()

    internal var isMruRejected = false
    internal var isAuthRejected = false
    internal var isIpAddressRejected = false
    internal var isDnsAddressRejected = false

    internal val acceptableMru = AcceptableOptions<LcpMruOption>()
    internal val acceptableAuth = AcceptableOptions<LcpAuthOption>()
    internal val acceptableIpAddress = AcceptableOptions<IpcpIpAddressOption>()
    internal val acceptableDnsAddress = AcceptableOptions<IpcpDnsAddressOption>()
}

internal class AcceptableOptions<T : Option<T>> {
    private val candidates = mutableListOf<T>()

    internal val isRejectable: Boolean
        get() = candidates.isEmpty()

    internal fun isAcceptable(suggestion: T): Boolean {
        if (isRejectable) return true

        candidates.forEach { if (it.isMatchedTo(suggestion)) return true }

        return false
    }

    internal fun add(option: T) {
        candidates.add(option)
    }
}
