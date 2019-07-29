package kittoku.opensstpclient.misc

import kittoku.opensstpclient.packet.HashProtocol
import java.net.InetAddress
import java.security.MessageDigest
import java.security.cert.Certificate
import java.util.*


internal enum class PppClientStatus {
    INITIAL, AUTHENTICATE, NETWORK, KILLED
}

internal enum class SstpClientStatus {
    CALL_ABORT_IN_PROGRESS_1,
    CALL_ABORT_IN_PROGRESS_2,
    CALL_ABORT_TIMEOUT_PENDING,
    CALL_ABORT_PENDING,
    CALL_DISCONNECT_IN_PROGRESS_1,
    CALL_DISCONNECT_IN_PROGRESS_2,
    CALL_DISCONNECT_TIMEOUT_PENDING,
    CALL_DISCONNECT_ACK_PENDING,
    CLIENT_CALL_DISCONNECTED,
    CLIENT_CONNECT_REQUEST_SENT,
    CLIENT_CONNECT_ACK_RECEIVED,
    CLIENT_CALL_CONNECTED
}

internal class DualClientStatus {
    internal var ppp = PppClientStatus.INITIAL
    internal var sstp = SstpClientStatus.CLIENT_CALL_DISCONNECTED
}

internal class PppCredential(internal val username: String, internal val password: String)

internal class NetworkSetting(internal val host: String, internal val credential: PppCredential) {
    internal lateinit var serverCertificate: Certificate
    internal val guid = UUID.randomUUID().toString()
    internal var ipAdress: InetAddress? = null
    internal var primaryDns: InetAddress? = null
    internal var mru: Short? = null
    internal var isNegotiated: Boolean = false

    internal fun hashCertificate(hashProtocol: HashProtocol) : ByteArray {
        val md = MessageDigest.getInstance(hashProtocol.str)
        return md.digest(serverCertificate.encoded)
    }
}
