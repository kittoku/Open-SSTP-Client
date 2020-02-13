package kittoku.opensstpclient.misc

import kittoku.opensstpclient.unit.*
import java.security.cert.Certificate
import java.util.*


internal class NetworkSetting(
    internal val host: String,
    internal val username: String,
    internal val password: String,
    internal val port: Int?,
    customMru: Int?,
    internal val customMtu: Int?,
    isPapAcceptable: Boolean,
    isMschapv2Acceptable: Boolean,
    internal val isHvIgnored: Boolean,
    internal val isDecryptable: Boolean
) {
    internal lateinit var serverCertificate: Certificate
    internal lateinit var hashProtocol: HashProtocol
    internal lateinit var nonce: ByteArray
    internal val guid = UUID.randomUUID().toString()

    internal val mgMru = when {
        customMru == 1500 -> {
            OptionManager(LcpMruOption(), arrayOf(LcpMruOption()), true)
        }

        customMru != null -> {
            LcpMruOption().let {
                it.unitSize = customMru.toShort()
                OptionManager(it, arrayOf(it.copy()), false)
            }
        }

        else -> OptionManager(LcpMruOption(), arrayOf(), true)
    }

    internal val mgAuth = when {
        isMschapv2Acceptable && isPapAcceptable -> {
            LcpAuthOption().let {
                it.protocol = AuthProtocol.CHAP.value
                it.holder.add(ChapAlgorithm.MS_CHAPv2.value)
                OptionManager(it, arrayOf(it.copy(), LcpAuthOption()), true)
            }
        }

        isMschapv2Acceptable -> {
            LcpAuthOption().let {
                it.protocol = AuthProtocol.CHAP.value
                it.holder.add(ChapAlgorithm.MS_CHAPv2.value)
                OptionManager(it, arrayOf(it.copy()), false)
            }
        }

        else -> OptionManager(LcpAuthOption(), arrayOf(), true)
    }

    internal val mgIpAddress = OptionManager(IpcpIpAddressOption(), arrayOf(), false)
    internal val mgDnsAddress = OptionManager(IpcpDnsAddressOption(), arrayOf(), true)
}

internal class OptionManager<T : Option<T>>(
    internal var current: T,
    internal val candidates: Array<T>,
    internal val isRejectable: Boolean
) {
    internal var isRejected = false

    internal fun isAcceptable(suggestion: T): Boolean {
        if (candidates.isEmpty()) return true

        candidates.forEach { if (it.isMatchedTo(suggestion)) return true }

        return false
    }
}
