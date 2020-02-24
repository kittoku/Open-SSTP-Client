package kittoku.opensstpclient.misc

import kittoku.opensstpclient.*
import kittoku.opensstpclient.unit.*
import java.security.cert.Certificate
import java.util.*
import kotlin.math.max
import kotlin.math.min


internal enum class AuthSuite {
    PAP, MSCHAPv2
}

internal class ChapSetting {
    val serverChallenge = ByteArray(16)
    val clientChallenge = ByteArray(16)
    val serverResponse = ByteArray(42)
    val clientResponse = ByteArray(24)
}

internal class NetworkSetting(
    internal val host: String,
    internal val username: String,
    internal val password: String,
    internal val port: Int?,
    internal val customMru: Int?,
    internal val customMtu: Int?,
    internal val customPrefix: Int?,
    internal val sslProtocol: String,
    internal val isPapAcceptable: Boolean,
    internal val isMschapv2Acceptable: Boolean,
    internal val isHvIgnored: Boolean,
    internal val isDecryptable: Boolean
) {
    internal lateinit var serverCertificate: Certificate
    internal lateinit var hashProtocol: HashProtocol
    internal lateinit var nonce: ByteArray
    lateinit var chapSetting: ChapSetting
    internal val guid = UUID.randomUUID().toString()
    internal var currentMru = customMru ?: DEFAULT_MRU
    internal var currentMtu = customMtu ?: DEFAULT_MTU
    internal var currentAuth = if (isMschapv2Acceptable) AuthSuite.MSCHAPv2 else AuthSuite.PAP
    internal val currentIp = ByteArray(4)
    internal val currentDns = ByteArray(4)

    internal val mgMru = object : OptionManager<LcpMruOption>() {
        override fun create() = LcpMruOption().also {
            it.unitSize = currentMru
        }

        override fun compromiseReq(option: LcpMruOption): Boolean {
            if (customMtu != null) {
                currentMtu = min(max(customMtu, option.unitSize), MAX_MTU)
                return option.unitSize >= currentMtu
            }

            return if (option.unitSize >= MIN_MTU) {
                currentMtu = min(option.unitSize, MAX_MTU)
                true
            } else {
                currentMtu = MIN_MTU
                false
            }
        }

        override fun compromiseNak(option: LcpMruOption) {
            currentMru = when {
                customMru != null -> max(min(customMru, option.unitSize), MIN_MRU)

                option.unitSize > MAX_MRU -> MAX_MRU

                option.unitSize < MIN_MRU -> MIN_MRU

                else -> option.unitSize
            }
        }
    }

    internal val mgAuth = object : OptionManager<LcpAuthOption>() {
        override fun create() = LcpAuthOption().also {
            if (currentAuth == AuthSuite.MSCHAPv2) {
                it.protocol = AuthProtocol.CHAP.value
                it.holder.add(ChapAlgorithm.MSCHAPv2.value)
            }
        }

        override fun compromiseReq(option: LcpAuthOption): Boolean {
            when (AuthProtocol.resolve(option.protocol)) {
                AuthProtocol.PAP -> {
                    return if (isPapAcceptable) {
                        currentAuth = AuthSuite.PAP
                        true
                    } else {
                        currentAuth = AuthSuite.MSCHAPv2
                        false
                    }
                }

                AuthProtocol.CHAP -> {
                    if (option._length == 5 && option.holder[0] == ChapAlgorithm.MSCHAPv2.value) {
                        return if (isMschapv2Acceptable) {
                            currentAuth = AuthSuite.MSCHAPv2
                            true
                        } else {
                            currentAuth = AuthSuite.PAP
                            false
                        }
                    }
                }
            }

            currentAuth = if (isMschapv2Acceptable) AuthSuite.MSCHAPv2 else AuthSuite.PAP
            return false
        }

        override fun compromiseNak(option: LcpAuthOption) {}
    }.also {
        it.isRejected = true
    }

    internal val mgIp = object : OptionManager<IpcpIpOption>() {
        override fun create() = IpcpIpOption().also {
            currentIp.copyInto(it.address)
        }

        override fun compromiseReq(option: IpcpIpOption) = true

        override fun compromiseNak(option: IpcpIpOption) {
            option.address.copyInto(currentIp)
        }
    }

    internal val mgDns = object : OptionManager<IpcpDnsOption>() {
        override fun create() = IpcpDnsOption().also {
            currentDns.copyInto(it.address)
        }

        override fun compromiseReq(option: IpcpDnsOption) = true

        override fun compromiseNak(option: IpcpDnsOption) {
            option.address.copyInto(currentDns)
        }
    }
}

internal abstract class OptionManager<T> {
    internal var isRejected = false

    internal abstract fun create(): T

    internal abstract fun compromiseReq(option: T): Boolean

    internal abstract fun compromiseNak(option: T)
}
