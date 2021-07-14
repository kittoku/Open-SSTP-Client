package kittoku.osc.misc

import android.content.SharedPreferences
import kittoku.osc.MAX_MTU
import kittoku.osc.MIN_MRU
import kittoku.osc.fragment.*
import kittoku.osc.unit.*
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

internal class NetworkSetting(prefs: SharedPreferences) {
    internal val HOME_HOST = StrPreference.HOME_HOST.getValue(prefs)
    internal val HOME_USER = StrPreference.HOME_USER.getValue(prefs)
    internal val HOME_PASS = StrPreference.HOME_PASS.getValue(prefs)
    internal val SSL_PORT = IntPreference.SSL_PORT.getValue(prefs)
    internal val SSL_VERSION = StrPreference.SSL_VERSION.getValue(prefs)
    internal val SSL_DO_VERIFY = BoolPreference.SSL_DO_VERIFY.getValue(prefs)
    internal val SSL_DO_ADD_CERT = BoolPreference.SSL_DO_ADD_CERT.getValue(prefs)
    internal val SSL_CERT_DIR = DirPreference.SSL_CERT_DIR.getValue(prefs)
    internal val SSL_DO_SELECT_SUITES = BoolPreference.SSL_DO_SELECT_SUITES.getValue(prefs)
    internal val SSL_SUITES = SetPreference.SSL_SUITES.getValue(prefs)
    internal val PPP_MRU = IntPreference.PPP_MRU.getValue(prefs)
    internal val PPP_MTU = IntPreference.PPP_MTU.getValue(prefs)
    internal val PPP_PAP_ENABLED = BoolPreference.PPP_PAP_ENABLED.getValue(prefs)
    internal val PPP_MSCHAPv2_ENABLED = BoolPreference.PPP_MSCHAPv2_ENABLED.getValue(prefs)
    internal val PPP_IPv4_ENABLED = BoolPreference.PPP_IPv4_ENABLED.getValue(prefs)
    internal val PPP_IPv6_ENABLED = BoolPreference.PPP_IPv6_ENABLED.getValue(prefs)
    internal val IP_PREFIX = IntPreference.IP_PREFIX.getValue(prefs)
    internal val IP_ONLY_LAN = BoolPreference.IP_ONLY_LAN.getValue(prefs)
    internal val IP_ONLY_ULA = BoolPreference.IP_ONLY_ULA.getValue(prefs)
    internal val BUFFER_INCOMING = IntPreference.BUFFER_INCOMING.getValue(prefs)
    internal val BUFFER_OUTGOING = IntPreference.BUFFER_OUTGOING.getValue(prefs)
    internal val LOG_DO_SAVE_LOG = BoolPreference.LOG_DO_SAVE_LOG.getValue(prefs)
    internal val LOG_DIR = DirPreference.LOG_DIR.getValue(prefs)

    internal lateinit var serverCertificate: Certificate
    internal lateinit var hashProtocol: HashProtocol
    internal lateinit var nonce: ByteArray
    lateinit var chapSetting: ChapSetting
    internal val guid = UUID.randomUUID().toString()
    internal var currentMru = PPP_MRU
    internal var currentMtu = PPP_MTU
    internal var currentAuth = if (PPP_MSCHAPv2_ENABLED) AuthSuite.MSCHAPv2 else AuthSuite.PAP
    internal val currentIp = ByteArray(4)
    internal val currentDns = ByteArray(4)
    internal val currentIpv6 = ByteArray(8)


    internal val mgMru = object : OptionManager<LcpMruOption>() {
        override fun create() = LcpMruOption().also {
            it.unitSize = currentMru
        }

        override fun compromiseReq(option: LcpMruOption): Boolean {
            currentMtu = min(max(PPP_MTU, option.unitSize), MAX_MTU)
            return option.unitSize >= currentMtu
        }

        override fun compromiseNak(option: LcpMruOption) {
            currentMru = max(min(PPP_MRU, option.unitSize), MIN_MRU)
        }
    }

    internal val mgAuth = object : OptionManager<LcpAuthOption>() {
        override fun create() = LcpAuthOption().also {
            if (currentAuth == AuthSuite.MSCHAPv2) {
                it.protocol = AuthProtocol.CHAP.value
                it.holder = ByteArray(1) { ChapAlgorithm.MSCHAPv2.value }
            }
        }

        override fun compromiseReq(option: LcpAuthOption): Boolean {
            when (AuthProtocol.resolve(option.protocol)) {
                AuthProtocol.PAP -> {
                    return if (PPP_PAP_ENABLED) {
                        currentAuth = AuthSuite.PAP
                        true
                    } else {
                        currentAuth = AuthSuite.MSCHAPv2
                        false
                    }
                }

                AuthProtocol.CHAP -> {
                    if (option._length == 5 && option.holder[0] == ChapAlgorithm.MSCHAPv2.value) {
                        return if (PPP_MSCHAPv2_ENABLED) {
                            currentAuth = AuthSuite.MSCHAPv2
                            true
                        } else {
                            currentAuth = AuthSuite.PAP
                            false
                        }
                    }
                }
            }

            currentAuth = if (PPP_MSCHAPv2_ENABLED) AuthSuite.MSCHAPv2 else AuthSuite.PAP
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

    internal val mgIpv6 = object : OptionManager<Ipv6cpIdentifierOption>() {
        override fun create() = Ipv6cpIdentifierOption().also {
            currentIpv6.copyInto(it.identifier)
        }

        override fun compromiseReq(option: Ipv6cpIdentifierOption) = true

        override fun compromiseNak(option: Ipv6cpIdentifierOption) {
            option.identifier.copyInto(currentIpv6)
        }
    }
}

internal abstract class OptionManager<T> {
    internal var isRejected = false

    internal abstract fun create(): T

    internal abstract fun compromiseReq(option: T): Boolean

    internal abstract fun compromiseNak(option: T)
}
