package kittoku.osc.client.ppp

import kittoku.osc.ControlMessage
import kittoku.osc.DEFAULT_MRU
import kittoku.osc.MIN_MRU
import kittoku.osc.Result
import kittoku.osc.SharedBridge
import kittoku.osc.Where
import kittoku.osc.preference.AUTH_PROTOCOL_EAP_MSCHAPv2
import kittoku.osc.preference.AUTH_PROTOCOL_MSCHAPv2
import kittoku.osc.preference.AUTH_PROTOCOl_PAP
import kittoku.osc.unit.ppp.LCPConfigureAck
import kittoku.osc.unit.ppp.LCPConfigureFrame
import kittoku.osc.unit.ppp.LCPConfigureNak
import kittoku.osc.unit.ppp.LCPConfigureReject
import kittoku.osc.unit.ppp.LCPConfigureRequest
import kittoku.osc.unit.ppp.PPP_PROTOCOL_CHAP
import kittoku.osc.unit.ppp.PPP_PROTOCOL_EAP
import kittoku.osc.unit.ppp.PPP_PROTOCOL_PAP
import kittoku.osc.unit.ppp.option.AuthOption
import kittoku.osc.unit.ppp.option.CHAP_ALGORITHM_MSCHAPv2
import kittoku.osc.unit.ppp.option.LCPOptionPack
import kittoku.osc.unit.ppp.option.MRUOption
import kotlin.math.max
import kotlin.math.min


internal class LCPClient(bridge: SharedBridge) : ConfigClient<LCPConfigureFrame>(Where.LCP, bridge) {
    private var isMruRejected = false

    override fun tryCreateServerReject(request: LCPConfigureFrame): LCPConfigureFrame? {
        val reject = LCPOptionPack()

        if (request.options.unknownOptions.isNotEmpty()) {
            reject.unknownOptions = request.options.unknownOptions
        }

        return if (reject.allOptions.isNotEmpty()) {
            LCPConfigureReject().also {
                it.id = request.id
                it.options = reject
                it.options.order = request.options.order
            }
        } else null
    }

    override fun tryCreateServerNak(request: LCPConfigureFrame): LCPConfigureFrame? {
        val nak = LCPOptionPack()

        val serverMru = request.options.mruOption?.unitSize ?: DEFAULT_MRU
        if (serverMru < bridge.PPP_MTU) {
            nak.mruOption = MRUOption().also { it.unitSize = bridge.PPP_MTU }
        }


        val serverAuth = request.options.authOption
        var isAuthAcknowledged = false

        when (serverAuth?.protocol) {
            PPP_PROTOCOL_EAP -> {
                if (bridge.isEnabled(AUTH_PROTOCOL_EAP_MSCHAPv2)) {
                    bridge.currentAuth = AUTH_PROTOCOL_EAP_MSCHAPv2
                    isAuthAcknowledged = true
                }
            }

            PPP_PROTOCOL_CHAP -> {
                if (serverAuth.holder.size != 1) {
                    throw NotImplementedError(serverAuth.holder.size.toString())
                }

                if (serverAuth.holder[0] == CHAP_ALGORITHM_MSCHAPv2 && bridge.isEnabled(AUTH_PROTOCOL_MSCHAPv2)) {
                    bridge.currentAuth = AUTH_PROTOCOL_MSCHAPv2
                    isAuthAcknowledged = true
                }
            }

            PPP_PROTOCOL_PAP -> {
                if (bridge.isEnabled(AUTH_PROTOCOl_PAP)) {
                    bridge.currentAuth = AUTH_PROTOCOl_PAP
                    isAuthAcknowledged = true
                }
            }
        }

        if (!isAuthAcknowledged) {
            val authOption = AuthOption()
            when {
                bridge.isEnabled(AUTH_PROTOCOL_EAP_MSCHAPv2) -> {
                    authOption.protocol = PPP_PROTOCOL_EAP
                }

                bridge.isEnabled(AUTH_PROTOCOL_MSCHAPv2) -> {
                    authOption.protocol = PPP_PROTOCOL_CHAP
                    authOption.holder = ByteArray(1) { CHAP_ALGORITHM_MSCHAPv2 }
                }

                bridge.isEnabled(AUTH_PROTOCOl_PAP) -> {
                    authOption.protocol = PPP_PROTOCOL_PAP
                }

                else -> throw NotImplementedError()
            }

            nak.authOption = authOption
        }


        return if (nak.allOptions.isNotEmpty()) {
            LCPConfigureNak().also {
                it.id = request.id
                it.options = nak
                it.options.order = request.options.order
            }
        } else null
    }

    override fun createServerAck(request: LCPConfigureFrame): LCPConfigureFrame {
        return LCPConfigureAck().also {
            it.id = request.id
            it.options = request.options
        }
    }


    override fun createClientRequest(): LCPConfigureFrame {
        val request = LCPConfigureRequest()

        if (!isMruRejected) {
            request.options.mruOption = MRUOption().also { it.unitSize = bridge.currentMRU }
        }

        return request
    }

    override suspend fun tryAcceptClientNak(nak: LCPConfigureFrame) {
        nak.options.mruOption?.also {
            bridge.currentMRU = max(min(it.unitSize, bridge.PPP_MRU), MIN_MRU)
        }
    }

    override suspend fun tryAcceptClientReject(reject: LCPConfigureFrame) {
        reject.options.mruOption?.also {
            isMruRejected = true

            if (DEFAULT_MRU > bridge.PPP_MRU) {
                bridge.controlMailbox.send(
                    ControlMessage(Where.LCP_MRU, Result.ERR_OPTION_REJECTED)
                )
            }
        }

        reject.options.authOption?.also {
            bridge.controlMailbox.send(ControlMessage(Where.LCP_AUTH, Result.ERR_OPTION_REJECTED))
        }
    }
}
