package kittoku.osc.client.ppp

import kittoku.osc.ControlMessage
import kittoku.osc.Result
import kittoku.osc.SharedBridge
import kittoku.osc.Where
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue
import kittoku.osc.unit.ppp.IpcpConfigureAck
import kittoku.osc.unit.ppp.IpcpConfigureFrame
import kittoku.osc.unit.ppp.IpcpConfigureReject
import kittoku.osc.unit.ppp.IpcpConfigureRequest
import kittoku.osc.unit.ppp.option.IpcpAddressOption
import kittoku.osc.unit.ppp.option.IpcpOptionPack
import kittoku.osc.unit.ppp.option.OPTION_TYPE_IPCP_DNS
import kittoku.osc.unit.ppp.option.OPTION_TYPE_IPCP_IP
import java.net.Inet4Address


internal class IpcpClient(bridge: SharedBridge) : ConfigClient<IpcpConfigureFrame>(Where.IPCP, bridge) {
    private val isDNSRequested = getBooleanPrefValue(OscPrefKey.DNS_DO_REQUEST_ADDRESS, bridge.prefs)
    private var isDNSRejected = false
    private val requestedAddress = if (getBooleanPrefValue(OscPrefKey.PPP_DO_REQUEST_STATIC_IPv4_ADDRESS, bridge.prefs)) {
        Inet4Address.getByName(getStringPrefValue(OscPrefKey.PPP_STATIC_IPv4_ADDRESS, bridge.prefs)).address
    } else {
        null
    }

    override fun tryCreateServerReject(request: IpcpConfigureFrame): IpcpConfigureFrame? {
        val reject = IpcpOptionPack()

        if (request.options.unknownOptions.isNotEmpty()) {
            reject.unknownOptions = request.options.unknownOptions
        }

        request.options.dnsOption?.also { // client doesn't have dns server
            reject.dnsOption = request.options.dnsOption
        }

        return if (reject.allOptions.isNotEmpty()) {
            IpcpConfigureReject().also {
                it.id = request.id
                it.options = reject
                it.options.order = request.options.order
            }
        } else null
    }

    override fun tryCreateServerNak(request: IpcpConfigureFrame): IpcpConfigureFrame? {
        return null
    }

    override fun createServerAck(request: IpcpConfigureFrame): IpcpConfigureFrame {
        return IpcpConfigureAck().also {
            it.id = request.id
            it.options = request.options
        }
    }

    override fun createClientRequest(): IpcpConfigureFrame {
        val request = IpcpConfigureRequest()

        requestedAddress?.also {
            it.copyInto(bridge.currentIPv4)
        }

        request.options.ipOption = IpcpAddressOption(OPTION_TYPE_IPCP_IP).also {
            bridge.currentIPv4.copyInto(it.address)
        }

        if (isDNSRequested && !isDNSRejected) {
            request.options.dnsOption = IpcpAddressOption(OPTION_TYPE_IPCP_DNS).also {
                bridge.currentProposedDNS.copyInto(it.address)
            }
        }

        return request
    }

    override suspend fun tryAcceptClientNak(nak: IpcpConfigureFrame) {
        nak.options.ipOption?.also {
            if (requestedAddress != null) {
                bridge.controlMailbox.send(ControlMessage(Where.IPCP, Result.ERR_ADDRESS_REJECTED))
            } else {
                it.address.copyInto(bridge.currentIPv4)
            }
        }

        nak.options.dnsOption?.also {
            it.address.copyInto(bridge.currentProposedDNS)
        }
    }

    override suspend fun tryAcceptClientReject(reject: IpcpConfigureFrame) {
        reject.options.ipOption?.also {
            bridge.controlMailbox.send(ControlMessage(Where.IPCP_IP, Result.ERR_OPTION_REJECTED))
        }

        reject.options.dnsOption?.also {
            isDNSRejected = true
        }
    }
}
