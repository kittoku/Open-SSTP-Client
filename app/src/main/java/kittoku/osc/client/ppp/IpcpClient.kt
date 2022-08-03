package kittoku.osc.client.ppp

import kittoku.osc.client.ClientBridge
import kittoku.osc.client.ControlMessage
import kittoku.osc.client.Result
import kittoku.osc.client.Where
import kittoku.osc.unit.ppp.IpcpConfigureAck
import kittoku.osc.unit.ppp.IpcpConfigureFrame
import kittoku.osc.unit.ppp.IpcpConfigureReject
import kittoku.osc.unit.ppp.IpcpConfigureRequest
import kittoku.osc.unit.ppp.option.IpcpAddressOption
import kittoku.osc.unit.ppp.option.IpcpOptionPack
import kittoku.osc.unit.ppp.option.OPTION_TYPE_IPCP_DNS
import kittoku.osc.unit.ppp.option.OPTION_TYPE_IPCP_IP


internal class IpcpClient(bridge: ClientBridge) : ConfigClient<IpcpConfigureFrame>(Where.IPCP, bridge) {
    private var isDNSRejected = false

    override fun tryCreateServerReject(request: IpcpConfigureFrame): IpcpConfigureFrame? {
        val rejected = IpcpOptionPack()

        if (request.options.unknownOptions.isNotEmpty()) {
            rejected.unknownOptions = request.options.unknownOptions
        }

        request.options.dnsOption?.also { // client doesn't have dns server
            rejected.dnsOption = request.options.dnsOption
        }

        return if (rejected.allOptions.isNotEmpty()) {
            IpcpConfigureReject().also {
                it.id = request.id
                it.options = rejected
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

        request.options.ipOption = IpcpAddressOption(OPTION_TYPE_IPCP_IP).also {
            bridge.currentIPv4.copyInto(it.address)
        }

        if (bridge.DNS_DO_REQUEST_ADDRESS && !isDNSRejected) {
            request.options.dnsOption = IpcpAddressOption(OPTION_TYPE_IPCP_DNS).also {
                bridge.currentProposedDNS.copyInto(it.address)
            }
        }

        return request
    }

    override fun tryAcceptClientNak(nak: IpcpConfigureFrame) {
        nak.options.ipOption?.also {
            it.address.copyInto(bridge.currentIPv4)
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
