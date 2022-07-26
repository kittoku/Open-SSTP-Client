package kittoku.osc.client.control

import android.net.*
import android.os.Build
import kittoku.osc.client.ClientBridge
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.setStringPrefValue


internal class NetworkObserver(val bridge: ClientBridge) {
    private val manager = bridge.service.getSystemService(ConnectivityManager::class.java)
    private val callback: ConnectivityManager.NetworkCallback

    init {
        wipeStatus()

        val request = NetworkRequest.Builder().let {
            it.addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            it.removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            it.build()
        }


        callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
                    manager.getLinkProperties(network)?.also {
                        updateSummary(it)
                    }
                }
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                updateSummary(linkProperties)
            }
        }

        manager.registerNetworkCallback(request, callback)
    }

    private fun updateSummary(properties: LinkProperties) {
        val summary = mutableListOf<String>()

        summary.add("[Assigned IP Address]")
        properties.linkAddresses.forEach {
            summary.add(it.address.hostAddress)
        }
        summary.add("")

        summary.add("[DNS server]")
        properties.dnsServers.forEach {
            summary.add(it.hostAddress)
        }
        summary.add("")

        summary.add("[Route]")
        properties.routes.forEach {
            summary.add(it.toString())
        }
        summary.add("")

        bridge.sslTerminal!!.getSession().also {
            summary.add("[SSL/TLS parameters]")
            summary.add("PROTOCOL: ${it.protocol}")
            summary.add("SUITE: ${it.cipherSuite}")
        }

        summary.reduce { acc, s ->
            acc + "\n" + s
        }.also {
            setStringPrefValue(it, OscPreference.HOME_STATUS, bridge.prefs)
        }
    }

    private fun wipeStatus() {
        setStringPrefValue("", OscPreference.HOME_STATUS, bridge.prefs)
    }

    internal fun close() {
        try {
            manager.unregisterNetworkCallback(callback)
        } catch (_: IllegalArgumentException) {} // already unregistered

        wipeStatus()
    }
}
