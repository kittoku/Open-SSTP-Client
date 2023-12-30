package kittoku.osc.control

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import kittoku.osc.SharedBridge
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.setStringPrefValue


internal class NetworkObserver(val bridge: SharedBridge) {
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

        bridge.sslTerminal!!.getSession().also {
            if (!it.isValid) return

            summary.add("[SSL/TLS Parameters]")
            summary.add("PROTOCOL: ${it.protocol}")
            summary.add("SUITE: ${it.cipherSuite}")
        }
        summary.add("")

        summary.add("[Assigned IP Address]")
        properties.linkAddresses.forEach {
            summary.add(it.address.hostAddress ?: "")
        }
        summary.add("")

        summary.add("[DNS Server Address]")
        if (properties.dnsServers.isNotEmpty()) {
            properties.dnsServers.forEach {
                summary.add(it.hostAddress ?: "")
            }
        } else {
            summary.add("Not specified")
        }
        summary.add("")

        summary.add("[Routing]")
        properties.routes.forEach {
            summary.add(it.toString())
        }
        summary.add("")

        summary.add("[Allowed Apps]")
        if (bridge.allowedApps.isNotEmpty()) {
            bridge.allowedApps.forEach { summary.add(it.label) }
        } else {
            summary.add("All apps")
        }

        summary.reduce { acc, s ->
            acc + "\n" + s
        }.also {
            setStringPrefValue(it, OscPrefKey.HOME_STATUS, bridge.prefs)
        }
    }

    private fun wipeStatus() {
        setStringPrefValue("", OscPrefKey.HOME_STATUS, bridge.prefs)
    }

    internal fun close() {
        try {
            manager.unregisterNetworkCallback(callback)
        } catch (_: IllegalArgumentException) {} // already unregistered

        wipeStatus()
    }
}
