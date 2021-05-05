package kittoku.opensstpclient.misc

import android.net.*
import android.os.Build
import androidx.preference.PreferenceManager
import kittoku.opensstpclient.SstpVpnService
import kittoku.opensstpclient.fragment.StatusPreference

internal class NetworkObserver(vpnService: SstpVpnService) {
    private val manager = vpnService.getSystemService(ConnectivityManager::class.java)

    private val callback: ConnectivityManager.NetworkCallback

    private val prefs = PreferenceManager.getDefaultSharedPreferences(vpnService.applicationContext)

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
                    manager.getLinkProperties(network)?.also { linkProperties ->
                        makeSummary(linkProperties).also {
                            prefs.edit().putString(StatusPreference.STATUS.name, it).apply()
                        }
                    }

                }
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                makeSummary(linkProperties).also {
                    prefs.edit().putString(StatusPreference.STATUS.name, it).apply()
                }
            }
        }

        manager.registerNetworkCallback(request, callback)
    }

    private fun makeSummary(properties: LinkProperties): String {
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

        return summary.reduce { acc, s ->
            acc + "\n" + s
        }
    }

    private fun wipeStatus() {
        prefs.edit().putString(StatusPreference.STATUS.name, "").apply()
    }

    internal fun close() {
        manager.unregisterNetworkCallback(callback)
        wipeStatus()
    }
}
