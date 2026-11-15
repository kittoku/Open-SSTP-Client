package kittoku.osc.terminal

import android.net.IpPrefix
import android.os.Build
import android.os.ParcelFileDescriptor
import kittoku.osc.DnsPresets
import kittoku.osc.ControlMessage
import kittoku.osc.IranApps
import kittoku.osc.IranRanges
import kittoku.osc.Result
import kittoku.osc.SharedBridge
import kittoku.osc.Where
import kittoku.osc.extension.toHexByteArray
import kittoku.osc.preference.LIST_TYPE_ALLOWED
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getSetPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.nio.ByteBuffer


internal class IPTerminal(private val bridge: SharedBridge) {
    private var fd: ParcelFileDescriptor? = null
    private var inputStream: FileInputStream? = null
    private var outputStream: FileOutputStream? = null

    private val doEnableAppBasedRule = getBooleanPrefValue(OscPrefKey.ROUTE_DO_ENABLE_APP_BASED_RULE, bridge.prefs)
    private val isAllowedList = getStringPrefValue(OscPrefKey.ROUTE_APP_LIST_TYPE, bridge.prefs) == LIST_TYPE_ALLOWED
    private val doAddDefaultRoute = getBooleanPrefValue(OscPrefKey.ROUTE_DO_ADD_DEFAULT_ROUTE, bridge.prefs)
    private val doRoutePrivateAddresses = getBooleanPrefValue(OscPrefKey.ROUTE_DO_ROUTE_PRIVATE_ADDRESSES, bridge.prefs)
    private val doUseCustomDNSServer = getBooleanPrefValue(OscPrefKey.DNS_DO_USE_CUSTOM_SERVER, bridge.prefs)
    private val doAddCustomRoutes = getBooleanPrefValue(OscPrefKey.ROUTE_DO_ADD_CUSTOM_ROUTES, bridge.prefs)

    internal suspend fun initialize() {
        if (bridge.PPP_IPv4_ENABLED) {
            if (bridge.currentIPv4.contentEquals(ByteArray(4))) {
                bridge.controlMailbox.send(ControlMessage(Where.IPv4, Result.ERR_INVALID_ADDRESS))
                return
            }

            InetAddress.getByAddress(bridge.currentIPv4).also {
                bridge.builder.addAddress(it, 32)
            }

            if (doUseCustomDNSServer) {
                bridge.builder.addDnsServer(getStringPrefValue(OscPrefKey.DNS_CUSTOM_ADDRESS, bridge.prefs))

                // A DNS preset (menu > DNS) has a second address.
                bridge.prefs.getString(DnsPresets.KEY_SECONDARY, "")?.trim()?.takeIf { it.isNotEmpty() }?.let {
                    try {
                        bridge.builder.addDnsServer(it)
                    } catch (_: IllegalArgumentException) {
                    }
                }
            }

            if (!bridge.currentProposedDNS.contentEquals(ByteArray(4))) {
                InetAddress.getByAddress(bridge.currentProposedDNS).also {
                    bridge.builder.addDnsServer(it)
                }
            }

            setIPv4BasedRouting()
        }

        if (bridge.PPP_IPv6_ENABLED) {
            if (bridge.currentIPv6.contentEquals(ByteArray(8))) {
                bridge.controlMailbox.send(ControlMessage(Where.IPv6, Result.ERR_INVALID_ADDRESS))
                return
            }

            ByteArray(16).also { // for link local addresses
                "FE80".toHexByteArray().copyInto(it)
                ByteArray(6).copyInto(it, destinationOffset = 2)
                bridge.currentIPv6.copyInto(it, destinationOffset = 8)
                bridge.builder.addAddress(InetAddress.getByAddress(it), 64)
            }

            setIPv6BasedRouting()
        }

        if (doAddCustomRoutes) {
            addCustomRoutes()
        }

        addAppBypass()

        bridge.builder.setMtu(bridge.PPP_MTU)
        bridge.builder.setBlocking(true)

        fd = bridge.builder.establish()!!.also {
            inputStream = FileInputStream(it.fileDescriptor)
            outputStream = FileOutputStream(it.fileDescriptor)
        }

        bridge.controlMailbox.send(ControlMessage(Where.IP, Result.PROCEEDED))
    }

    private fun setIPv4BasedRouting() {
        if (doAddDefaultRoute) {
            if (!addRoutesWithoutIranianRanges()) {
                bridge.builder.addRoute("0.0.0.0", 0)
            }
        }

        if (doRoutePrivateAddresses) {
            bridge.builder.addRoute("10.0.0.0", 8)
            bridge.builder.addRoute("172.16.0.0", 12)
            bridge.builder.addRoute("192.168.0.0", 16)
        }
    }

    private fun setIPv6BasedRouting() {
        if (doAddDefaultRoute) {
            bridge.builder.addRoute("::", 0)
        }

        if (doRoutePrivateAddresses) {
            bridge.builder.addRoute("fc00::", 7)
        }
    }

    private fun addAppBasedRules() {
        bridge.selectedApps.forEach {
            if (isAllowedList) {
                bridge.builder.addAllowedApplication(it.packageName)
            } else {
                bridge.builder.addDisallowedApplication(it.packageName)
            }
        }
    }

    // Iranian apps and the apps the user picked connect directly. Apps that are not installed are skipped.
    private fun addAppBypass() {
        if (!bridge.prefs.getBoolean(IranApps.KEY_ENABLED, true)) {
            return
        }

        val packages = HashSet<String>()
        bridge.prefs.getStringSet(IranApps.KEY_LIST, null)?.let { packages.addAll(it) }
        packages.addAll(getSetPrefValue(OscPrefKey.ROUTE_SELECTED_APPS, bridge.prefs))

        packages.forEach {
            try {
                bridge.builder.addDisallowedApplication(it)
            } catch (_: Exception) {
                // not installed on this phone
            }
        }
    }

    // Experimental: Iranian IPv4 ranges connect directly. Returns false if the normal default route should be used.
    private fun addRoutesWithoutIranianRanges(): Boolean {
        if (!bridge.prefs.getBoolean(IranRanges.KEY_ENABLED, false)) {
            return false
        }

        val ranges = IranRanges.load(bridge.service)
        if (ranges.isEmpty()) {
            return false
        }

        return try {
            if (Build.VERSION.SDK_INT >= 33) {
                val excluded = IranRanges.toCidrs(ranges)
                if (excluded.size > IranRanges.MAX_ROUTES) return false

                bridge.builder.addRoute("0.0.0.0", 0)
                excluded.forEach { (address, length) ->
                    bridge.builder.excludeRoute(IpPrefix(InetAddress.getByName(IranRanges.format(address)), length))
                }
            } else {
                val routes = IranRanges.complementCidrs(ranges)
                if (routes.size > IranRanges.MAX_ROUTES) return false

                routes.forEach { (address, length) ->
                    bridge.builder.addRoute(IranRanges.format(address), length)
                }
            }

            true
        } catch (_: Exception) {
            false
        }
    }

    private suspend fun addCustomRoutes(): Boolean {
        getStringPrefValue(OscPrefKey.ROUTE_CUSTOM_ROUTES, bridge.prefs).split("\n").filter { it.isNotEmpty() }.forEach {
            val parsed = it.split("/")

            if (parsed.size != 2) {
                bridge.controlMailbox.send(ControlMessage(Where.ROUTE, Result.ERR_PARSING_FAILED))
                return false
            }

            val address = parsed[0]
            val prefix = parsed[1].toIntOrNull()

            if (prefix == null){
                bridge.controlMailbox.send(ControlMessage(Where.ROUTE, Result.ERR_PARSING_FAILED))
                return false
            }

            try {
                bridge.builder.addRoute(address, prefix)
            } catch (_: IllegalArgumentException) {
                bridge.controlMailbox.send(ControlMessage(Where.ROUTE, Result.ERR_PARSING_FAILED))
                return false
            }
        }

        return true
    }

    internal fun writePacket(start: Int, size: Int, buffer: ByteBuffer) {
        // nothing will be written until initialized
        // the position won't be changed
        outputStream?.write(buffer.array(), start, size)
    }

    internal fun readPacket(buffer: ByteBuffer) {
        buffer.clear()
        buffer.position(inputStream?.read(buffer.array(), 0, bridge.PPP_MTU) ?: buffer.position())
        buffer.flip()
    }

    internal fun close() {
        fd?.close()
    }
}
