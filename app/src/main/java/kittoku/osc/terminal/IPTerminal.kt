package kittoku.osc.terminal

import android.os.ParcelFileDescriptor
import kittoku.osc.client.ClientBridge
import kittoku.osc.client.ControlMessage
import kittoku.osc.client.Result
import kittoku.osc.client.Where
import kittoku.osc.extension.isSame
import kittoku.osc.extension.toHexByteArray
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.nio.ByteBuffer


internal class IPTerminal(private val bridge: ClientBridge) {
    private var fd: ParcelFileDescriptor? = null

    private lateinit var inputStream: FileInputStream
    private lateinit var outputStream: FileOutputStream

    private val isDefaultRouteAdded = getBooleanPrefValue(OscPreference.ROUTE_DO_ADD_DEFAULT_ROUTE, bridge.prefs)
    private val isPrivateAddressesRouted = getBooleanPrefValue(OscPreference.ROUTE_DO_ROUTE_PRIVATE_ADDRESSES, bridge.prefs)

    private suspend fun addCustomRoutes(table: String): Boolean {
        table.split("\n").filter { it.isNotEmpty() }.forEach {
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

    internal suspend fun initializeTun(): Boolean {
        if (bridge.PPP_IPv4_ENABLED) {
            if (bridge.currentIPv4.isSame(ByteArray(4))) {
                bridge.controlMailbox.send(ControlMessage(Where.IPv4, Result.ERR_INVALID_ADDRESS))
                return false
            }

            if (isDefaultRouteAdded) {
                bridge.builder.addRoute("0.0.0.0", 0)
            }

            if (isPrivateAddressesRouted) {
                bridge.builder.addRoute("10.0.0.0", 8)
                bridge.builder.addRoute("172.16.0.0", 12)
                bridge.builder.addRoute("192.168.0.0", 16)
            }

            InetAddress.getByAddress(bridge.currentIPv4).also {
                bridge.builder.addAddress(it, 32)
            }

            if (bridge.DNS_DO_USE_CUSTOM_SERVER) {
                bridge.builder.addDnsServer(getStringPrefValue(OscPreference.DNS_CUSTOM_ADDRESS, bridge.prefs))
            }

            if (!bridge.currentProposedDNS.isSame(ByteArray(4))) {
                InetAddress.getByAddress(bridge.currentProposedDNS).also {
                    bridge.builder.addDnsServer(it)
                }
            }
        }

        if (bridge.PPP_IPv6_ENABLED) {
            if (bridge.currentIPv6.isSame(ByteArray(8))) {
                bridge.controlMailbox.send(ControlMessage(Where.IPv6, Result.ERR_INVALID_ADDRESS))
                return false
            }

            if (isDefaultRouteAdded) {
                bridge.builder.addRoute("::", 0)
            }

            if (isPrivateAddressesRouted) {
                bridge.builder.addRoute("fc00::", 7)
            }

            ByteArray(16).also { // for link local addresses
                "FE80".toHexByteArray().copyInto(it)
                ByteArray(6).copyInto(it, destinationOffset = 2)
                bridge.currentIPv6.copyInto(it, destinationOffset = 8)
                bridge.builder.addAddress(InetAddress.getByAddress(it), 64)
            }
        }

        if (getBooleanPrefValue(OscPreference.ROUTE_DO_ADD_CUSTOM_ROUTES, bridge.prefs)) {
            addCustomRoutes(getStringPrefValue(OscPreference.ROUTE_CUSTOM_ROUTES, bridge.prefs))
        }

        bridge.builder.setMtu(bridge.PPP_MTU)
        bridge.builder.setBlocking(true)

        fd = bridge.builder.establish()!!.also {
            inputStream = FileInputStream(it.fileDescriptor)
            outputStream = FileOutputStream(it.fileDescriptor)
        }

        return true
    }

    internal fun writePacket(start: Int, size: Int, buffer: ByteBuffer) {
        // the position won't be changed
        outputStream.write(buffer.array(), start, size)
    }

    internal fun readPacket(buffer: ByteBuffer) {
        buffer.clear()
        buffer.position(inputStream.read(buffer.array(), 0, bridge.PPP_MTU))
        buffer.flip()
    }

    internal fun close() {
        fd?.close()
    }
}
