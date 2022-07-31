@file:Suppress("BlockingMethodInNonBlockingContext")

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
import kittoku.osc.preference.accessor.getIntPrefValue
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.nio.ByteBuffer


internal class IPTerminal(private val bridge: ClientBridge) {
    private var fd: ParcelFileDescriptor? = null

    private lateinit var inputStream: FileInputStream
    private lateinit var outputStream: FileOutputStream

    private fun getPrefixLength(array: ByteArray): Int {
        if (array[0] == 10.toByte()) return 8

        if (array[0] == 172.toByte() && array[1] in 16..31) return 20

        return 16
    }

    private fun getNetworkAddress(array: ByteArray, prefixLength: Int): InetAddress {
        val buffer = ByteBuffer.allocate(4)
        buffer.put(array)

        var num = buffer.getInt(0)
        var mask: Int = -1
        mask = mask.shl(32 - prefixLength)
        num = num and mask
        buffer.putInt(0, num)

        return InetAddress.getByAddress(buffer.array())
    }

    internal suspend fun initializeTun(): Boolean {
        if (bridge.PPP_IPv4_ENABLED) {
            if (bridge.currentIp.isSame(ByteArray(4))) {
                bridge.controlMailbox.send(ControlMessage(Where.IPv4, Result.ERR_INVALID_ADDRESS))
                return false
            }

            val givenPrefix = getIntPrefValue(OscPreference.IP_PREFIX, bridge.prefs)
            val prefix = if (givenPrefix == 0) getPrefixLength(bridge.currentIp) else givenPrefix
            val hostAddress = InetAddress.getByAddress(bridge.currentIp)
            val networkAddress = getNetworkAddress(bridge.currentIp, prefix)

            bridge.builder.addAddress(hostAddress, prefix)
            bridge.builder.addRoute(networkAddress, prefix)

            if (!bridge.currentDns.isSame(ByteArray(4))) {
                val dnsAddress = InetAddress.getByAddress(bridge.currentDns)
                bridge.builder.addDnsServer(dnsAddress)
            }

            if (!getBooleanPrefValue(OscPreference.IP_ONLY_LAN, bridge.prefs)) {
                bridge.builder.addRoute("0.0.0.0", 0)
            }
        }

        if (bridge.PPP_IPv6_ENABLED) {
            if (bridge.currentIpv6.isSame(ByteArray(8))) {
                bridge.controlMailbox.send(ControlMessage(Where.IPv6, Result.ERR_INVALID_ADDRESS))
                return false
            }

            val address = ByteArray(16)
            "FE80".toHexByteArray().copyInto(address)
            ByteArray(6).copyInto(address, destinationOffset = 2)
            bridge.currentIpv6.copyInto(address, destinationOffset = 8)

            bridge.builder.addAddress(InetAddress.getByAddress(address), 64)
            bridge.builder.addRoute("fc00::", 7)

            if (!getBooleanPrefValue(OscPreference.IP_ONLY_ULA, bridge.prefs)) {
                bridge.builder.addRoute("::", 0)
            }
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
