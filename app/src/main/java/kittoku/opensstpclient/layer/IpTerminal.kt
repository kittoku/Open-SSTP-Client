package kittoku.opensstpclient.layer

import android.os.Build
import android.os.ParcelFileDescriptor
import kittoku.opensstpclient.ControlClient
import kittoku.opensstpclient.misc.isSame
import kittoku.opensstpclient.misc.toHexByteArray
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.nio.ByteBuffer


internal class IpTerminal(parent: ControlClient) : Terminal(parent) {
    private lateinit var fd: ParcelFileDescriptor

    internal lateinit var ipInput: FileInputStream

    internal lateinit var ipOutput: FileOutputStream

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

    internal fun initializeTun() {
        val setting = parent.networkSetting
        val builder = parent.builder

        if (setting.isIpv4Enabled) {
            if (setting.mgIp.isRejected) {
                throw Exception("IPv4 NCP was rejected")
            }

            if (setting.currentIp.isSame(ByteArray(4))) {
                throw Exception("Null IPv4 address was given")
            }

            val prefix = setting.customPrefix ?: getPrefixLength(setting.currentIp)
            val hostAddress = InetAddress.getByAddress(setting.currentIp)
            val networkAddress = getNetworkAddress(setting.currentIp, prefix)

            builder.addAddress(hostAddress, prefix)
            builder.addRoute(networkAddress, prefix)

            if (!setting.mgDns.isRejected) {
                val dnsAddress = InetAddress.getByAddress(setting.currentDns)
                builder.addDnsServer(dnsAddress)
            }

            if (!setting.isOnlyLan) {
                builder.addRoute("0.0.0.0", 0)
            }
        }

        if (setting.isIpv6Enabled) {
            if (setting.mgIpv6.isRejected) {
                throw Exception("IPv6 NCP was rejected")
            }

            if (setting.currentIpv6.isSame(ByteArray(8))) {
                throw Exception("Null IPv6 address was given")
            }

            val address = ByteArray(16)
            "FE80".toHexByteArray().copyInto(address)
            ByteArray(6).copyInto(address, destinationOffset = 2)
            setting.currentIpv6.copyInto(address, destinationOffset = 8)

            builder.addAddress(InetAddress.getByAddress(address), 64)

            if (!setting.isOnlyLan) {
                builder.addRoute("::", 0)
            }
        }

        builder.setMtu(setting.currentMtu)

        if (Build.VERSION.SDK_INT >= 21) builder.setBlocking(true)

        fd = builder.establish()!!

        ipInput = FileInputStream(fd.fileDescriptor)

        ipOutput = FileOutputStream(fd.fileDescriptor)
    }

    override fun release() {
        if (::fd.isInitialized) fd.close()
    }
}
