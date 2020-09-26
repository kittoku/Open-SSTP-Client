package kittoku.opensstpclient.layer

import android.os.Build
import android.os.ParcelFileDescriptor
import kittoku.opensstpclient.ControlClient
import kittoku.opensstpclient.misc.isSame
import kittoku.opensstpclient.misc.toHexByteArray
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress


internal class IpTerminal(parent: ControlClient) : Terminal(parent) {
    private lateinit var fd: ParcelFileDescriptor

    internal lateinit var ipInput: FileInputStream

    internal lateinit var ipOutput: FileOutputStream

    private fun getPrefixLength(array: ByteArray): Int {
        if (array[0] == 10.toByte()) return 8

        if (array[0] == 172.toByte() && array[1] in 16..31) return 20

        return 16
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

            builder.addAddress(
                InetAddress.getByAddress(setting.currentIp),
                setting.customPrefix ?: getPrefixLength(setting.currentIp)
            )

            if (!setting.mgDns.isRejected) {
                builder.addDnsServer(InetAddress.getByAddress(setting.currentDns))
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
            ByteArray(6).copyInto(address, startIndex = 2)
            setting.currentIpv6.copyInto(address, startIndex = 6)

            builder.addAddress(InetAddress.getByAddress(address), 64)
        }

        builder.setMtu(setting.currentMtu)

        if (!setting.isOnlyLan) {
            builder.addRoute("0.0.0.0", 0)
        }

        if (Build.VERSION.SDK_INT >= 21) builder.setBlocking(true)

        fd = builder.establish()!!

        ipInput = FileInputStream(fd.fileDescriptor)

        ipOutput = FileOutputStream(fd.fileDescriptor)
    }

    override fun release() {
        if (::fd.isInitialized) fd.close()
    }
}
