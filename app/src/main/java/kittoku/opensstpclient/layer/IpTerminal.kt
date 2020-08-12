package kittoku.opensstpclient.layer

import android.os.Build
import android.os.ParcelFileDescriptor
import kittoku.opensstpclient.ControlClient
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

        builder.addAddress(
            InetAddress.getByAddress(setting.currentIp),
            setting.customPrefix ?: getPrefixLength(setting.currentIp)
        )

        if (!setting.mgDns.isRejected) {
            builder.addDnsServer(InetAddress.getByAddress(setting.currentDns))
        }

        builder.setMtu(setting.currentMtu)

        builder.addRoute("0.0.0.0", 0)

        if (Build.VERSION.SDK_INT >= 21) builder.setBlocking(true)

        fd = builder.establish()!!

        ipInput = FileInputStream(fd.fileDescriptor)

        ipOutput = FileOutputStream(fd.fileDescriptor)
    }

    override fun release() {
        if (::fd.isInitialized) fd.close()
    }
}
