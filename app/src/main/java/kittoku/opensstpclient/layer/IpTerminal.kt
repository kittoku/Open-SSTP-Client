package kittoku.opensstpclient.layer

import android.os.ParcelFileDescriptor
import kittoku.opensstpclient.ControlClient
import kittoku.opensstpclient.misc.SuicideException
import kittoku.opensstpclient.misc.isSame
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
        parent.networkSetting.ipAddress.address.also {
            if (it.isSame(ByteArray(4))) throw SuicideException()

            parent.builder.addAddress(InetAddress.getByAddress(it), getPrefixLength(it))
        }

        parent.networkSetting.dnsAddress.also {
            if (it.address.isSame(ByteArray(4))) return

            parent.builder.addDnsServer(InetAddress.getByAddress(it.address))
        }

        parent.builder.setMtu(parent.networkSetting.mru.unitSize.toInt())

        parent.builder.addRoute("0.0.0.0", 0)

        fd = parent.builder.establish()

        ipInput = FileInputStream(fd.fileDescriptor)

        ipOutput = FileOutputStream(fd.fileDescriptor)
    }

    override fun release() {
        if (::fd.isInitialized) fd.close()
    }
}
