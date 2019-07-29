package kittoku.opensstpclient.packet

import android.net.VpnService
import android.os.ParcelFileDescriptor
import kittoku.opensstpclient.BUFFER_SIZE_IP
import kittoku.opensstpclient.POLLING_TIME_STREAM_READ
import kittoku.opensstpclient.misc.AbstractTerminal
import kittoku.opensstpclient.misc.LayerBridge
import kittoku.opensstpclient.misc.NetworkSetting
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream

internal class IpClient(val  builder: VpnService.Builder, bridge: LayerBridge, networkSetting: NetworkSetting)
    : AbstractTerminal(bridge, networkSetting, BUFFER_SIZE_IP) {
    private val readUnitFromPpp = bridge::readUnitFromLower
    private val writeUnitToPpp = bridge::writeUnitToLower
    private lateinit var fd: ParcelFileDescriptor

    fun initializeTun() {
        networkSetting.ipAdress?.apply { builder.addAddress(this, 16) }

        networkSetting.primaryDns?.apply { builder.addDnsServer(this) }

        networkSetting.mru?.apply { builder.setMtu(this.toInt()) }

        builder.addRoute("0.0.0.0", 0)

        fd = builder.establish()
    }

    override fun runOutgoing() {
        launch {
            val inputStream = FileInputStream(fd.fileDescriptor)
            var readSize: Int
            while (true) {
                outgoingBuffer.clear()
                while (true) {
                    readSize = inputStream.read(outgoingBuffer.array())
                    if (readSize > 0) break
                    else delay(POLLING_TIME_STREAM_READ)
                }
                outgoingBuffer.limit(readSize)
                writeUnitToPpp(outgoingBuffer)
            }
        }
    }

    override suspend fun run() {
        while (!networkSetting.isNegotiated) delay(100L)

        initializeTun()
        runOutgoing()

        val outputStream = FileOutputStream(fd.fileDescriptor)
        while (true) {
            incomingBuffer.clear()
            readUnitFromPpp(incomingBuffer)
            outputStream.write(incomingBuffer.array(), 0, incomingBuffer.limit())
            outputStream.flush()
        }
    }

    override fun release() {
        if (::fd.isInitialized) fd.close()
    }
}