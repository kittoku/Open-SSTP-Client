package kittoku.opensstpclient.misc

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import java.nio.ByteBuffer
import kotlin.coroutines.CoroutineContext


internal abstract class AbstractClient(protected val lowerBridge: LayerBridge, protected val higherBridge: LayerBridge,
                                       protected val networkSetting: NetworkSetting, protected val status: DualClientStatus,
                                       bufferSize: Int) : CoroutineScope {
    // Abstract class inherited to PPP and SSTP layers.
    val job = Job()
    protected val incomingBuffer: ByteBuffer = ByteBuffer.allocate(bufferSize)
    protected val outgoingBuffer: ByteBuffer = ByteBuffer.allocate(bufferSize)
    protected val controlBuffer: ByteBuffer = ByteBuffer.allocate(bufferSize)

    override val coroutineContext: CoroutineContext
        get() = Dispatchers.Default + job

    protected abstract fun runOutgoing() // process data from the higher layer and send them to the lower layer

    internal abstract suspend fun run()
}

internal abstract class AbstractTerminal(protected val bridge: LayerBridge, protected val networkSetting: NetworkSetting,
                                         bufferSize: Int) : CoroutineScope {
    // Abstract class inherited to SSL and IP layers.
    val job = Job()
    protected val incomingBuffer: ByteBuffer = ByteBuffer.allocate(bufferSize)
    protected val outgoingBuffer: ByteBuffer = ByteBuffer.allocate(bufferSize)

    override val coroutineContext: CoroutineContext
        get() = Dispatchers.Default + job

    protected abstract fun runOutgoing()

    internal abstract suspend fun run()

    internal abstract fun release() // release socket or file descriptor
}