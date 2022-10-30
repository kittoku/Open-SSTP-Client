package kittoku.osc.client

import kittoku.osc.unit.ppp.PPP_HEADER
import kittoku.osc.unit.ppp.PPP_PROTOCOL_IP
import kittoku.osc.unit.ppp.PPP_PROTOCOL_IPv6
import kittoku.osc.unit.sstp.SSTP_PACKET_TYPE_DATA
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.nio.ByteBuffer


private const val PREFIX_SIZE = 8

private const val IPv4_HEADER: Int = (0x4).shl(28)
private const val IPv6_HEADER: Int = (0x6).shl(28)
private const val IP_VERSION_MASK: Int = (0xF).shl(28)

internal class OutgoingClient(private val bridge: ClientBridge) {
    private var jobMain: Job? = null
    private var jobRetrieve: Job? = null

    private val mainBuffer = ByteBuffer.allocate(bridge.sslTerminal!!.getApplicationBufferSize())
    private val channel = Channel<ByteBuffer>(0)

    internal fun launchJobMain() {
        jobMain = bridge.service.scope.launch(bridge.handler) {
            bridge.attachIPTerminal()
            if (!bridge.ipTerminal!!.initializeTun()) return@launch

            launchJobRetrieve()

            val minCapacity = PREFIX_SIZE + bridge.PPP_MTU

            while (isActive) {
                mainBuffer.clear()

                if (!load(channel.receive())) continue

                while (isActive) {
                    channel.tryReceive().getOrNull()?.also {
                        load(it)
                    } ?: break

                    if (mainBuffer.remaining() < minCapacity) break
                }

                mainBuffer.flip()
                bridge.sslTerminal!!.send(mainBuffer)
            }
        }
    }

    private fun launchJobRetrieve() {
        jobRetrieve = bridge.service.scope.launch(bridge.handler) {
            val bufferAlpha = ByteBuffer.allocate(bridge.PPP_MTU)
            val bufferBeta = ByteBuffer.allocate(bridge.PPP_MTU)
            var isBlockingAlpha = true

            while (isActive) {
                isBlockingAlpha = if (isBlockingAlpha) {
                    bridge.ipTerminal!!.readPacket(bufferAlpha)
                    channel.send(bufferAlpha)
                    false
                } else {
                    bridge.ipTerminal!!.readPacket(bufferBeta)
                    channel.send(bufferBeta)
                    true
                }
            }
        }
    }

    private suspend fun load(packet: ByteBuffer): Boolean { // true if data protocol is enabled
        val header = packet.getInt(0)
        val protocol = when (header and IP_VERSION_MASK) {
            IPv4_HEADER -> {
                if (!bridge.PPP_IPv4_ENABLED) return false

                PPP_PROTOCOL_IP
            }

            IPv6_HEADER -> {
                if (!bridge.PPP_IPv6_ENABLED) return false

                PPP_PROTOCOL_IPv6
            }

            else -> {
                bridge.controlMailbox.send(ControlMessage(Where.OUTGOING, Result.ERR_UNKNOWN_TYPE))

                return false
            }
        }

        mainBuffer.putShort(SSTP_PACKET_TYPE_DATA)
        mainBuffer.putShort((packet.remaining() + PREFIX_SIZE).toShort())
        mainBuffer.putShort(PPP_HEADER)
        mainBuffer.putShort(protocol)
        mainBuffer.put(packet)

        return true
    }

    internal fun cancel() {
        jobMain?.cancel()
        jobRetrieve?.cancel()
        channel.close()
    }
}
