package kittoku.osc.client

import kittoku.osc.ControlMessage
import kittoku.osc.Result
import kittoku.osc.SharedBridge
import kittoku.osc.Where
import kittoku.osc.preference.AUTH_PROTOCOL_EAP_MSCHAPv2
import kittoku.osc.preference.AUTH_PROTOCOL_MSCHAPv2
import kittoku.osc.preference.AUTH_PROTOCOl_PAP
import kittoku.osc.unit.sstp.CERT_HASH_PROTOCOL_SHA1
import kittoku.osc.unit.sstp.CERT_HASH_PROTOCOL_SHA256
import kittoku.osc.unit.sstp.ControlPacket
import kittoku.osc.unit.sstp.SSTP_MESSAGE_TYPE_CALL_ABORT
import kittoku.osc.unit.sstp.SSTP_MESSAGE_TYPE_CALL_DISCONNECT
import kittoku.osc.unit.sstp.SSTP_MESSAGE_TYPE_CALL_DISCONNECT_ACK
import kittoku.osc.unit.sstp.SstpCallAbort
import kittoku.osc.unit.sstp.SstpCallConnectAck
import kittoku.osc.unit.sstp.SstpCallConnectNak
import kittoku.osc.unit.sstp.SstpCallConnectRequest
import kittoku.osc.unit.sstp.SstpCallConnected
import kittoku.osc.unit.sstp.SstpCallDisconnect
import kittoku.osc.unit.sstp.SstpCallDisconnectAck
import kittoku.osc.unit.sstp.SstpEchoRequest
import kittoku.osc.unit.sstp.SstpEchoResponse
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.nio.ByteBuffer
import java.nio.charset.Charset
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec


private const val SSTP_REQUEST_INTERVAL = 60_000L
private const val SSTP_REQUEST_COUNT = 3
internal const val SSTP_REQUEST_TIMEOUT = SSTP_REQUEST_INTERVAL * SSTP_REQUEST_COUNT

private class HashSetting(hashProtocol: Byte) {
    val cmacSize: Short // little endian
    val digestProtocol: String
    val macProtocol: String

    init {
        when (hashProtocol) {
            CERT_HASH_PROTOCOL_SHA1 -> {
                cmacSize = 0x1400.toShort()
                digestProtocol = "SHA-1"
                macProtocol = "HmacSHA1"

            }

            CERT_HASH_PROTOCOL_SHA256 -> {
                cmacSize = 0x2000.toShort()
                digestProtocol = "SHA-256"
                macProtocol = "HmacSHA256"
            }

            else -> throw NotImplementedError(hashProtocol.toString())
        }
    }
}

internal class SstpClient(val bridge: SharedBridge) {
    internal val mailbox = Channel<ControlPacket>(Channel.BUFFERED)

    private var jobRequest: Job? = null
    private var jobControl: Job? = null

    internal suspend fun launchJobControl() {
        jobControl = bridge.service.scope.launch(bridge.handler) {
            while (isActive) {
                when (mailbox.receive()) {
                    is SstpEchoRequest -> {
                        SstpEchoResponse().also {
                            bridge.sslTerminal!!.send(it.toByteBuffer())
                        }
                    }

                    is SstpEchoResponse -> { }

                    is SstpCallDisconnect -> {
                        bridge.controlMailbox.send(
                            ControlMessage(Where.SSTP_CONTROL, Result.ERR_DISCONNECT_REQUESTED)
                        )
                    }

                    is SstpCallAbort -> {
                        bridge.controlMailbox.send(
                            ControlMessage(Where.SSTP_CONTROL, Result.ERR_ABORT_REQUESTED)
                        )
                    }

                    else -> {
                        bridge.controlMailbox.send(
                            ControlMessage(Where.SSTP_CONTROL, Result.ERR_UNEXPECTED_MESSAGE)
                        )
                    }

                }
            }

        }
    }

    internal suspend fun launchJobRequest() {
        jobRequest = bridge.service.scope.launch(bridge.handler) {
            val request = SstpCallConnectRequest()
            var requestCount = SSTP_REQUEST_COUNT

            val received: ControlPacket
            while (true) {
                requestCount--
                if (requestCount < 0) {
                    bridge.controlMailbox.send(
                        ControlMessage(Where.SSTP_REQUEST, Result.ERR_COUNT_EXHAUSTED)
                    )

                    return@launch
                }

                bridge.sslTerminal!!.send(request.toByteBuffer())

                received = withTimeoutOrNull(SSTP_REQUEST_INTERVAL) { mailbox.receive() } ?: continue

                break
            }

            when (received) {
                is SstpCallConnectAck -> {
                    bridge.hashProtocol = when (received.request.bitmask.toInt()) {
                        in 2..3 -> CERT_HASH_PROTOCOL_SHA256
                        1 -> CERT_HASH_PROTOCOL_SHA1
                        else -> {
                            bridge.controlMailbox.send(
                                ControlMessage(Where.SSTP_HASH, Result.ERR_UNKNOWN_TYPE)
                            )

                            return@launch
                        }
                    }

                    received.request.nonce.copyInto(bridge.nonce)

                    bridge.controlMailbox.send(
                        ControlMessage(Where.SSTP_REQUEST, Result.PROCEEDED)
                    )
                }

                is SstpCallConnectNak -> {
                    bridge.controlMailbox.send(
                        ControlMessage(Where.SSTP_REQUEST, Result.ERR_NEGATIVE_ACKNOWLEDGED)
                    )
                }

                is SstpCallDisconnect -> {
                    bridge.controlMailbox.send(
                        ControlMessage(Where.SSTP_REQUEST, Result.ERR_DISCONNECT_REQUESTED)
                    )
                }

                is SstpCallAbort -> {
                    bridge.controlMailbox.send(
                        ControlMessage(Where.SSTP_REQUEST, Result.ERR_ABORT_REQUESTED)
                    )
                }

                else -> {
                    bridge.controlMailbox.send(
                        ControlMessage(Where.SSTP_REQUEST, Result.ERR_UNEXPECTED_MESSAGE)
                    )
                }
            }
        }
    }

    internal suspend fun sendCallConnected() {
        val call = SstpCallConnected()

        val cmkInputBuffer = ByteBuffer.allocate(32)
        val cmacInputBuffer = ByteBuffer.allocate(call.length)
        val hashSetting = HashSetting(bridge.hashProtocol)

        bridge.nonce.copyInto(call.binding.nonce)
        MessageDigest.getInstance(hashSetting.digestProtocol).also {
            it.digest(bridge.sslTerminal!!.getServerCertificate()).copyInto(call.binding.certHash)
        }

        call.binding.hashProtocol = bridge.hashProtocol
        call.write(cmacInputBuffer)

        val hlak = when (bridge.currentAuth) {
            AUTH_PROTOCOl_PAP -> ByteArray(32)
            AUTH_PROTOCOL_MSCHAPv2, AUTH_PROTOCOL_EAP_MSCHAPv2 -> bridge.hlak!!
            else -> throw NotImplementedError(bridge.currentAuth)
        }

        val cmkSeed = "SSTP inner method derived CMK".toByteArray(Charset.forName("US-ASCII"))
        cmkInputBuffer.put(cmkSeed)
        cmkInputBuffer.putShort(hashSetting.cmacSize)
        cmkInputBuffer.put(1)

        Mac.getInstance(hashSetting.macProtocol).also {
            it.init(SecretKeySpec(hlak, hashSetting.macProtocol))
            val cmk = it.doFinal(cmkInputBuffer.array())
            it.init(SecretKeySpec(cmk, hashSetting.macProtocol))
            val cmac = it.doFinal(cmacInputBuffer.array())
            cmac.copyInto(call.binding.compoundMac)
        }

        bridge.sslTerminal!!.send(call.toByteBuffer())
    }

    internal suspend fun sendLastPacket(type: Short) {
        val packet = when (type) {
            SSTP_MESSAGE_TYPE_CALL_DISCONNECT -> SstpCallDisconnect()
            SSTP_MESSAGE_TYPE_CALL_DISCONNECT_ACK -> SstpCallDisconnectAck()
            SSTP_MESSAGE_TYPE_CALL_ABORT -> SstpCallAbort()

            else -> throw NotImplementedError(type.toString())
        }

        try { // maybe the socket is no longer available
            bridge.sslTerminal!!.send(packet.toByteBuffer())
        } catch (_: Throwable) { }
    }

    internal fun cancel() {
        jobRequest?.cancel()
        jobControl?.cancel()
        mailbox.close()
    }
}
