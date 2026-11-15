package kittoku.osc

import android.os.SystemClock
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.security.SecureRandom

/**
 * The "ping" for L2TP/IPsec. SSTP is tested with a TCP connection to the server's port, but L2TP does
 * not use that port at all: it talks IKE on UDP 500. This sends only the first IKEv1 Main Mode message
 * (no key is exchanged) and times the answer. Any answer, an accepted proposal or a refusal, means the
 * server speaks IKE and the network lets it through.
 */
internal object IkeProbe {
    private const val PORT = 500
    private const val TRIES = 2
    private const val TRY_TIMEOUT_MS = 1600

    /** Milliseconds until the first IKE answer, or [ServerTester.FAILED]. Blocks, so call it off the main thread. */
    fun test(host: String): Int {
        return try {
            val address = InetAddress.getByName(host)
            val cookie = ByteArray(8).also { SecureRandom().nextBytes(it) }
            val request = buildMainModeMessage1(cookie)

            DatagramSocket().use { socket ->
                socket.soTimeout = TRY_TIMEOUT_MS
                socket.connect(address, PORT)

                val buffer = ByteArray(2048)

                repeat(TRIES) {
                    val startedAt = SystemClock.elapsedRealtime()
                    socket.send(DatagramPacket(request, request.size))

                    while (true) {
                        val reply = DatagramPacket(buffer, buffer.size)

                        try {
                            socket.receive(reply)
                        } catch (_: SocketTimeoutException) {
                            break // send again
                        }

                        // An ISAKMP header that echoes our initiator cookie.
                        if (reply.length >= 28 && (0 until 8).all { buffer[it] == cookie[it] }) {
                            return (SystemClock.elapsedRealtime() - startedAt).toInt().coerceAtLeast(1)
                        }
                    }
                }
            }

            ServerTester.FAILED
        } catch (_: Exception) {
            ServerTester.FAILED
        }
    }

    // ---- message building (RFC 2408 / 2409) -----------------------------------------------------

    private fun u16(out: ByteArrayOutputStream, value: Int) {
        out.write((value shr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun u32(out: ByteArrayOutputStream, value: Int) {
        u16(out, value ushr 16)
        u16(out, value and 0xFFFF)
    }

    // Basic (type/value) attribute: the top bit of the type is set.
    private fun attribute(out: ByteArrayOutputStream, type: Int, value: Int) {
        u16(out, 0x8000 or type)
        u16(out, value)
    }

    private fun transform(number: Int, encryption: Int, keyLength: Int?, hash: Int, group: Int, last: Boolean): ByteArray {
        val attributes = ByteArrayOutputStream()
        attribute(attributes, 1, encryption)
        if (keyLength != null) attribute(attributes, 14, keyLength)
        attribute(attributes, 2, hash)
        attribute(attributes, 4, group)
        attribute(attributes, 3, 1)       // pre-shared key
        attribute(attributes, 11, 1)      // life type: seconds
        attribute(attributes, 12, 28800)  // life duration

        val out = ByteArrayOutputStream()
        out.write(if (last) 0 else 3)
        out.write(0)
        u16(out, 8 + attributes.size())
        out.write(number)
        out.write(1) // KEY_IKE
        u16(out, 0)
        out.write(attributes.toByteArray())
        return out.toByteArray()
    }

    private fun buildMainModeMessage1(initiatorCookie: ByteArray): ByteArray {
        // The three algorithm sets the tunnel itself tries, so a server that answers here can be offered the same.
        val transforms = ByteArrayOutputStream().apply {
            write(transform(1, encryption = 7, keyLength = 256, hash = 2, group = 2, last = false))   // AES-256, SHA1, MODP-1024
            write(transform(2, encryption = 5, keyLength = null, hash = 2, group = 2, last = false))  // 3DES, SHA1, MODP-1024
            write(transform(3, encryption = 7, keyLength = 256, hash = 4, group = 14, last = true))   // AES-256, SHA-256, MODP-2048
        }.toByteArray()

        val proposal = ByteArrayOutputStream().apply {
            write(0)                  // last proposal
            write(0)
            u16(this, 8 + transforms.size)
            write(1)                  // proposal number
            write(1)                  // protocol: ISAKMP
            write(0)                  // SPI size
            write(3)                  // transforms
            write(transforms)
        }.toByteArray()

        val sa = ByteArrayOutputStream().apply {
            write(0)                  // no payload after the SA
            write(0)
            u16(this, 4 + 8 + proposal.size)
            u32(this, 1)              // DOI: IPsec
            u32(this, 1)              // situation: identity only
            write(proposal)
        }.toByteArray()

        return ByteArrayOutputStream().apply {
            write(initiatorCookie)
            write(ByteArray(8))       // responder cookie: none yet
            write(1)                  // first payload: SA
            write(0x10)               // IKEv1
            write(2)                  // Main Mode (identity protection)
            write(0)                  // flags
            u32(this, 0)              // message id
            u32(this, 28 + sa.size)   // total length
            write(sa)
        }.toByteArray()
    }
}
