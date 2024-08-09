package kittoku.osc.client.ppp.auth

import kittoku.osc.SharedBridge
import kittoku.osc.cipher.hashMd4
import kittoku.osc.extension.sum
import kittoku.osc.extension.toHexByteArray
import kittoku.osc.extension.toHexString
import kittoku.osc.unit.ppp.auth.ChapMessageField
import kittoku.osc.unit.ppp.auth.ChapValueNameFiled
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec


internal class MSCHAPV2Client(private val bridge: SharedBridge) {
    private val serverChallenge = ByteArray(16)
    private val clientChallenge = ByteArray(16)
    private val serverResponse = ByteArray(42)
    private val clientResponse = ByteArray(24)

    internal fun processChallenge(challenge: ChapValueNameFiled): ChapValueNameFiled {
        challenge.value.copyInto(serverChallenge)

        prepareClientResponse()

        return ChapValueNameFiled().also {
            it.name = bridge.HOME_USERNAME.toByteArray(Charsets.US_ASCII)
            it.value = ByteArray(49)
            clientChallenge.copyInto(it.value)
            clientResponse.copyInto(it.value, destinationOffset = 24)
        }
    }

    internal fun verifyAuthenticator(success: ChapMessageField): Boolean {
        if (success.message.size < serverResponse.size) {
            return false
        }

        success.message.copyInto(serverResponse, endIndex = serverResponse.size)

        return checkServerResponse()
    }

    private fun isEvenBits(value: Int): Boolean {
        // only count the bits of the least significant byte
        var count = 0
        var holder = value
        repeat(8) {
            count += (holder and 1)
            holder = holder.shr(1)
        }

        return count % 2 == 0
    }

    private fun addParity(bytes: ByteArray): ByteArray {
        val buffer = ByteBuffer.allocate(8)
        buffer.position(1)
        buffer.put(bytes)
        buffer.clear()
        var holder = buffer.getLong(0)
        val mask = 0b0111_1111L

        repeat(8) {
            var b = (holder and mask).toInt()
            b = b.shl(1) + if (isEvenBits(b)) 1 else 0
            buffer.put(7 - it, b.toByte())
            holder = holder.shr(7)
        }

        return buffer.array()
    }

    private fun prepareClientResponse() {
        SecureRandom().nextBytes(clientChallenge)

        val userArray = bridge.HOME_USERNAME.toByteArray(Charsets.US_ASCII)
        val passArray = bridge.HOME_PASSWORD.toByteArray(Charsets.UTF_16LE)

        val challenge = MessageDigest.getInstance("SHA-1").let {
            it.update(clientChallenge)
            it.update(serverChallenge)
            it.update(userArray)
            it.digest().sliceArray(0 until 8)
        }

        val zeroPassHash = ByteArray(21)
        hashMd4(passArray).copyInto(zeroPassHash)

        Cipher.getInstance("DES/ECB/NoPadding").also {
            repeat(3) { i ->
                it.init(
                    Cipher.ENCRYPT_MODE,
                    SecretKeySpec(
                        addParity(zeroPassHash.sliceArray(i * 7 until (i + 1) * 7)),
                        "DES"
                    )
                )

                it.doFinal(challenge).copyInto(clientResponse, i * 8)
            }
        }
    }

    private fun checkServerResponse(): Boolean {
        val userArray = bridge.HOME_USERNAME.toByteArray(Charsets.US_ASCII)
        val passArray = bridge.HOME_PASSWORD.toByteArray(Charsets.UTF_16LE)

        val magic1 = sum(
            "4D616769632073657276657220746F20",
            "636C69656E74207369676E696E672063",
            "6F6E7374616E74"
        ).toHexByteArray()

        val magic2 = sum(
            "50616420746F206D616B652069742064",
            "6F206D6F7265207468616E206F6E6520",
            "697465726174696F6E"
        ).toHexByteArray()

        val challenge = MessageDigest.getInstance("SHA-1").let {
            it.update(clientChallenge)
            it.update(serverChallenge)
            it.update(userArray)
            it.digest().sliceArray(0 until 8)
        }

        val digest = MessageDigest.getInstance("SHA-1").let {
            it.update(hashMd4(hashMd4(passArray)))
            it.update(clientResponse)
            it.update(magic1)
            val tempDigest = it.digest()

            it.reset()
            it.update(tempDigest)
            it.update(challenge)
            it.update(magic2)
            it.digest()
        }

        val expected = "S=${digest.toHexString()}".toByteArray(Charsets.US_ASCII)

        return expected.contentEquals(serverResponse)
    }

    internal fun prepareHlak() {
        val passArray = bridge.HOME_PASSWORD.toByteArray(Charsets.UTF_16LE)

        val magic1 = sum(
            "5468697320697320746865204D505045",
            "204D6173746572204B6579"
        ).toHexByteArray()

        val magic2 = sum(
            "4F6E2074686520636C69656E74207369",
            "64652C20746869732069732074686520",
            "73656E64206B65793B206F6E20746865",
            "2073657276657220736964652C206974",
            "20697320746865207265636569766520",
            "6B65792E"
        ).toHexByteArray()

        val magic3 = sum(
            "4F6E2074686520636C69656E74207369",
            "64652C20746869732069732074686520",
            "72656365697665206B65793B206F6E20",
            "7468652073657276657220736964652C",
            "206974206973207468652073656E6420",
            "6B65792E"
        ).toHexByteArray()

        val pad1 = sum(
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "0000000000000000"
        ).toHexByteArray()

        val pad2 = sum(
            "F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2",
            "F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2",
            "F2F2F2F2F2F2F2F2"
        ).toHexByteArray()

        bridge.hlak = MessageDigest.getInstance("SHA-1").let {
            it.update(hashMd4(hashMd4(passArray)))
            it.update(clientResponse)
            it.update(magic1)
            val masterKey = it.digest().sliceArray(0 until 16)

            val hlak = ByteArray(32)
            it.reset()
            it.update(masterKey)
            it.update(pad1)
            it.update(magic2)
            it.update(pad2)
            it.digest().copyInto(hlak, endIndex = 16)

            it.reset()
            it.update(masterKey)
            it.update(pad1)
            it.update(magic3)
            it.update(pad2)
            it.digest().copyInto(hlak, 16, endIndex = 16)

            hlak
        }
    }
}
