package kittoku.osc

import android.graphics.Bitmap
import android.graphics.Color
import android.util.Base64
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec


internal data class SharedServer(
    val host: String,
    val port: Int,
    val user: String,
    val pass: String,
    val countryCode: String,
    val verify: Boolean
)

/**
 * Turns a server into a scrambled text for a QR code and back.
 * A normal camera app only sees meaningless characters, and anything that was not made by Banafsh
 * (or was changed) fails to decrypt and is rejected.
 */
internal object QrShare {
    private const val SECRET = "Banafsh-sstp/qr/v1/7f3a9c1e5b"
    private val AAD = "BNF1".toByteArray(Charsets.UTF_8)
    private const val IV_SIZE = 12

    private val key: SecretKeySpec by lazy {
        SecretKeySpec(MessageDigest.getInstance("SHA-256").digest(SECRET.toByteArray(Charsets.UTF_8)), "AES")
    }

    private val hostRegex = Regex("^[A-Za-z0-9.:_\\-\\[\\]]{1,253}$")

    fun encode(server: SharedServer): String {
        val json = JSONObject().apply {
            put("h", server.host)
            put("p", server.port)
            put("u", server.user)
            put("w", server.pass)
            put("c", server.countryCode)
            put("v", if (server.verify) 1 else 0)
        }

        val iv = ByteArray(IV_SIZE).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        cipher.updateAAD(AAD)
        val encrypted = cipher.doFinal(json.toString().toByteArray(Charsets.UTF_8))

        return Base64.encodeToString(iv + encrypted, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    fun decode(text: String): SharedServer? {
        return try {
            val raw = Base64.decode(text.trim(), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            if (raw.size <= IV_SIZE + 16) return null

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, raw.copyOfRange(0, IV_SIZE)))
            cipher.updateAAD(AAD)
            val plain = cipher.doFinal(raw, IV_SIZE, raw.size - IV_SIZE)

            val json = JSONObject(String(plain, Charsets.UTF_8))
            val server = SharedServer(
                host = json.getString("h"),
                port = json.getInt("p"),
                user = json.optString("u"),
                pass = json.optString("w"),
                countryCode = json.optString("c"),
                verify = json.optInt("v", 1) != 0
            )

            val isValid = hostRegex.matches(server.host) &&
                    server.port in 1..65535 &&
                    server.user.length <= 128 &&
                    server.pass.length <= 128 &&
                    (server.countryCode.isEmpty() || server.countryCode.length == 2)

            if (isValid) server else null
        } catch (e: Exception) {
            null
        }
    }

    fun makeBitmap(text: String, size: Int, dark: Int, light: Int): Bitmap {
        val hints = mapOf(
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
            EncodeHintType.MARGIN to 0
        )

        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, hints)
        val pixels = IntArray(size * size)

        for (y in 0 until size) {
            for (x in 0 until size) {
                pixels[y * size + x] = if (matrix.get(x, y)) dark else light
            }
        }

        return Bitmap.createBitmap(pixels, size, size, Bitmap.Config.ARGB_8888)
    }
}
