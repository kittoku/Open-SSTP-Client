package kittoku.osc.activity

import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.preference.PreferenceManager
import kittoku.osc.QrShare
import kittoku.osc.R
import kittoku.osc.SharedServer
import kittoku.osc.flagEmoji
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getIntPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue


/** Shows the current server as a scrambled QR code that the Banafsh app on another phone can read. */
class QrSendActivity : AppCompatActivity() {
    override fun attachBaseContext(newBase: android.content.Context) {
        super.attachBaseContext(kittoku.osc.LocaleFix.wrap(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_qr_send)

        val root = findViewById<View>(R.id.qrRoot)
        WindowCompat.getInsetsController(window, root).isAppearanceLightStatusBars = true
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }

        findViewById<View>(R.id.btnBack).setOnClickListener { finish() }

        val prefs = PreferenceManager.getDefaultSharedPreferences(this)
        val host = getStringPrefValue(OscPrefKey.HOME_HOSTNAME, prefs)

        if (host.isEmpty()) {
            Toast.makeText(this, R.string.bs_qr_no_server, Toast.LENGTH_LONG).show()
            finish()
            return
        }

        val port = getIntPrefValue(OscPrefKey.SSL_PORT, prefs)
        val ui = getSharedPreferences("banafsh_ui", MODE_PRIVATE)
        val countryCode = if (ui.getString("server_host", "") == host) {
            ui.getString("server_country", "").orEmpty()
        } else ""

        val payload = QrShare.encode(
            SharedServer(
                host = host,
                port = port,
                user = getStringPrefValue(OscPrefKey.HOME_USERNAME, prefs),
                pass = getStringPrefValue(OscPrefKey.HOME_PASSWORD, prefs),
                countryCode = countryCode,
                verify = getBooleanPrefValue(OscPrefKey.SSL_DO_VERIFY, prefs)
            )
        )

        findViewById<ImageView>(R.id.ivQr).setImageBitmap(
            QrShare.makeBitmap(payload, 720, 0xFF2A1D4A.toInt(), Color.WHITE)
        )

        findViewById<TextView>(R.id.tvServer).text = "${flagEmoji(countryCode)} $host:$port".trim()

        // A brighter screen makes the QR easier to scan.
        window.attributes = window.attributes.also { it.screenBrightness = 1f }
    }
}
