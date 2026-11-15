package kittoku.osc.activity

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Outline
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.Settings
import android.view.View
import android.view.ViewOutlineProvider
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.ResultPoint
import com.journeyapps.barcodescanner.BarcodeCallback
import com.journeyapps.barcodescanner.BarcodeResult
import com.journeyapps.barcodescanner.BarcodeView
import com.journeyapps.barcodescanner.DefaultDecoderFactory
import kittoku.osc.QrShare
import kittoku.osc.R


/** Explains why the camera is needed, then scans the QR code of a server sent by another Banafsh app. */
class QrScanActivity : AppCompatActivity() {
    override fun attachBaseContext(newBase: android.content.Context) {
        super.attachBaseContext(kittoku.osc.LocaleFix.wrap(newBase))
    }

    companion object {
        const val EXTRA_HOST = "qr_host"
        const val EXTRA_PORT = "qr_port"
        const val EXTRA_USER = "qr_user"
        const val EXTRA_PASS = "qr_pass"
        const val EXTRA_COUNTRY = "qr_country"
        const val EXTRA_VERIFY = "qr_verify"
    }

    private lateinit var barcodeView: BarcodeView
    private lateinit var paneExplain: View
    private lateinit var paneScan: View
    private lateinit var tvScanStatus: TextView
    private lateinit var tvPermBody: TextView
    private lateinit var btnPermContinue: TextView

    private val handler = Handler(Looper.getMainLooper())
    private var openSettingsMode = false
    private var lastText: String? = null
    private var lastTime = 0L
    private var finished = false

    private val permissionLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) {
            showScanner()
        } else {
            showExplain(denied = true)
        }
    }

    private val callback = object : BarcodeCallback {
        override fun barcodeResult(result: BarcodeResult?) {
            val text = result?.text ?: return
            val now = SystemClock.elapsedRealtime()

            if (finished) return
            if (text == lastText && now - lastTime < 2500) return

            lastText = text
            lastTime = now

            val server = QrShare.decode(text)

            if (server == null) {
                showInvalid()
                return
            }

            finished = true
            barcodeView.pause()

            setResult(
                RESULT_OK,
                Intent()
                    .putExtra(EXTRA_HOST, server.host)
                    .putExtra(EXTRA_PORT, server.port)
                    .putExtra(EXTRA_USER, server.user)
                    .putExtra(EXTRA_PASS, server.pass)
                    .putExtra(EXTRA_COUNTRY, server.countryCode)
                    .putExtra(EXTRA_VERIFY, server.verify)
            )
            finish()
        }

        override fun possibleResultPoints(resultPoints: MutableList<ResultPoint>?) {}
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_qr_scan)

        val root = findViewById<View>(R.id.qrRoot)
        WindowCompat.getInsetsController(window, root).isAppearanceLightStatusBars = true
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }

        paneExplain = findViewById(R.id.paneExplain)
        paneScan = findViewById(R.id.paneScan)
        tvScanStatus = findViewById(R.id.tvScanStatus)
        tvPermBody = findViewById(R.id.tvPermBody)
        btnPermContinue = findViewById(R.id.btnPermContinue)
        barcodeView = findViewById(R.id.barcodeView)

        barcodeView.decoderFactory = DefaultDecoderFactory(listOf(BarcodeFormat.QR_CODE))

        // Rounded corners for the camera preview.
        findViewById<View>(R.id.cameraFrame).apply {
            outlineProvider = object : ViewOutlineProvider() {
                override fun getOutline(view: View, outline: Outline) {
                    outline.setRoundRect(0, 0, view.width, view.height, 28 * resources.displayMetrics.density)
                }
            }
            clipToOutline = true
        }

        findViewById<View>(R.id.btnBack).setOnClickListener { finish() }
        findViewById<View>(R.id.btnPermLater).setOnClickListener { finish() }

        btnPermContinue.setOnClickListener {
            if (openSettingsMode) {
                startActivity(
                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", packageName, null))
                )
            } else {
                permissionLauncher.launch(Manifest.permission.CAMERA)
            }
        }
    }

    private fun hasCameraPermission(): Boolean {
        return ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
    }

    override fun onResume() {
        super.onResume()

        if (hasCameraPermission()) {
            showScanner()
        }
    }

    override fun onPause() {
        barcodeView.pause()
        super.onPause()
    }

    private fun showExplain(denied: Boolean) {
        barcodeView.pause()
        paneScan.visibility = View.GONE
        paneExplain.visibility = View.VISIBLE

        if (denied) {
            openSettingsMode = !shouldShowRequestPermissionRationale(Manifest.permission.CAMERA)
            tvPermBody.setText(R.string.bs_qr_perm_denied)
            btnPermContinue.setText(if (openSettingsMode) R.string.bs_qr_open_settings else R.string.bs_qr_perm_continue)
        }
    }

    private fun showScanner() {
        paneExplain.visibility = View.GONE
        paneScan.visibility = View.VISIBLE

        barcodeView.decodeContinuous(callback)
        barcodeView.resume()
    }

    private fun showInvalid() {
        tvScanStatus.setText(R.string.bs_qr_invalid)
        tvScanStatus.setTextColor(ContextCompat.getColor(this, R.color.qr_error))

        handler.removeCallbacksAndMessages(null)
        handler.postDelayed({
            tvScanStatus.setText(R.string.bs_qr_searching)
            tvScanStatus.setTextColor(ContextCompat.getColor(this, R.color.qr_accent_soft))
        }, 2500)
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }
}
