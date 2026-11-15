package kittoku.osc.activity

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.drawable.GradientDrawable
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.MenuItem
import androidx.activity.OnBackPressedCallback
import android.view.View
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.preference.PreferenceManager
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import kittoku.osc.R
import kittoku.osc.preference.accessor.getStringPrefValue
import kittoku.osc.IkeProbe
import kittoku.osc.Protocol
import kittoku.osc.ProtocolSwitch
import kittoku.osc.ServerTester
import kittoku.osc.flagEmoji
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getBooleanPrefValue
import org.json.JSONArray
import java.net.HttpURLConnection
import java.net.URL
import java.util.Locale
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

internal data class FreeServer(
    val host: String,
    val port: Int,
    val country: String,
    val countryCode: String,
    val speedMbps: Double,
    val ping: Int,
    val sessions: Int = 0,
    val udpPort: Int = 0,
)

private val EXCLUDED_COUNTRIES = setOf("RU")

private enum class Quality { GOOD, MEDIUM, BAD, UNKNOWN }

// Share of the announced server speed that each user gets (Mbps per session).
private const val GOOD_SHARE = 8.0
private const val MEDIUM_SHARE = 3.0

private fun shareOf(server: FreeServer): Double = server.speedMbps / (server.sessions + 1)

// Order of the tiers in the list: good first, then medium, then unknown, bad last.
private fun qualityRank(server: FreeServer): Int = when (qualityOf(server)) {
    Quality.GOOD -> 0
    Quality.MEDIUM -> 1
    Quality.UNKNOWN -> 2
    Quality.BAD -> 3
}

// A server with 0 or 1 session may simply be new, or one nobody can use: no verdict for it.
private fun qualityOf(server: FreeServer): Quality = when {
    server.sessions <= 1 -> Quality.UNKNOWN
    shareOf(server) >= GOOD_SHARE -> Quality.GOOD
    shareOf(server) >= MEDIUM_SHARE -> Quality.MEDIUM
    else -> Quality.BAD
}

private const val PENDING = -2

// A country can have hundreds of servers: only the best ones are drawn at first.
private const val ROWS_LIMIT = 50

private val IP_REGEX = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")

/**
 * The "free servers" page: downloads the list, shows the countries; a country opens its servers,
 * which are tested from the user's own network and shown with ping and a quality label.
 */
class ServerListActivity : AppCompatActivity() {
    override fun attachBaseContext(newBase: android.content.Context) {
        super.attachBaseContext(kittoku.osc.LocaleFix.wrap(newBase))
    }

    companion object {
        const val EXTRA_HOST = "host"
        const val EXTRA_PORT = "port"
        const val EXTRA_COUNTRY_CODE = "country_code"
        const val EXTRA_PING = "ping"
    }

    private var servers: List<FreeServer> = emptyList()
    private var results = IntArray(0)
    private var currentCountry: String? = null   // null: the country list is shown
    private var visible: List<Int> = emptyList() // indices of the servers of the open country
    private var showAll = false
    private var renderPending = false
    private var finished = 0
    private var testing = false
    private var vpnOn = false
    private var generation = 0
    private var executor: ExecutorService? = null
    private val handler = Handler(Looper.getMainLooper())

    private lateinit var tvNote: TextView
    private lateinit var tvHint: TextView
    private lateinit var btnTestAll: MaterialButton
    private lateinit var progress: ProgressBar
    private lateinit var list: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        setTheme(R.style.Theme_OpenSSTPClient_NoActionBar)
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_server_list)

        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        title = getString(R.string.bs_servers_title)

        WindowCompat.getInsetsController(window, toolbar).isAppearanceLightStatusBars = true
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.body)) { view, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            view.setPadding(bars.left, 0, bars.right, bars.bottom)
            insets
        }

        tvNote = findViewById(R.id.tvTestNote)
        tvHint = findViewById(R.id.tvHint)
        btnTestAll = findViewById(R.id.btnTestAll)
        progress = findViewById(R.id.progress)
        list = findViewById(R.id.listServers)

        btnTestAll.setOnClickListener { startTest() }
        btnTestAll.setText(R.string.bs_test_again)
        btnTestAll.visibility = View.GONE

        // Back from a country returns to the country list first.
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (currentCountry != null) {
                    showCountries()
                } else {
                    isEnabled = false
                    onBackPressedDispatcher.onBackPressed()
                }
            }
        })

        load()
    }

    override fun onDestroy() {
        generation++
        executor?.shutdownNow()
        super.onDestroy()
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) {
            if (currentCountry != null) showCountries() else finish()
            return true
        }

        return super.onOptionsItemSelected(item)
    }

    // ---- Loading ---------------------------------------------------------

    private fun load() {
        progress.visibility = View.VISIBLE
        tvNote.text = getString(R.string.bs_load_running)

        val protocol = ProtocolSwitch.get(this)

        Thread {
            val downloaded = try {
                downloadFreeServers(protocol)
            } catch (e: Exception) {
                null
            }

            runOnUiThread {
                if (isFinishing || isDestroyed) {
                    return@runOnUiThread
                }

                progress.visibility = View.GONE

                if (downloaded.isNullOrEmpty()) {
                    Toast.makeText(this, R.string.bs_load_failed, Toast.LENGTH_LONG).show()
                    finish()
                    return@runOnUiThread
                }

                servers = downloaded
                results = IntArray(servers.size) { PENDING }
                vpnOn = isVpnActive()

                // Nothing is tested yet: a country is tested when it is opened.
                showCountries()
            }
        }.start()
    }

    private fun downloadFreeServers(protocol: Protocol): List<FreeServer> {
        for (url in listUrls(protocol)) {
            val result = try {
                // L2TP does not use the TCP port, so its list may leave it out.
                downloadFrom(url, portOptional = protocol == Protocol.L2TP)
            } catch (e: Exception) {
                emptyList()
            }

            if (result.isNotEmpty()) {
                return result
            }
        }

        return emptyList()
    }

    private fun downloadFrom(url: String, portOptional: Boolean): List<FreeServer> {
        val connection = URL(url).openConnection() as HttpURLConnection
        connection.connectTimeout = 15000
        connection.readTimeout = 15000

        try {
            val text = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            val array = JSONArray(text)
            val result = mutableListOf<FreeServer>()

            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                val host = obj.optString("host")
                val port = obj.optInt("port", 0)

                if (host.isEmpty() || (!portOptional && port !in 1..65535)) {
                    continue
                }

                // Never listed: too many sites are blocked there (the list file leaves it out too).
                if (obj.optString("country") in EXCLUDED_COUNTRIES) {
                    continue
                }

                result.add(
                    FreeServer(
                        host = host,
                        port = port,
                        country = obj.optString("country_name"),
                        countryCode = obj.optString("country"),
                        speedMbps = obj.optDouble("speed_mbps", 0.0),
                        ping = obj.optInt("ping", 0),
                        sessions = obj.optInt("sessions", 0),
                        udpPort = obj.optInt("udp_port", 0),
                    )
                )
            }

            return result
        } finally {
            connection.disconnect()
        }
    }

    private fun isVpnActive(): Boolean {
        val prefs = PreferenceManager.getDefaultSharedPreferences(this)

        if (getBooleanPrefValue(OscPrefKey.HOME_CONNECTOR, prefs)) {
            return true
        }

        val manager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val caps = manager.getNetworkCapabilities(manager.activeNetwork)

        return caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }

    // ---- Testing ---------------------------------------------------------

    private fun showCountries() {
        stopTests()
        currentCountry = null
        visible = emptyList()

        title = getString(R.string.bs_servers_title)
        tvHint.visibility = View.GONE
        btnTestAll.visibility = View.GONE

        updateNote()
        render()
    }

    private fun showServers(code: String) {
        stopTests()
        showAll = false
        currentCountry = code
        visible = servers.indices.filter { servers[it].countryCode == code }

        val first = servers[visible.first()]
        title = "${flagEmoji(code)} ${countryName(first)}".trim()
        tvHint.visibility = View.VISIBLE
        btnTestAll.visibility = View.VISIBLE

        if (vpnOn) {
            // A test through the tunnel would be misleading, so only the plain list is shown.
            updateNote()
            render()
        } else {
            startTest()
        }
    }

    private fun stopTests() {
        generation++
        executor?.shutdownNow()
        executor = null
        testing = false
    }

    // Ping answers arrive in bursts; drawing the list after each one would block the screen.
    private fun scheduleRender() {
        if (renderPending) return

        renderPending = true
        handler.postDelayed({
            renderPending = false
            if (!isDestroyed) render()
        }, 500)
    }

    private fun startTest() {
        if (visible.isEmpty() || vpnOn) {
            return
        }

        executor?.shutdownNow()
        visible.forEach { results[it] = PENDING }
        finished = 0
        testing = true
        generation++

        val myGeneration = generation
        // L2TP does not use the server's TCP port: it is tested with an IKE message on UDP 500.
        val useIke = ProtocolSwitch.get(this) == Protocol.L2TP
        val pool = Executors.newFixedThreadPool(16)
        executor = pool

        updateNote()
        render()

        visible.forEach { index ->
            val server = servers[index]

            pool.execute {
                val ms = if (useIke) IkeProbe.test(server.host) else ServerTester.test(server.host, server.port)

                handler.post {
                    if (myGeneration != generation) {
                        return@post
                    }

                    results[index] = ms
                    finished++

                    if (finished >= visible.size) {
                        testing = false
                    }

                    updateNote()
                    if (testing) scheduleRender() else render()
                }
            }
        }
    }

    private fun updateNote() {
        if (currentCountry == null) {
            val countries = servers.map { it.countryCode }.distinct().size
            tvNote.text = getString(R.string.bs_countries_note, servers.size, countries)
            return
        }

        val ok = visible.count { results[it] > 0 }

        tvNote.text = when {
            vpnOn -> getString(R.string.bs_test_vpn_on)
            testing -> getString(R.string.bs_test_running, finished, visible.size)
            ok == 0 -> getString(R.string.bs_test_none)
            else -> getString(R.string.bs_test_done, ok)
        }

        val canTest = !vpnOn && !testing
        btnTestAll.isEnabled = canTest
        btnTestAll.alpha = if (canTest) 1f else 0.5f
    }

    // ---- Rendering -------------------------------------------------------

    private fun countryName(server: FreeServer): String {
        val code = server.countryCode.trim()

        if (code.length == 2) {
            val name = Locale.Builder().setRegion(code.uppercase(Locale.US)).build().displayCountry

            if (name.isNotBlank() && !name.equals(code, ignoreCase = true)) {
                return name
            }
        }

        return server.country
    }

    private fun shortName(host: String): String {
        return if (IP_REGEX.matches(host)) host else host.substringBefore('.')
    }

    private fun pill(color: Int) = GradientDrawable().also {
        it.cornerRadius = 12f * resources.displayMetrics.density
        it.setColor(color)
    }

    private fun dot(color: Int) = GradientDrawable().also {
        it.shape = GradientDrawable.OVAL
        it.setColor(color)
    }

    private fun currentHost(): String =
        getStringPrefValue(OscPrefKey.HOME_HOSTNAME, PreferenceManager.getDefaultSharedPreferences(this))

    private fun render() {
        if (currentCountry == null) renderCountries() else renderServers()
    }

    private fun renderCountries() {
        list.removeAllViews()

        val groups = servers.indices.groupBy { servers[it].countryCode }
        val ordered = groups.entries.sortedWith(
            compareByDescending<Map.Entry<String, List<Int>>> { it.value.size }
                .thenBy { countryName(servers[it.value.first()]) }
        )

        val currentHost = currentHost()

        for ((code, indices) in ordered) {
            val row = layoutInflater.inflate(R.layout.item_country, list, false)

            // The country that holds the server in use is marked, so it is easy to find among the others.
            if (currentHost.isNotEmpty() && indices.any { servers[it].host == currentHost }) {
                row.findViewById<TextView>(R.id.tvCountryCurrent).apply {
                    setText(R.string.bs_current_here)
                    visibility = View.VISIBLE
                }
            }

            row.findViewById<TextView>(R.id.tvCountryTitle).text =
                "${flagEmoji(code)} ${countryName(servers[indices.first()])}".trim()
            row.findViewById<TextView>(R.id.tvCountryCount).text =
                if (indices.size == 1) getString(R.string.bs_country_servers_one)
                else getString(R.string.bs_country_servers, indices.size)

            row.setOnClickListener { showServers(code) }
            list.addView(row)
        }
    }

    private fun renderServers() {
        list.removeAllViews()

        // Servers that answered come first: by quality tier (good first), inside a tier by the lowest ping.
        // The ones not answered yet follow by quality, and the ones that failed are last.
        val currentHost = currentHost()

        val order = visible.sortedWith(
            compareBy<Int> { if (servers[it].host == currentHost) 0 else 1 } // the server in use stays on top
            .thenBy {
                when {
                    results[it] > 0 -> 0
                    results[it] == PENDING -> 1
                    else -> 2
                }
            }
                .thenBy { qualityRank(servers[it]) }
                .thenBy { if (results[it] > 0) results[it].toDouble() else -shareOf(servers[it]) }
        )

        val purple = getColor(R.color.banafsh_purple)
        val greyButton = 0xFFC9C2DD.toInt()

        val shown = if (showAll || order.size <= ROWS_LIMIT) order else order.take(ROWS_LIMIT)
        val showPort = ProtocolSwitch.get(this) == Protocol.SSTP

        for (index in shown) {
            val server = servers[index]
            val result = results[index]
            val row = layoutInflater.inflate(R.layout.item_free_server, list, false)

            row.findViewById<TextView>(R.id.tvTitle).text =
                "${flagEmoji(server.countryCode)} ${countryName(server)} · ${shortName(server.host)}".trim()

            // The server in use is framed and tagged: the names look alike, so it is easy to pick it again by mistake.
            val isCurrent = server.host == currentHost
            val tvCurrent = row.findViewById<TextView>(R.id.tvCurrent)
            val tvPort = row.findViewById<TextView>(R.id.tvPort)

            if (isCurrent) {
                row.background = getDrawable(R.drawable.bg_server_card_current)
                tvCurrent.setText(R.string.bs_current_server)
                tvCurrent.background = pill(0xFF8B5CF6.toInt())
                tvCurrent.visibility = View.VISIBLE
            }

            // SSTP connects to the server's TCP port, so it is shown; L2TP does not use it.
            if (showPort && server.port in 1..65535) {
                tvPort.text = getString(R.string.bs_port_label, server.port)
                tvPort.visibility = View.VISIBLE
            }

            if (isCurrent || showPort) {
                row.findViewById<View>(R.id.rowMeta).visibility = View.VISIBLE
            }

            // Quality: how much of the server's speed each user gets, from the list's own numbers.
            val chip = row.findViewById<TextView>(R.id.tvSpeed)
            when (qualityOf(server)) {
                Quality.GOOD -> {
                    chip.setText(R.string.bs_quality_good)
                    chip.background = pill(0xFFDDF7E8.toInt())
                    chip.setTextColor(0xFF0B6B30.toInt())
                }

                Quality.MEDIUM -> {
                    chip.setText(R.string.bs_quality_medium)
                    chip.background = pill(0xFFFFF1CC.toInt())
                    chip.setTextColor(0xFF7A5200.toInt())
                }

                Quality.BAD -> {
                    chip.setText(R.string.bs_quality_bad)
                    chip.background = pill(0xFFFDE7E7.toInt())
                    chip.setTextColor(0xFF8A1C1C.toInt())
                }

                Quality.UNKNOWN -> {
                    chip.setText(R.string.bs_quality_unknown)
                    chip.background = pill(0xFFECECEC.toInt())
                    chip.setTextColor(0xFF5F5F5F.toInt())
                }
            }

            val pill = row.findViewById<View>(R.id.pill)
            val pillDot = row.findViewById<View>(R.id.dotState)
            val pillText = row.findViewById<TextView>(R.id.tvPing)
            val button = row.findViewById<MaterialButton>(R.id.btnConnect)

            when {
                vpnOn -> {
                    // Not tested: no light, the button is simply available.
                    pill.visibility = View.GONE
                    button.backgroundTintList = ColorStateList.valueOf(purple)
                }

                result > 0 -> {
                    pill.background = pill(0xFFDDF7E8.toInt())
                    pillDot.background = dot(0xFF2ECC71.toInt())
                    pillText.setTextColor(0xFF0B6B30.toInt())
                    pillText.text = getString(R.string.bs_ping_ms, result) + " ✓"
                    button.backgroundTintList = ColorStateList.valueOf(purple)
                }

                result == ServerTester.FAILED -> {
                    pill.background = pill(0xFFFDE7E7.toInt())
                    pillDot.background = dot(0xFFE5484D.toInt())
                    pillText.setTextColor(0xFF8A1C1C.toInt())
                    pillText.text = getString(R.string.bs_server_failed) + " ✕"
                    button.backgroundTintList = ColorStateList.valueOf(greyButton)
                    row.alpha = 0.6f
                }

                else -> {
                    pill.background = pill(0xFFECE8F7.toInt())
                    pillDot.background = dot(0xFF9E9E9E.toInt())
                    pillText.setTextColor(0xFF5B4A8C.toInt())
                    pillText.text = getString(R.string.bs_pill_testing)
                    button.backgroundTintList = ColorStateList.valueOf(greyButton)
                    button.isEnabled = false
                }
            }

            button.setOnClickListener {
                if (result == ServerTester.FAILED) {
                    AlertDialog.Builder(this)
                        .setMessage(R.string.bs_connect_anyway)
                        .setPositiveButton(R.string.bs_connect) { _, _ -> choose(server) }
                        .setNegativeButton(R.string.bs_cancel, null)
                        .show()
                } else {
                    choose(server)
                }
            }

            list.addView(row)
        }

        if (shown.size < order.size) {
            val more = MaterialButton(this)
            more.text = getString(R.string.bs_show_all, order.size)
            more.setOnClickListener {
                showAll = true
                render()
            }
            list.addView(more)
        }
    }

    private fun choose(server: FreeServer) {
        generation++
        executor?.shutdownNow()

        setResult(
            RESULT_OK,
            android.content.Intent()
                .putExtra(EXTRA_HOST, server.host)
                .putExtra(EXTRA_PORT, server.port)
                .putExtra(EXTRA_COUNTRY_CODE, server.countryCode)
                .putExtra(EXTRA_PING, servers.indexOf(server).let { if (it >= 0 && results[it] > 0) results[it] else 0 })
        )
        finish()
    }
}
