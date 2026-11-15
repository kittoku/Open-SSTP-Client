package kittoku.osc.activity

import android.Manifest
import android.app.Dialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.text.util.Linkify
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.AppCompatCheckBox
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.fragment.app.Fragment
import androidx.preference.EditTextPreference
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.PreferenceGroup
import androidx.preference.PreferenceManager
import androidx.preference.forEach
import androidx.viewpager2.adapter.FragmentStateAdapter
import com.google.android.material.tabs.TabLayoutMediator
import kittoku.osc.BuildConfig
import kittoku.osc.R
import kittoku.osc.databinding.ActivityMainBinding
import kittoku.osc.IranApps
import kittoku.osc.IranRanges
import kittoku.osc.NewsChecker
import kittoku.osc.NewsNotifier
import kittoku.osc.DnsDialog
import kittoku.osc.Protocol
import kittoku.osc.ProtocolSwitch
import kittoku.osc.SharedServer
import kittoku.osc.ThemeMode
import kittoku.osc.flagEmoji
import kittoku.osc.extension.firstEditText
import kittoku.osc.extension.sum
import kittoku.osc.fragment.HomeFragment
import kittoku.osc.fragment.SettingFragment
import kittoku.osc.preference.LIST_TYPE_DISALLOWED
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.PROFILE_KEY_HEADER
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getIntPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue
import kittoku.osc.preference.accessor.setStringPrefValue
import kittoku.osc.preference.accessor.setBooleanPrefValue
import kittoku.osc.preference.accessor.setSetPrefValue
import kittoku.osc.preference.custom.OscPreference
import kittoku.osc.preference.deserializeProfile
import kittoku.osc.preference.importProfile
import kittoku.osc.preference.serializeProfile
import kittoku.osc.service.ACTION_VPN_CONNECT
import kittoku.osc.service.ACTION_VPN_DISCONNECT
import kittoku.osc.service.SstpVpnService
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.Locale

private const val KEY_RECONNECT_DEFAULT_V1 = "reconnect_default_v1"

class MainActivity : AppCompatActivity() {
    override fun attachBaseContext(newBase: android.content.Context) {
        super.attachBaseContext(kittoku.osc.LocaleFix.wrap(newBase))
    }

    private lateinit var prefs: SharedPreferences

    private val uiPrefs: SharedPreferences by lazy {
        getSharedPreferences("banafsh_ui", MODE_PRIVATE)
    }

    private val dialogResource: Int by lazy { EditTextPreference(this).dialogLayoutResource }

    private val profileLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode != RESULT_OK) {
            return@registerForActivityResult
        }

        updatePreferenceView()
    }

    private val importLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.also {
            val text = try {
                contentResolver.openInputStream(it)?.use { stream ->
                    stream.reader(Charsets.UTF_8).readText()
                }
            } catch (e: Exception) {
                null
            }

            if (text == null) {
                Toast.makeText(this, R.string.bs_file_read_failed, Toast.LENGTH_SHORT).show()
            } else {
                showImportConfirm(text)
            }
        }
    }

    private val exportLauncher = registerForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        uri?.also {
            contentResolver.openOutputStream(it)?.also { stream ->
                BufferedOutputStream(stream).use {
                    it.write(serializeProfile(prefs).toByteArray(Charsets.UTF_8))
                }
            }

            Toast.makeText(this, R.string.bs_profile_exported, Toast.LENGTH_SHORT).show()
        }
    }

    private val scanLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val data = result.data

        if (result.resultCode != RESULT_OK || data == null) {
            return@registerForActivityResult
        }

        val server = SharedServer(
            host = data.getStringExtra(QrScanActivity.EXTRA_HOST).orEmpty(),
            port = data.getIntExtra(QrScanActivity.EXTRA_PORT, 443),
            user = data.getStringExtra(QrScanActivity.EXTRA_USER).orEmpty(),
            pass = data.getStringExtra(QrScanActivity.EXTRA_PASS).orEmpty(),
            countryCode = data.getStringExtra(QrScanActivity.EXTRA_COUNTRY).orEmpty(),
            verify = data.getBooleanExtra(QrScanActivity.EXTRA_VERIFY, true)
        )

        if (server.host.isNotEmpty()) {
            showReceivedServerConfirm(server)
        }
    }

    private fun updatePreferenceView() {
        // Home refreshes itself from the preferences; Settings reads them when it is opened.
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        ThemeMode.apply(PreferenceManager.getDefaultSharedPreferences(this).getString("THEME_MODE", "system"))
        setTheme(R.style.Theme_OpenSSTPClient_NoActionBar)
        super.onCreate(savedInstanceState)

        title = getString(R.string.bs_title)

        val binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayShowTitleEnabled(false)
        binding.toolbar.overflowIcon = ContextCompat.getDrawable(this, R.drawable.ic_bars)?.mutate()?.apply {
            setTint(ContextCompat.getColor(this@MainActivity, R.color.bs_ink))
        }
        // The background is light: dark icons in the status bar and the navigation bar.
        WindowCompat.getInsetsController(window, binding.root).apply {
            isAppearanceLightStatusBars = true
            isAppearanceLightNavigationBars = true
        }
        ViewCompat.setOnApplyWindowInsetsListener(binding.container) { view, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            view.setPadding(bars.left, 0, bars.right, bars.bottom)
            insets
        }

        prefs = PreferenceManager.getDefaultSharedPreferences(this)
        IranApps.ensureSeeded(this, prefs)
        IranApps.refreshIfDue(this, prefs)
        IranRanges.ensureSeeded(this)
        IranRanges.refreshIfDue(this)

        // The old "only these apps use the VPN" mode is gone. Keep earlier picks only if they meant
        // "these apps connect directly"; otherwise clear them so they do not change meaning.
        if (!uiPrefs.getBoolean("apps_rule_migrated_v2", false)) {
            val keep = getBooleanPrefValue(OscPrefKey.ROUTE_DO_ENABLE_APP_BASED_RULE, prefs) &&
                    getStringPrefValue(OscPrefKey.ROUTE_APP_LIST_TYPE, prefs) == LIST_TYPE_DISALLOWED

            if (!keep) setSetPrefValue(emptySet(), OscPrefKey.ROUTE_SELECTED_APPS, prefs)
            setBooleanPrefValue(false, OscPrefKey.ROUTE_DO_ENABLE_APP_BASED_RULE, prefs)
            uiPrefs.edit().putBoolean("apps_rule_migrated_v2", true).apply()
        }

        if (savedInstanceState == null) {
            supportFragmentManager.beginTransaction().replace(R.id.container, HomeFragment()).commit()
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
            }
        }

        // Reconnection is now on by default; switch it on once for installs that saved the old default.
        if (!uiPrefs.getBoolean(KEY_RECONNECT_DEFAULT_V1, false)) {
            setBooleanPrefValue(true, OscPrefKey.RECONNECTION_ENABLED, prefs)
            uiPrefs.edit().putBoolean(KEY_RECONNECT_DEFAULT_V1, true).apply()
        }

        if (savedInstanceState == null) {
            val lastSeen = uiPrefs.getString(KEY_LAST_SEEN_VERSION, null)

            var infoShown = true

            if (!uiPrefs.getBoolean(OnboardingActivity.KEY_DONE, false)) {
                // First launch: a short intro (it can be skipped) instead of the old welcome dialog.
                uiPrefs.edit().putBoolean(KEY_HIDE_WELCOME, true).apply()
                startActivity(Intent(this, OnboardingActivity::class.java))
            } else if (!uiPrefs.getBoolean(KEY_HIDE_WELCOME, false)) {
                showWelcomeDialog(this)
            } else if (lastSeen != BuildConfig.VERSION_NAME) {
                showWhatsNewDialog(this)
            } else {
                infoShown = false
            }

            uiPrefs.edit().putString(KEY_LAST_SEEN_VERSION, BuildConfig.VERSION_NAME).apply()

            // News and update pop-ups (also opened from their notifications).
            if (!infoShown) {
                Popups.showPending(this, prefs)
            }

            NewsChecker.fetchAsync(prefs, UpdateUi.language(this)) { Popups.showPending(this, prefs) }
            UpdateUi.checkIfDue(prefs) { Popups.showPending(this, prefs) }
        }

        NewsNotifier.ensureChannel(this)
        NewsNotifier.schedule(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        Popups.showPending(this, prefs)
    }

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        MenuInflater(this).inflate(R.menu.home_menu, menu)

        return true
    }

    private fun openSettings() {
        startActivity(
            Intent(this, BlankActivity::class.java).putExtra(EXTRA_KEY_TYPE, BLANK_ACTIVITY_TYPE_SETTINGS)
        )
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.open_settings -> openSettings()

            R.id.manual_server -> showServerDialog()

            R.id.dns_settings -> DnsDialog.show(this)

            R.id.check_update -> UpdateUi.checkNow(this, prefs)

            R.id.send_server -> startActivity(Intent(this, QrSendActivity::class.java))

            R.id.receive_server -> scanLauncher.launch(Intent(this, QrScanActivity::class.java))

            R.id.load_profile -> {
                profileLauncher.launch(Intent(this, BlankActivity::class.java).putExtra(
                    EXTRA_KEY_TYPE,
                    BLANK_ACTIVITY_TYPE_PROFILES
                ))
            }

            R.id.save_profile -> showSaveDialog()
            R.id.import_profile -> importLauncher.launch(arrayOf("*/*"))
            R.id.export_profile -> showExportDialog()
            R.id.reload_defaults -> showReloadDialog()
        }

        return true
    }

    private fun showSaveDialog() {
        val inflated = layoutInflater.inflate(dialogResource, null)
        val editText = inflated.firstEditText()
        val hostname = getStringPrefValue(OscPrefKey.HOME_HOSTNAME, prefs)

        editText.inputType = InputType.TYPE_CLASS_TEXT
        editText.hint = hostname
        editText.requestFocus()

        AlertDialog.Builder(this).also {
            it.setView(inflated)
            it.setMessage(R.string.bs_save_msg)
            it.setPositiveButton(R.string.bs_save) { _, _ ->
                prefs.edit().also { editor ->
                    editor.putString(
                        PROFILE_KEY_HEADER + editText.text.ifEmpty { hostname },
                        serializeProfile(prefs)
                    )

                    editor.apply()
                }

                Toast.makeText(this, R.string.bs_profile_saved, Toast.LENGTH_SHORT).show()
            }
            it.setNegativeButton(R.string.bs_cancel) { _, _ -> }
            it.show()
        }
    }

    private fun showExportDialog() {
        val filename = getStringPrefValue(OscPrefKey.HOME_HOSTNAME, prefs) + ".json"

        AlertDialog.Builder(this).also {
            it.setMessage(R.string.bs_export_msg)
            it.setPositiveButton(R.string.bs_proceed) { _, _ ->
                exportLauncher.launch(filename)
            }
            it.setNegativeButton(R.string.bs_cancel) { _, _ -> }
            it.show()
        }
    }

    private fun showReloadDialog() {
        AlertDialog.Builder(this).also {
            it.setMessage(R.string.bs_reload_msg)
            it.setPositiveButton(R.string.bs_yes) { _, _ ->
                importProfile(null, prefs)
                updatePreferenceView()

                Toast.makeText(this, R.string.bs_defaults_reloaded, Toast.LENGTH_SHORT).show()
            }
            it.setNegativeButton(R.string.bs_no) { _, _ -> }
            it.show()
        }
    }

    // ---- Import with confirmation ----------------------------------------

    private fun showImportConfirm(jsonText: String) {
        val profile = deserializeProfile(jsonText)

        var host = ""
        var port = 443
        var user = ""
        var pass = ""

        try {
            val json = JSONObject(jsonText)
            val strings = json.optJSONObject("stringSetting")
            val ints = json.optJSONObject("intSetting")

            host = strings?.optString("HOME_HOSTNAME").orEmpty()
            user = strings?.optString("HOME_USERNAME").orEmpty()
            pass = strings?.optString("HOME_PASSWORD").orEmpty()
            port = ints?.optInt("SSL_PORT", 443) ?: 443
        } catch (e: Exception) {
            host = ""
        }

        if (profile == null || host.isEmpty()) {
            Toast.makeText(this, R.string.bs_config_invalid, Toast.LENGTH_LONG).show()
            return
        }

        val message = getString(
            R.string.bs_config_msg,
            host,
            port,
            user.ifEmpty { getString(R.string.bs_empty) },
            pass.ifEmpty { getString(R.string.bs_empty) }
        )

        AlertDialog.Builder(this).also {
            it.setTitle(R.string.bs_config_title)
            it.setMessage(message)
            it.setPositiveButton(R.string.bs_config_use) { _, _ ->
                importProfile(profile, prefs)
                updatePreferenceView()

                Toast.makeText(this, R.string.bs_config_saved, Toast.LENGTH_LONG).show()
            }
            it.setNegativeButton(R.string.bs_cancel) { _, _ -> }
            it.show()
        }
    }

    // ---- Receive a server by QR --------------------------------------------

    private fun showReceivedServerConfirm(server: SharedServer) {
        val label = "${flagEmoji(server.countryCode)} ${server.host}:${server.port}".trim()

        AlertDialog.Builder(this)
            .setTitle(R.string.bs_qr_confirm_title)
            .setMessage(getString(R.string.bs_qr_confirm_msg, label))
            .setPositiveButton(R.string.bs_qr_confirm_save) { _, _ -> applyReceivedServer(server) }
            .setNegativeButton(R.string.bs_cancel, null)
            .show()
    }

    private fun applyReceivedServer(server: SharedServer) {
        uiPrefs.edit().remove("server_list").apply() // not from a list: any service may use it
        if (!applyServerSettings(server.host, server.port, server.user, server.pass, !server.verify)) {
            Toast.makeText(this, R.string.bs_server_set_failed, Toast.LENGTH_SHORT).show()
            return
        }

        uiPrefs.edit()
            .putString("server_host", server.host)
            .putString("server_country", server.countryCode)
            .apply()
        updatePreferenceView()

        AlertDialog.Builder(this)
            .setMessage(R.string.bs_qr_connect_msg)
            .setPositiveButton(R.string.bs_yes) { _, _ ->
                if (getBooleanPrefValue(OscPrefKey.HOME_CONNECTOR, prefs)) {
                    // Drop the current connection first so that the new server is really used.
                    disconnectNow()
                    window.decorView.postDelayed({ connectNow() }, 1800)
                } else {
                    connectNow()
                }
            }
            .setNegativeButton(R.string.bs_no, null)
            .show()
    }

    // ---- Get Free Config -------------------------------------------------

    private val freeServerLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val data = result.data

        if (result.resultCode != RESULT_OK || data == null) {
            return@registerForActivityResult
        }

        val host = data.getStringExtra(ServerListActivity.EXTRA_HOST).orEmpty()
        val port = data.getIntExtra(ServerListActivity.EXTRA_PORT, 443)
        val countryCode = data.getStringExtra(ServerListActivity.EXTRA_COUNTRY_CODE).orEmpty()
        val ping = data.getIntExtra(ServerListActivity.EXTRA_PING, 0)

        if (host.isNotEmpty()) {
            applyFreeServer(FreeServer(host, port, "", countryCode, 0.0, ping))
        }
    }

    internal fun showFreeConfig() {
        freeServerLauncher.launch(Intent(this, ServerListActivity::class.java))
    }

    private fun JSONObject.section(name: String): JSONObject {
        return optJSONObject(name) ?: JSONObject().also { put(name, it) }
    }

    private fun applyServerSettings(host: String, port: Int, user: String, pass: String, disableVerify: Boolean): Boolean {
        uiPrefs.edit().remove("server_ping").apply() // a server entered by hand has no measured ping
        val profile = try {
            val json = JSONObject(serializeProfile(prefs))

            json.section("stringSetting").also {
                it.put("HOME_HOSTNAME", host)
                it.put("HOME_USERNAME", user)
                it.put("HOME_PASSWORD", pass)
            }
            json.section("intSetting").put("SSL_PORT", port)
            if (disableVerify) {
                json.section("booleanSetting").put("SSL_DO_VERIFY", false)
            }

            deserializeProfile(json.toString())
        } catch (e: Exception) {
            null
        }

        if (profile == null) {
            return false
        }

        importProfile(profile, prefs)
        return true
    }

    private fun applyFreeServer(server: FreeServer) {
        // L2TP does not use the TCP port, so its list may leave it out: keep the stored port valid anyway.
        val port = if (server.port in 1..65535) server.port else 443

        if (!applyServerSettings(server.host, port, "vpn", "vpn", true)) {
            Toast.makeText(this, R.string.bs_server_set_failed, Toast.LENGTH_SHORT).show()
            return
        }

        uiPrefs.edit()
            .putString("server_host", server.host)
            .putString("server_country", server.countryCode)
            .putString("server_list", ProtocolSwitch.get(this).listKey) // the list this server was picked from
            .putInt("server_ping", server.ping)
            .apply()
        updatePreferenceView()

        Toast.makeText(this, getString(R.string.bs_server_set_connecting, server.host), Toast.LENGTH_LONG).show()
        connectNow()
    }

    // ---- Server dialog ---------------------------------------------------

    internal fun showServerDialog() {
        val view = layoutInflater.inflate(R.layout.dialog_server, null)
        val etHost = view.findViewById<EditText>(R.id.etHost)
        val etPort = view.findViewById<EditText>(R.id.etPort)
        val etUser = view.findViewById<EditText>(R.id.etUser)
        val etPass = view.findViewById<EditText>(R.id.etPass)

        etHost.setText(getStringPrefValue(OscPrefKey.HOME_HOSTNAME, prefs))
        etPort.setText(getIntPrefValue(OscPrefKey.SSL_PORT, prefs).toString())
        etUser.setText(getStringPrefValue(OscPrefKey.HOME_USERNAME, prefs))
        etPass.setText(getStringPrefValue(OscPrefKey.HOME_PASSWORD, prefs))

        val dialog = AlertDialog.Builder(this)
            .setTitle(R.string.bs_server_dialog_title)
            .setView(view)
            .setPositiveButton(R.string.bs_save, null)
            .setNegativeButton(R.string.bs_cancel, null)
            .create()

        dialog.setOnShowListener {
            dialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener {
                val host = etHost.text.toString().trim()
                val port = etPort.text.toString().trim().toIntOrNull()

                when {
                    host.isEmpty() -> etHost.error = getString(R.string.bs_err_address)
                    port == null || port !in 1..65535 -> etPort.error = getString(R.string.bs_err_port)
                    else -> {
                        if (applyServerSettings(host, port, etUser.text.toString(), etPass.text.toString(), false)) {
                            uiPrefs.edit().remove("server_list").apply() // typed by hand: any service may use it
                            Toast.makeText(this, R.string.bs_saved, Toast.LENGTH_SHORT).show()
                            dialog.dismiss()
                        }
                    }
                }
            }
        }

        dialog.show()
    }

    // ---- Protocol dialog -------------------------------------------------

    internal fun showProtocolDialog() {
        val current = ProtocolSwitch.get(this)
        val density = resources.displayMetrics.density
        val container = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        var dialog: Dialog? = null

        Protocol.values().forEach { protocol ->
            val row = layoutInflater.inflate(R.layout.item_protocol, container, false)
            val card = row as com.google.android.material.card.MaterialCardView
            val selected = protocol == current

            row.findViewById<TextView>(R.id.tvProtoName).setText(protocol.nameRes)
            row.findViewById<TextView>(R.id.tvProtoDesc).setText(protocol.descRes)
            row.findViewById<ImageView>(R.id.ivProtoCheck).visibility = if (selected) View.VISIBLE else View.INVISIBLE

            card.strokeColor = ContextCompat.getColor(this, if (selected) R.color.bs_dialog_link else R.color.bs_dialog_stroke)
            card.strokeWidth = ((if (selected) 2 else 1) * density).toInt()

            row.setOnClickListener {
                dialog?.dismiss()

                if (protocol != current) {
                    ProtocolSwitch.set(this, protocol)

                    if (getBooleanPrefValue(OscPrefKey.HOME_CONNECTOR, prefs)) {
                        // A running tunnel keeps its service; the new one starts with the next connection.
                        Toast.makeText(this, R.string.bs_protocol_next, Toast.LENGTH_LONG).show()
                    } else {
                        verifyServerForService { }
                    }
                }
            }

            container.addView(row)
        }

        dialog = GlassDialog.show(
            this,
            R.drawable.ic_gd_protocol,
            getString(R.string.bs_protocol_title),
            content = container,
            secondaryText = getString(R.string.bs_cancel)
        )
    }

    // ---- Each service has its own server list ------------------------------

    // A server picked from the list of one service is not offered to the other one.
    private fun serverMatchesService(): Boolean {
        val marker = uiPrefs.getString("server_list", null) ?: return true
        return marker == ProtocolSwitch.get(this).listKey
    }

    private fun clearListServer() {
        setStringPrefValue("", OscPrefKey.HOME_HOSTNAME, prefs)
        uiPrefs.edit().remove("server_host").remove("server_country").remove("server_list").apply()
        updatePreferenceView()
    }

    // The server was picked from the other service's list. Many servers are in both: look into the list of the
    // selected service and only ask for a new server when this one is not there. [onSame] runs when it can stay.
    private fun verifyServerForService(onSame: () -> Unit) {
        if (serverMatchesService()) {
            onSame()
            return
        }

        val protocol = ProtocolSwitch.get(this)
        val host = getStringPrefValue(OscPrefKey.HOME_HOSTNAME, prefs)

        if (host.isEmpty()) {
            onSame()
            return
        }

        Thread {
            val hosts = fetchServerHosts(protocol) // null: the list could not be loaded

            runOnUiThread {
                if (isFinishing || isDestroyed || ProtocolSwitch.get(this) != protocol) return@runOnUiThread

                if (hosts != null && host in hosts) {
                    uiPrefs.edit().putString("server_list", protocol.listKey).apply()
                    onSame()
                } else {
                    clearListServer()
                    showChooseAgain()
                }
            }
        }.start()
    }

    private fun showChooseAgain() {
        GlassDialog.show(
            this,
            R.drawable.ic_gd_protocol,
            getString(R.string.bs_choose_again_title),
            body = getString(R.string.bs_choose_again_body, getString(ProtocolSwitch.get(this).nameRes)),
            primaryText = getString(R.string.bs_choose_again_button),
            onPrimary = { showFreeConfig() },
            secondaryText = getString(R.string.bs_later)
        )
    }

    // ---- Connect / disconnect ---------------------------------------------

    private val vpnPermissionLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        }
    }

    internal fun connectNow() {
        if (!serverMatchesService()) {
            verifyServerForService { connectNow() }
            return
        }

        if (getStringPrefValue(OscPrefKey.HOME_HOSTNAME, prefs).isEmpty()) {
            Toast.makeText(this, R.string.bs_connect_pick_server, Toast.LENGTH_LONG).show()
            return
        }

        val intent = VpnService.prepare(this)

        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpnService()
        }
    }

    // The chosen service (L2TP or SSTP) decides which tunnel is started.
    private fun startVpnService() {
        ProtocolSwitch.connect(this)
    }

    internal fun disconnectNow() {
        ProtocolSwitch.disconnect(this)
    }

    internal fun toggleConnection() {
        if (getBooleanPrefValue(OscPrefKey.HOME_CONNECTOR, prefs)) {
            disconnectNow()
        } else {
            connectNow()
        }
    }
}
