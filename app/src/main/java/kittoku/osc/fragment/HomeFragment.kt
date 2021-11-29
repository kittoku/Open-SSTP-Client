package kittoku.osc.fragment

import android.app.Activity
import android.content.*
import android.net.*
import android.os.Bundle
import android.text.TextUtils
import android.view.View
import android.widget.Toast
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import kittoku.osc.*
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getIntPrefValue
import kittoku.osc.preference.accessor.getSetPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue
import kittoku.osc.preference.custom.HomeConnectorPreference


class HomeFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.home, rootKey)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        attachSwitchListener()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (resultCode == Activity.RESULT_OK) {
            startVpnService(ACTION_VPN_CONNECT)
        }
    }

    private fun startVpnService(action: String) {
        context?.startService(Intent(context, SstpVpnService::class.java).setAction(action))
    }

    private fun attachSwitchListener() {
        findPreference<HomeConnectorPreference>(OscPreference.HOME_CONNECTOR.name)!!.also {
            it.onPreferenceChangeListener = Preference.OnPreferenceChangeListener { _, newState ->
                if (newState == true) {
                    if (!checkPreferences()) {
                        return@OnPreferenceChangeListener false
                    }

                    VpnService.prepare(context)?.also { intent ->
                        startActivityForResult(intent, 0)
                    } ?: onActivityResult(0, Activity.RESULT_OK, null)
                } else {
                    startVpnService(ACTION_VPN_DISCONNECT)
                }

                true
            }
        }
    }

    private fun makeToast(cause: String) {
        Toast.makeText(context, "INVALID SETTING: $cause", Toast.LENGTH_LONG).show()
    }

    private fun checkPreferences(): Boolean {
        val prefs = preferenceManager.sharedPreferences


        getStringPrefValue(OscPreference.HOME_HOSTNAME, prefs).also {
            if (TextUtils.isEmpty(it)) {
                makeToast("Host is missing")
                return false
            }
        }

        getIntPrefValue(OscPreference.SSL_PORT, prefs).also {
            if (it !in 0..65535) {
                makeToast("The given port is out of 0-65535")
                return false
            }
        }

        val doAddCerts = getBooleanPrefValue(OscPreference.SSL_DO_ADD_CERT, prefs)
        val version = getStringPrefValue(OscPreference.SSL_VERSION, prefs)
        val certDir = getStringPrefValue(OscPreference.SSL_CERT_DIR, prefs)
        if (doAddCerts && version == "DEFAULT") {
            makeToast("Adding trusted certificates needs SSL version to be specified")
            return false
        }

        if (doAddCerts && certDir.isEmpty()) {
            makeToast("No certificates directory was selected")
            return false
        }

        val doSelectSuites = getBooleanPrefValue(OscPreference.SSL_DO_SELECT_SUITES, prefs)
        val suites = getSetPrefValue(OscPreference.SSL_SUITES, prefs)
        if (doSelectSuites && suites.isEmpty()) {
            makeToast("No cipher suite was selected")
            return false
        }

        val mru = getIntPrefValue(OscPreference.PPP_MRU, prefs).also {
            if (it !in MIN_MRU..MAX_MRU) {
                makeToast("The given MRU is out of $MIN_MRU-$MAX_MRU")
                return false
            }
        }

        val mtu = getIntPrefValue(OscPreference.PPP_MTU, prefs).also {
            if (it !in MIN_MTU..MAX_MTU) {
                makeToast("The given MRU is out of $MIN_MTU-$MAX_MTU")
                return false
            }
        }

        val isIpv4Enabled = getBooleanPrefValue(OscPreference.PPP_IPv4_ENABLED, prefs)
        val isIpv6Enabled = getBooleanPrefValue(OscPreference.PPP_IPv6_ENABLED, prefs)
        if (!isIpv4Enabled && !isIpv6Enabled) {
            makeToast("No network protocol was enabled")
            return false
        }

        val isPapEnabled = getBooleanPrefValue(OscPreference.PPP_PAP_ENABLED, prefs)
        val isMschapv2Enabled = getBooleanPrefValue(OscPreference.PPP_MSCHAPv2_ENABLED, prefs)
        if (!isPapEnabled && !isMschapv2Enabled) {
            makeToast("No authentication protocol was enabled")
            return false
        }

        getIntPrefValue(OscPreference.IP_PREFIX, prefs).also {
            if (it !in 0..32) {
                makeToast("The given address prefix length is out of 0-32")
                return false
            }
        }

        getIntPrefValue(OscPreference.RECONNECTION_COUNT, prefs).also {
            if (it < 1) {
                makeToast("Retry Count must be a positive integer")
                return false
            }
        }

        getIntPrefValue(OscPreference.BUFFER_INCOMING, prefs).also {
            if (it < 2 * mru) {
                makeToast("Incoming Buffer Size must be >= 2 * MRU")
                return false
            }
        }

        getIntPrefValue(OscPreference.BUFFER_OUTGOING, prefs).also {
            if (it < 2 * mtu) {
                makeToast("Outgoing Buffer Size must be >= 2 * MTU")
                return false
            }
        }

        val doSaveLog = getBooleanPrefValue(OscPreference.LOG_DO_SAVE_LOG, prefs)
        val logDir = getStringPrefValue(OscPreference.LOG_DIR, prefs)
        if (doSaveLog && logDir.isEmpty()) {
            makeToast("No log directory was selected")
            return false
        }


        return true
    }
}
