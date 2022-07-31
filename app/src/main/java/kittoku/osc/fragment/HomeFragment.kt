package kittoku.osc.fragment

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import kittoku.osc.ACTION_VPN_CONNECT
import kittoku.osc.ACTION_VPN_DISCONNECT
import kittoku.osc.R
import kittoku.osc.SstpVpnService
import kittoku.osc.preference.OscPreference
import kittoku.osc.preference.checkPreferences
import kittoku.osc.preference.custom.HomeConnectorPreference
import kittoku.osc.preference.toastInvalidSetting


class HomeFragment : PreferenceFragmentCompat() {
    private val authorizer = registerForActivityResult(StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService(ACTION_VPN_CONNECT)
        }
    }

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.home, rootKey)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        attachConnectorListener()
    }

    private fun startVpnService(action: String) {
        context?.startService(Intent(context, SstpVpnService::class.java).setAction(action))
    }

    private fun attachConnectorListener() {
        findPreference<HomeConnectorPreference>(OscPreference.HOME_CONNECTOR.name)!!.also {
            it.onPreferenceChangeListener = Preference.OnPreferenceChangeListener { _, newState ->
                if (newState == true) {
                    checkPreferences(preferenceManager.sharedPreferences!!)?.also { message ->
                        toastInvalidSetting(message, context)
                        return@OnPreferenceChangeListener false
                    }

                    VpnService.prepare(context)?.also { intent ->
                        authorizer.launch(intent)
                    } ?: startVpnService(ACTION_VPN_CONNECT)
                } else {
                    startVpnService(ACTION_VPN_DISCONNECT)
                }

                true
            }
        }
    }
}
