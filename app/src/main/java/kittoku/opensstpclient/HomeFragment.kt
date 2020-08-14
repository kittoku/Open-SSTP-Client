package kittoku.opensstpclient

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Bundle
import android.preference.PreferenceManager
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CompoundButton
import androidx.fragment.app.Fragment
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import kotlinx.android.synthetic.main.fragment_home.*


class HomeFragment : Fragment() {
    private val TAG = "HomeFragment"

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? = inflater.inflate(R.layout.fragment_home, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        val listener = { _: CompoundButton, isChecked: Boolean ->
            if (isChecked) {
                wipeLog()
                savePreferences()

                val intent = VpnService.prepare(context)
                if (intent != null) {
                    startActivityForResult(intent, 0)
                } else {
                    onActivityResult(0, Activity.RESULT_OK, null)
                }

            } else {
                startVpnService(VpnAction.ACTION_DISCONNECT)
            }
        }

        loadPreferences()

        connector.setOnCheckedChangeListener(listener)

        LocalBroadcastManager.getInstance(context!!).registerReceiver(
            object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    if (intent?.action == VpnAction.ACTION_UPDATE.value) {
                        if (activity != null) {
                            connector.setOnCheckedChangeListener(null)
                            loadPreferences()
                            connector.setOnCheckedChangeListener(listener)
                        }
                    }
                }
            },
            IntentFilter().also { it.addAction(VpnAction.ACTION_UPDATE.value) }
        )
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (resultCode == Activity.RESULT_OK) { startVpnService(VpnAction.ACTION_CONNECT) }
    }

    private fun startVpnService(action: VpnAction) {
        context?.startService(Intent(context, SstpVpnService::class.java).setAction(action.value))
    }

    private fun loadPreferences() {
        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        editHost.setText(prefs.getString(PreferenceKey.HOST.value, ""))
        editUsername.setText(prefs.getString(PreferenceKey.USERNAME.value, ""))
        editPassword.setText(prefs.getString(PreferenceKey.PASSWORD.value, ""))
        connector.isChecked = prefs.getBoolean(PreferenceKey.SWITCH.value, false)
        textLog.text = prefs.getString(PreferenceKey.LOG.value, "")
    }

    private fun savePreferences() {
        val editor = PreferenceManager.getDefaultSharedPreferences(context).edit()
        editor.putString(PreferenceKey.HOST.value, editHost.text.toString())
        editor.putString(PreferenceKey.USERNAME.value, editUsername.text.toString())
        editor.putString(PreferenceKey.PASSWORD.value, editPassword.text.toString())
        editor.putBoolean(PreferenceKey.SWITCH.value, connector.isChecked)
        editor.putString(PreferenceKey.LOG.value, textLog.text.toString())

        editor.apply()
    }

    private fun wipeLog() {
        textLog.text = ""
        val editor = PreferenceManager.getDefaultSharedPreferences(context).edit()
        editor.putString(PreferenceKey.LOG.value, "")
        editor.apply()
    }
}
