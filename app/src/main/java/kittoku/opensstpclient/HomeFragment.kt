package kittoku.opensstpclient

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Bundle
import android.preference.PreferenceManager
import android.support.v4.app.Fragment
import android.support.v4.content.LocalBroadcastManager
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.Switch
import android.widget.TextView
import kittoku.opensstpclient.misc.EXTENDED_LOG


class HomeFragment : Fragment() {
    private val TAG = "HomeFragment"

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? = inflater.inflate(R.layout.fragment_home, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        val switch = view.findViewById<Switch>(R.id.connector)
        val log = view.findViewById<TextView>(R.id.log)

        loadPreferences(view)

        switch.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                wipeLog(log)

                val intent = VpnService.prepare(context)
                if (intent == null) {
                    onActivityResult(0, Activity.RESULT_OK, null)
                } else startActivityForResult(intent, 0)
            } else {
                startVpnService(VpnAction.ACTION_DISCONNECT)
            }

            savePreferences(view)
        }

        LocalBroadcastManager.getInstance(context!!).registerReceiver(
            object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    when (intent?.action) {
                        VpnAction.ACTION_CONVEY.value -> {
                            intent.getStringExtra(EXTENDED_LOG)?.also {
                                log.append(it)
                            }
                        }

                        VpnAction.ACTION_SWITCHOFF.value -> {
                            switch.isChecked = false
                        }
                    }

                    savePreferences(view)
                }
            },
            IntentFilter().also {
                it.addAction(VpnAction.ACTION_CONVEY.value)
                it.addAction(VpnAction.ACTION_SWITCHOFF.value)
            }
        )
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (resultCode == Activity.RESULT_OK) { startVpnService(VpnAction.ACTION_CONNECT) }
    }

    private fun startVpnService(action: VpnAction) {
        context?.startService(Intent(context, SstpVpnService::class.java).setAction(action.value))
    }

    private fun loadPreferences(view: View) {
        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        view.findViewById<EditText>(R.id.host).setText(prefs.getString(PreferenceKey.HOST.value, null))
        view.findViewById<EditText>(R.id.username).setText(prefs.getString(PreferenceKey.USERNAME.value, null))
        view.findViewById<EditText>(R.id.password).setText(prefs.getString(PreferenceKey.PASSWORD.value, null))
        view.findViewById<Switch>(R.id.connector).isChecked =
            prefs.getBoolean(PreferenceKey.SWITCH.value, false)
        view.findViewById<TextView>(R.id.log).text = prefs.getString(PreferenceKey.LOG.value, null)
    }

    private fun savePreferences(view: View) {
        val editor = PreferenceManager.getDefaultSharedPreferences(context).edit()
        editor.putString(PreferenceKey.HOST.value, view.findViewById<EditText>(R.id.host).text.toString())
        editor.putString(PreferenceKey.USERNAME.value, view.findViewById<EditText>(R.id.username).text.toString())
        editor.putString(PreferenceKey.PASSWORD.value, view.findViewById<EditText>(R.id.password).text.toString())
        editor.putBoolean(
            PreferenceKey.SWITCH.value,
            view.findViewById<Switch>(R.id.connector).isChecked
        )
        editor.putString(PreferenceKey.LOG.value, view.findViewById<TextView>(R.id.log).text.toString())

        editor.apply()
    }

    private fun wipeLog(log: TextView) {
        log.text = ""
        val editor = PreferenceManager.getDefaultSharedPreferences(context).edit()
        editor.putString(PreferenceKey.LOG.value, "")
        editor.apply()
    }
}
