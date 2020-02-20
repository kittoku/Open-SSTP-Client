package kittoku.opensstpclient

import android.os.Bundle
import android.preference.PreferenceManager
import android.support.v4.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*


internal val sslMap = mapOf(
    0 to "DEFAULT",
    1 to "SSLv3",
    2 to "TLSv1",
    3 to "TLSv1.1",
    4 to "TLSv1.2"
)


class SettingFragment : Fragment() {
    private val TAG = "SettingFragment"

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? = inflater.inflate(R.layout.fragment_setting, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        val spinner = view.findViewById<Spinner>(R.id.spinner)
        spinner.adapter = ArrayAdapter<String>(
            context!!,
            android.R.layout.simple_spinner_item,
            sslMap.values.toTypedArray()
        ).also {
            it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        val button = view.findViewById<Button>(R.id.button)

        loadPreferences(view)

        button.setOnClickListener {
            savePreferences(view)
            Toast.makeText(context, "The settings have been saved", Toast.LENGTH_SHORT).show()
        }
    }

    private fun loadPreferences(view: View) {
        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        view.findViewById<EditText>(R.id.port)
            .setText(prefs.getString(PreferenceKey.PORT.value, ""))
        view.findViewById<EditText>(R.id.mru)
            .setText(prefs.getString(PreferenceKey.MRU.value, ""))
        view.findViewById<EditText>(R.id.mtu)
            .setText(prefs.getString(PreferenceKey.MTU.value, ""))
        view.findViewById<EditText>(R.id.prefix)
            .setText(prefs.getString(PreferenceKey.PREFIX.value, ""))
        view.findViewById<Spinner>(R.id.spinner).setSelection(
            prefs.getInt(PreferenceKey.SSL.value, 0)
        )
        view.findViewById<CheckBox>(R.id.pap).isChecked =
            prefs.getBoolean(PreferenceKey.PAP.value, true)
        view.findViewById<CheckBox>(R.id.mschapv2).isChecked =
            prefs.getBoolean(PreferenceKey.MSCHAPv2.value, true)
        view.findViewById<CheckBox>(R.id.hvIgnored).isChecked =
            prefs.getBoolean(PreferenceKey.HV_IGNORED.value, false)
        view.findViewById<CheckBox>(R.id.decryptable).isChecked =
            prefs.getBoolean(PreferenceKey.DECRYPTABLE.value, false)
    }

    private fun savePreferences(view: View) {
        val editor = PreferenceManager.getDefaultSharedPreferences(context).edit()
        editor.putString(
            PreferenceKey.PORT.value,
            view.findViewById<EditText>(R.id.port).text.toString()
        )
        editor.putString(
            PreferenceKey.MRU.value,
            view.findViewById<EditText>(R.id.mru).text.toString()
        )
        editor.putString(
            PreferenceKey.MTU.value,
            view.findViewById<EditText>(R.id.mtu).text.toString()
        )
        editor.putString(
            PreferenceKey.PREFIX.value,
            view.findViewById<EditText>(R.id.prefix).text.toString()
        )
        editor.putInt(
            PreferenceKey.SSL.value,
            view.findViewById<Spinner>(R.id.spinner).selectedItemPosition
        )
        editor.putBoolean(PreferenceKey.PAP.value, view.findViewById<CheckBox>(R.id.pap).isChecked)
        editor.putBoolean(
            PreferenceKey.MSCHAPv2.value,
            view.findViewById<CheckBox>(R.id.mschapv2).isChecked
        )
        editor.putBoolean(
            PreferenceKey.HV_IGNORED.value,
            view.findViewById<CheckBox>(R.id.hvIgnored).isChecked
        )
        editor.putBoolean(
            PreferenceKey.DECRYPTABLE.value,
            view.findViewById<CheckBox>(R.id.decryptable).isChecked
        )

        editor.apply()
    }
}
