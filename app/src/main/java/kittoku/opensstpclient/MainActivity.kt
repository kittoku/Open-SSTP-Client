package kittoku.opensstpclient

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.tabs.TabLayout
import kotlinx.android.synthetic.main.activity_main.*


internal enum class PreferenceKey(val value: String) {
    HOST("HOST"),
    USERNAME("USERNAME"),
    PASSWORD("PASSWORD"),
    PORT("PORT"),
    MRU("MRU"),
    MTU("MTU"),
    PREFIX("PREFIX"),
    SSL("SSL"),
    PAP("PAP"),
    MSCHAPv2("MSCHAPv2"),
    HV_IGNORED("HV_IGNORED"),
    DECRYPTABLE("DECRYPTABLE"),
    LOG("LOG"),
    SWITCH("SWITCH"),
    CERTIFICATE("CERTIFICATE"),
    IPv4("IPv4"),
    IPv6("IPv6"),
    ONLY_LAN("ONLY_LAN")
}

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        title = "Open SSTP Client: ${BuildConfig.VERSION_NAME}"

        tabBar.addTab(tabBar.newTab().setText("HOME"), 0)
        tabBar.addTab(tabBar.newTab().setText("SETTING"), 1)

        val fm = supportFragmentManager
        val homeFragment = HomeFragment()
        val settingFragment = SettingFragment()

        fun update(tab: Int) {
            fm.beginTransaction().also {
                it.replace(container.id, if (tab == 0) homeFragment else settingFragment)
                it.commit()
            }
        }

        update(0)

        tabBar.addOnTabSelectedListener(
            object : TabLayout.OnTabSelectedListener {
                override fun onTabSelected(tab: TabLayout.Tab?) {
                    update(tab?.position ?: 0)
                }

                override fun onTabUnselected(tab: TabLayout.Tab?) {}

                override fun onTabReselected(tab: TabLayout.Tab?) {}
            }
        )
    }
}
