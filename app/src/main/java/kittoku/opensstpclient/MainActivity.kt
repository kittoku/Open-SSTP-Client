package kittoku.opensstpclient

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import androidx.viewpager2.adapter.FragmentStateAdapter
import com.google.android.material.tabs.TabLayoutMediator
import kittoku.opensstpclient.databinding.ActivityMainBinding
import kittoku.opensstpclient.fragment.HomeFragment
import kittoku.opensstpclient.fragment.SettingFragment


class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "Open SSTP Client: ${BuildConfig.VERSION_NAME}"
        val binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)


        object : FragmentStateAdapter(this) {
            private val homeFragment = HomeFragment()

            private val settingFragment = SettingFragment()

            override fun getItemCount() = 2

            override fun createFragment(position: Int): Fragment {
                return when (position) {
                    0 -> homeFragment
                    1 -> settingFragment
                    else -> throw NotImplementedError()
                }
            }
        }.also {
            binding.pager.adapter = it
        }


        TabLayoutMediator(binding.tabBar, binding.pager) { tab, position ->
            tab.text = when (position) {
                0 -> "HOME"
                1 -> "SETTING"
                else -> throw NotImplementedError()
            }
        }.attach()
    }
}
