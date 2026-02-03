package kittoku.osc.activity

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import kittoku.osc.R
import kittoku.osc.databinding.ActivityBlankBinding
import kittoku.osc.fragment.AppsFragment
import kittoku.osc.fragment.ProfilesFragment
import kittoku.osc.fragment.SaveCertFragment


internal const val BLANK_ACTIVITY_TYPE_PROFILES = 0
internal const val BLANK_ACTIVITY_TYPE_APPS = 1
internal const val BLANK_ACTIVITY_TYPE_SAVE_CERT = 2

internal const val EXTRA_KEY_TYPE = "TYPE"
internal const val EXTRA_KEY_CERT = "CERT"
internal const val EXTRA_KEY_FILENAME = "FILENAME"

class BlankActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val fragment: Fragment

        when (intent.extras!!.getInt(EXTRA_KEY_TYPE)) {
            BLANK_ACTIVITY_TYPE_PROFILES -> {
                title = "Profiles"
                fragment = ProfilesFragment()
            }

            BLANK_ACTIVITY_TYPE_APPS -> {
                title = "Allowed Apps"
                fragment = AppsFragment()
            }

            BLANK_ACTIVITY_TYPE_SAVE_CERT -> {
                fragment = SaveCertFragment(intent)
            }

            else -> throw NotImplementedError(intent.toString())
        }

        val binding = ActivityBlankBinding.inflate(layoutInflater)
        binding.root.fitsSystemWindows = true
        setContentView(binding.root)

        supportFragmentManager.beginTransaction().also {
            it.replace(R.id.blank, fragment)
            it.commit()
        }
    }
}
