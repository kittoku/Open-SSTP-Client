package kittoku.osc.activity

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import kittoku.osc.R
import kittoku.osc.databinding.ActivityAppsBinding
import kittoku.osc.fragment.AppsFragment

class AppsActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "Allowed Apps"
        val binding = ActivityAppsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        supportFragmentManager.beginTransaction().also {
            it.replace(R.id.appsFrame, AppsFragment())
            it.commit()
        }
    }
}
