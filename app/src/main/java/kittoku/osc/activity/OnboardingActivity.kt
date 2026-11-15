package kittoku.osc.activity

import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import kittoku.osc.R

/**
 * The intro shown once, on the first launch: a few short pages, "skip" on every page,
 * "start" on the last one. Whoever used the app before can skip it at once.
 */
class OnboardingActivity : AppCompatActivity() {

    companion object {
        const val KEY_DONE = "onboarding_done"
    }

    private class Page(val logo: Boolean, val emoji: String, val title: Int, val body: Int)

    private val pages = listOf(
        Page(true, "", R.string.bs_ob1_title, R.string.bs_ob1_body),
        Page(false, "\uD83D\uDEE1\uFE0F", R.string.bs_ob2_title, R.string.bs_ob2_body),
        Page(false, "\uD83E\uDDED", R.string.bs_ob3_title, R.string.bs_ob3_body),
        Page(false, "\u26A1", R.string.bs_ob4_title, R.string.bs_ob4_body),
        Page(false, "\uD83C\uDDEE\uD83C\uDDF7", R.string.bs_ob5_title, R.string.bs_ob5_body),
    )

    private var index = 0

    private lateinit var host: FrameLayout
    private lateinit var dots: LinearLayout
    private lateinit var btnSkip: MaterialButton
    private lateinit var btnNext: MaterialButton

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_onboarding)

        host = findViewById(R.id.pageHost)
        dots = findViewById(R.id.dots)
        btnSkip = findViewById(R.id.btnSkip)
        btnNext = findViewById(R.id.btnNext)

        index = savedInstanceState?.getInt("index", 0) ?: 0

        btnSkip.setOnClickListener { finishIntro() }
        btnNext.setOnClickListener {
            if (index < pages.lastIndex) show(index + 1, animate = true) else finishIntro()
        }

        // Back leaves the intro like "skip" does, so it never comes back.
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                finishIntro()
            }
        })

        buildDots()
        show(index, animate = false)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt("index", index)
    }

    private fun finishIntro() {
        getSharedPreferences("banafsh_ui", MODE_PRIVATE).edit().putBoolean(KEY_DONE, true).apply()
        finish()
    }

    private fun buildDots() {
        val density = resources.displayMetrics.density

        dots.removeAllViews()
        pages.forEach { _ ->
            val dot = View(this)
            val params = LinearLayout.LayoutParams((8 * density).toInt(), (8 * density).toInt())
            params.marginStart = (4 * density).toInt()
            params.marginEnd = (4 * density).toInt()
            dots.addView(dot, params)
        }
    }

    private fun updateDots() {
        val density = resources.displayMetrics.density

        for (i in 0 until dots.childCount) {
            val dot = dots.getChildAt(i)
            val selected = i == index

            dot.setBackgroundResource(if (selected) R.drawable.bg_dot_on else R.drawable.bg_dot_off)
            dot.layoutParams = (dot.layoutParams as LinearLayout.LayoutParams).apply {
                width = ((if (selected) 22 else 8) * density).toInt()
            }
        }
    }

    private fun show(newIndex: Int, animate: Boolean) {
        index = newIndex

        val page = pages[index]
        val view = layoutInflater.inflate(R.layout.item_onboarding, host, false)

        view.findViewById<View>(R.id.obLogo).visibility = if (page.logo) View.VISIBLE else View.GONE
        view.findViewById<TextView>(R.id.obEmoji).apply {
            text = page.emoji
            visibility = if (page.logo) View.GONE else View.VISIBLE
        }
        view.findViewById<TextView>(R.id.obTitle).setText(page.title)
        view.findViewById<TextView>(R.id.obBody).apply {
            setText(page.body)
            gravity = if (index == 0) Gravity.CENTER_HORIZONTAL else Gravity.START
        }

        val last = index == pages.lastIndex
        btnNext.setText(if (last) R.string.bs_ob_start else R.string.bs_ob_next)
        btnSkip.visibility = if (last) View.INVISIBLE else View.VISIBLE
        updateDots()

        if (!animate || host.childCount == 0) {
            host.removeAllViews()
            host.addView(view)
            return
        }

        // A short cross-fade: the old page fades out, the new one fades in.
        val old = host.getChildAt(0)
        view.alpha = 0f
        host.addView(view)

        old.animate().alpha(0f).setDuration(140).withEndAction { host.removeView(old) }.start()
        view.animate().alpha(1f).setDuration(220).start()
    }
}
