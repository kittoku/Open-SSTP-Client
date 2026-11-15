package kittoku.osc.activity

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Typeface
import android.text.util.Linkify
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.AppCompatCheckBox
import androidx.core.content.ContextCompat
import androidx.preference.PreferenceManager
import kittoku.osc.BuildConfig
import kittoku.osc.R
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getStringPrefValue

internal const val KEY_HIDE_WELCOME = "hide_welcome"
internal const val KEY_LAST_SEEN_VERSION = "last_seen_version"

internal fun showWelcomeDialog(activity: AppCompatActivity) {
    showInfoDialog(activity, activity.getString(R.string.bs_welcome_title), Kind.WELCOME)
}

internal fun showAboutDialog(activity: AppCompatActivity) {
    showInfoDialog(activity, activity.getString(R.string.bs_about_title), Kind.ABOUT)
}

/** Shown once after an update: what is new first, then the description of the app. */
internal fun showWhatsNewDialog(activity: AppCompatActivity) {
    showInfoDialog(activity, activity.getString(R.string.bs_whats_new_title, ltr(BuildConfig.VERSION_NAME)), Kind.WHATS_NEW)
}

private enum class Kind { WELCOME, ABOUT, WHATS_NEW }

// Keeps a version number like 1.2.0 in the right order inside Persian text.
private fun ltr(text: String) = "\u2066$text\u2069"

private fun showInfoDialog(activity: AppCompatActivity, title: String, kind: Kind) {
    val density = activity.resources.displayMetrics.density
    val dp = { value: Int -> (value * density).toInt() }
    val textColor = ContextCompat.getColor(activity, R.color.bs_dialog_text)
    val linkColor = ContextCompat.getColor(activity, R.color.bs_dialog_link)

    val container = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }

    fun addHeading(text: String) {
        container.addView(
            TextView(activity).apply {
                this.text = text
                textSize = 15f
                setTextColor(linkColor)
                setTypeface(typeface, Typeface.BOLD)
                textAlignment = View.TEXT_ALIGNMENT_VIEW_START
            },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
                .apply { topMargin = if (container.childCount == 0) 0 else dp(18); bottomMargin = dp(4) }
        )
    }

    fun addBody(text: String, links: Boolean = false) {
        container.addView(
            TextView(activity).apply {
                this.text = text
                textSize = 14f
                setTextColor(textColor)
                textAlignment = View.TEXT_ALIGNMENT_VIEW_START
                setLineSpacing(0f, 1.25f)
                if (links) {
                    Linkify.addLinks(this, Linkify.WEB_URLS)
                    setLinkTextColor(linkColor)
                }
            },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        )
    }

    if (kind != Kind.ABOUT) {
        if (kind == Kind.WELCOME) addHeading(activity.getString(R.string.bs_whats_new_title, ltr(BuildConfig.VERSION_NAME)))
        addBody(activity.getString(R.string.bs_whats_new_list))
        container.addView(
            View(activity).apply { setBackgroundColor(linkColor); alpha = 0.3f },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(1)).apply { topMargin = dp(16); bottomMargin = dp(14) }
        )
    }

    addBody(activity.getString(R.string.bs_welcome_message), links = true)
    addHeading(activity.getString(R.string.bs_features_title_short))
    addBody(activity.getString(R.string.bs_features_list))

    if (kind == Kind.ABOUT) {
        container.addView(
            TextView(activity).apply {
                text = activity.getString(R.string.bs_credits)
                textSize = 12f
                alpha = 0.75f
                setTextColor(textColor)
                layoutDirection = View.LAYOUT_DIRECTION_LTR
                gravity = android.view.Gravity.CENTER
            },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(18) }
        )
    }

    val checkBox = AppCompatCheckBox(activity).apply {
        text = activity.getString(R.string.bs_dont_show_again)
        setTextColor(textColor)
        textAlignment = View.TEXT_ALIGNMENT_VIEW_START
    }

    if (kind == Kind.WELCOME) {
        container.addView(
            checkBox,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(12) }
        )
    }

    GlassDialog.show(
        activity,
        if (kind == Kind.ABOUT) R.drawable.ic_gd_info else R.drawable.ic_gd_update,
        title,
        content = container,
        primaryText = activity.getString(R.string.bs_close),
        cancelable = kind != Kind.WELCOME,
        onClose = {
            if (kind == Kind.WELCOME && checkBox.isChecked) {
                activity.getSharedPreferences("banafsh_ui", Context.MODE_PRIVATE)
                    .edit().putBoolean(KEY_HIDE_WELCOME, true).apply()
            }
        }
    )
}

internal fun showLogDialog(activity: AppCompatActivity) {
    val prefs = PreferenceManager.getDefaultSharedPreferences(activity)
    val text = getStringPrefValue(OscPrefKey.HOME_STATUS, prefs).ifEmpty { activity.getString(R.string.bs_log_empty) }
    val density = activity.resources.displayMetrics.density

    val body = TextView(activity).apply {
        this.text = text
        textSize = 13f
        setTextIsSelectable(true)
        setPadding((24 * density).toInt(), (16 * density).toInt(), (24 * density).toInt(), (8 * density).toInt())
    }

    AlertDialog.Builder(activity)
        .setTitle(R.string.bs_log_title)
        .setView(ScrollView(activity).apply { addView(body) })
        .setPositiveButton(R.string.bs_copy) { _, _ ->
            val manager = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            manager.setPrimaryClip(ClipData.newPlainText("Banafsh-sstp log", text))
            Toast.makeText(activity, R.string.bs_copied, Toast.LENGTH_SHORT).show()
        }
        .setNegativeButton(R.string.bs_close, null)
        .show()
}
