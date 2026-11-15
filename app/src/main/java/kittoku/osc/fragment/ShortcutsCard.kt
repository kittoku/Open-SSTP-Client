package kittoku.osc.fragment

import android.content.Context
import android.graphics.drawable.Drawable
import android.os.Handler
import android.os.Looper
import android.util.LruCache
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.CheckedTextView
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.preference.PreferenceManager
import kittoku.osc.IranApps
import kittoku.osc.R

/** The "app shortcuts" card on Home: up to 5 foreign apps that are opened with one tap. */
internal class ShortcutsCard(private val fragment: Fragment, root: View) {
    private class AppEntry(val pkg: String, val label: String)

    private val row = root.findViewById<LinearLayout>(R.id.shortcutRow)
    private val empty = root.findViewById<TextView>(R.id.tvShortcutEmpty)
    private val icons = LruCache<String, Drawable>(120)

    init {
        root.findViewById<View>(R.id.btnEditShortcuts).setOnClickListener { edit() }
    }

    private fun ctx(): Context? = fragment.context

    private fun saved(context: Context): List<String> {
        val raw = context.getSharedPreferences(UI, Context.MODE_PRIVATE).getString(KEY, null)
        return raw?.split(',')?.filter { it.isNotBlank() } ?: DEFAULTS
    }

    private fun dp(context: Context, value: Int) = (value * context.resources.displayMetrics.density).toInt()

    /** Shows the chosen apps that are installed. */
    fun refresh() {
        val context = ctx() ?: return
        val pm = context.packageManager
        row.removeAllViews()

        var shown = 0
        for (pkg in saved(context)) {
            if (shown >= MAX) break
            val launch = pm.getLaunchIntentForPackage(pkg) ?: continue
            val info = try {
                pm.getApplicationInfo(pkg, 0)
            } catch (e: Exception) {
                continue
            }

            val cell = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER_HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                setPadding(dp(context, 2), dp(context, 8), dp(context, 2), dp(context, 4))
                isClickable = true
                isFocusable = true
                setBackgroundResource(android.R.drawable.list_selector_background)
                setOnClickListener { fragment.startActivity(launch) }
            }
            val icon = ImageView(context).apply {
                layoutParams = LinearLayout.LayoutParams(dp(context, 46), dp(context, 46))
                setImageDrawable(pm.getApplicationIcon(info))
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            }
            val name = TextView(context).apply {
                layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).also {
                    it.topMargin = dp(context, 6)
                }
                text = pm.getApplicationLabel(info)
                textSize = 11f
                alpha = 0.85f
                maxLines = 1
                ellipsize = android.text.TextUtils.TruncateAt.END
                gravity = Gravity.CENTER
            }
            cell.addView(icon)
            cell.addView(name)
            row.addView(cell)
            shown++
        }

        empty.visibility = if (shown == 0) View.VISIBLE else View.GONE
        row.visibility = if (shown == 0) View.GONE else View.VISIBLE
    }

    // ---- editing ----

    private fun edit() {
        val context = ctx() ?: return
        val appContext = context.applicationContext
        val main = Handler(Looper.getMainLooper())

        Thread {
            val pm = appContext.packageManager
            val iran = PreferenceManager.getDefaultSharedPreferences(appContext)
                .getStringSet(IranApps.KEY_LIST, null) ?: emptySet()

            val apps = pm.getInstalledApplications(0)
                .filter { it.packageName != appContext.packageName }
                .filter { it.packageName !in iran }
                .filter { pm.getLaunchIntentForPackage(it.packageName) != null }
                .map { AppEntry(it.packageName, pm.getApplicationLabel(it).toString()) }
                .sortedBy { it.label.lowercase() }

            main.post { if (fragment.isAdded) showPicker(apps) }
        }.start()
    }

    private fun showPicker(all: List<AppEntry>) {
        val context = ctx() ?: return
        val pm = context.packageManager
        val chosen = saved(context)

        // Apps chosen earlier come first.
        val apps = all.sortedWith(compareByDescending<AppEntry> { it.pkg in chosen }.thenBy { it.label.lowercase() })
        val size = dp(context, 36)

        val list = ListView(context)
        val adapter = object : ArrayAdapter<AppEntry>(context, android.R.layout.simple_list_item_multiple_choice, apps) {
            override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                val view = super.getView(position, convertView, parent) as CheckedTextView
                val app = apps[position]
                view.text = app.label

                var icon = icons.get(app.pkg)
                if (icon == null) {
                    icon = try {
                        pm.getApplicationIcon(app.pkg)
                    } catch (e: Exception) {
                        null
                    }
                    if (icon != null) icons.put(app.pkg, icon)
                }
                icon?.setBounds(0, 0, size, size)
                view.setCompoundDrawablesRelative(icon, null, null, null)
                view.compoundDrawablePadding = dp(context, 12)
                return view
            }
        }
        list.adapter = adapter
        list.choiceMode = ListView.CHOICE_MODE_MULTIPLE
        apps.forEachIndexed { index, app -> if (app.pkg in chosen) list.setItemChecked(index, true) }
        list.onItemClickListener = AdapterView.OnItemClickListener { _, _, position, _ ->
            if (list.isItemChecked(position) && list.checkedItemCount > MAX) {
                list.setItemChecked(position, false)
                Toast.makeText(context, R.string.bs_sc_max, Toast.LENGTH_SHORT).show()
            }
        }

        AlertDialog.Builder(context).also {
            it.setTitle(R.string.bs_sc_pick)
            it.setView(list)
            it.setPositiveButton(R.string.bs_save) { _, _ ->
                val checked = HashSet<String>()
                for (i in apps.indices) if (list.isItemChecked(i)) checked.add(apps[i].pkg)

                // Keep the old order; new apps go to the end.
                val result = chosen.filter { pkg -> pkg in checked } + apps.map { a -> a.pkg }.filter { pkg -> pkg in checked && pkg !in chosen }
                context.getSharedPreferences(UI, Context.MODE_PRIVATE).edit().putString(KEY, result.take(MAX).joinToString(",")).apply()
                refresh()
            }
            it.setNeutralButton(R.string.bs_sc_reset) { _, _ ->
                context.getSharedPreferences(UI, Context.MODE_PRIVATE).edit().remove(KEY).apply()
                refresh()
            }
            it.setNegativeButton(R.string.bs_cancel) { _, _ -> }
            it.show()
        }
    }

    companion object {
        private const val UI = "banafsh_ui"
        private const val KEY = "shortcut_apps"
        private const val MAX = 5

        // Telegram, Instagram, WhatsApp, YouTube, Chrome
        private val DEFAULTS = listOf(
            "org.telegram.messenger",
            "com.instagram.android",
            "com.whatsapp",
            "com.google.android.youtube",
            "com.android.chrome"
        )
    }
}
