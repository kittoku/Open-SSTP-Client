package kittoku.osc.activity

import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.util.LruCache
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.preference.PreferenceManager
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kittoku.osc.IranApps
import kittoku.osc.R
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getSetPrefValue
import kittoku.osc.preference.accessor.setSetPrefValue
import java.util.concurrent.Executors


/** Apps that connect directly (without the VPN): the Iranian ones are fixed, the others are chosen here. */
class BypassAppsActivity : AppCompatActivity() {
    override fun attachBaseContext(newBase: android.content.Context) {
        super.attachBaseContext(kittoku.osc.LocaleFix.wrap(newBase))
    }

    private class AppItem(val pkg: String, val label: String)

    private sealed class Row {
        class Section(val title: String) : Row()
        class Note(val text: String) : Row()
        class App(val item: AppItem, val iran: Boolean) : Row()
        class IranHeader(val expanded: Boolean) : Row()
    }

    private lateinit var prefs: SharedPreferences
    private lateinit var adapter: AppAdapter
    private lateinit var selected: MutableSet<String>

    private val main = Handler(Looper.getMainLooper())
    private val executor = Executors.newFixedThreadPool(3)
    private val icons = LruCache<String, Drawable>(150)

    private var others: List<AppItem> = emptyList()
    private var iranInstalled: List<AppItem> = emptyList()
    private var query = ""
    private var iranExpanded = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_bypass_apps)

        val root = findViewById<View>(R.id.bpRoot)
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }

        prefs = PreferenceManager.getDefaultSharedPreferences(this)
        selected = getSetPrefValue(OscPrefKey.ROUTE_SELECTED_APPS, prefs).toMutableSet()

        findViewById<View>(R.id.btnBack).setOnClickListener { finish() }

        adapter = AppAdapter()
        findViewById<RecyclerView>(R.id.rvApps).apply {
            layoutManager = LinearLayoutManager(this@BypassAppsActivity)
            adapter = this@BypassAppsActivity.adapter
            itemAnimator = null
        }

        findViewById<EditText>(R.id.etSearch).addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                query = s?.toString().orEmpty()
                rebuild()
            }
        })

        loadApps()
    }

    private fun loadApps() {
        executor.execute {
            val pm = packageManager
            val iranSet = prefs.getStringSet(IranApps.KEY_LIST, null) ?: emptySet()
            val otherList = ArrayList<AppItem>()
            val iranList = ArrayList<AppItem>()

            pm.getInstalledApplications(0).forEach { info ->
                if (info.packageName == packageName) return@forEach
                if (pm.getLaunchIntentForPackage(info.packageName) == null) return@forEach

                val item = AppItem(info.packageName, pm.getApplicationLabel(info).toString())
                if (info.packageName in iranSet) iranList.add(item) else otherList.add(item)
            }

            main.post {
                if (isFinishing || isDestroyed) return@post

                others = otherList
                iranInstalled = iranList.sortedBy { it.label.lowercase() }
                findViewById<View>(R.id.tvLoading).visibility = View.GONE
                rebuild()
            }
        }
    }

    // Apps picked earlier come first; later ticks do not move the rows around.
    private fun rebuild() {
        val q = query.trim().lowercase()
        val matches = { item: AppItem -> q.isEmpty() || item.label.lowercase().contains(q) || item.pkg.lowercase().contains(q) }

        val rows = ArrayList<Row>()
        rows.add(Row.Section(getString(R.string.bs_bp_others)))

        val shown = others.filter(matches).sortedWith(
            compareByDescending<AppItem> { it.pkg in selected }.thenBy { it.label.lowercase() }
        )

        if (shown.isEmpty()) rows.add(Row.Note(getString(R.string.bs_bp_none)))
        shown.forEach { rows.add(Row.App(it, false)) }

        if (iranInstalled.isNotEmpty()) {
            val expanded = iranExpanded || q.isNotEmpty()
            rows.add(Row.IranHeader(expanded))

            if (expanded) iranInstalled.filter(matches).forEach { rows.add(Row.App(it, true)) }
        }

        adapter.submit(rows)
    }

    private fun toggle(pkg: String, checked: Boolean) {
        if (checked) selected.add(pkg) else selected.remove(pkg)
        setSetPrefValue(HashSet(selected), OscPrefKey.ROUTE_SELECTED_APPS, prefs)
    }

    override fun onDestroy() {
        executor.shutdownNow()
        super.onDestroy()
    }

    private inner class AppAdapter : RecyclerView.Adapter<RecyclerView.ViewHolder>() {
        private var rows: List<Row> = emptyList()

        fun submit(newRows: List<Row>) {
            rows = newRows
            notifyDataSetChanged()
        }

        override fun getItemCount() = rows.size

        override fun getItemViewType(position: Int) = when (rows[position]) {
            is Row.Section, is Row.Note -> 0
            is Row.App -> 1
            is Row.IranHeader -> 2
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
            val layout = when (viewType) {
                0 -> R.layout.item_bp_section
                1 -> R.layout.item_bp_app
                else -> R.layout.item_bp_iran_header
            }

            return object : RecyclerView.ViewHolder(LayoutInflater.from(parent.context).inflate(layout, parent, false)) {}
        }

        override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
            val view = holder.itemView

            when (val row = rows[position]) {
                is Row.Section -> view.findViewById<TextView>(R.id.tvSection).apply {
                    text = row.title
                    alpha = 1f
                }

                is Row.Note -> view.findViewById<TextView>(R.id.tvSection).apply {
                    text = row.text
                    alpha = 0.7f
                }

                is Row.IranHeader -> {
                    view.findViewById<View>(R.id.ivChevron).rotation = if (row.expanded) 180f else 0f
                    view.setOnClickListener {
                        iranExpanded = !iranExpanded
                        rebuild()
                    }
                }

                is Row.App -> bindApp(view, row)
            }
        }

        private fun bindApp(view: View, row: Row.App) {
            val pkg = row.item.pkg
            val icon = view.findViewById<ImageView>(R.id.ivIcon)
            val box = view.findViewById<CheckBox>(R.id.cbSelect)

            view.findViewById<TextView>(R.id.tvLabel).text = row.item.label
            view.findViewById<View>(R.id.ivLock).visibility = if (row.iran) View.VISIBLE else View.GONE

            box.setOnCheckedChangeListener(null)
            box.isChecked = row.iran || pkg in selected
            box.isEnabled = !row.iran

            if (row.iran) {
                view.setOnClickListener(null)
                view.isClickable = false
            } else {
                box.setOnCheckedChangeListener { _, checked -> toggle(pkg, checked) }
                view.setOnClickListener { box.isChecked = !box.isChecked }
            }

            icon.tag = pkg
            val cached = icons.get(pkg)

            if (cached != null) {
                icon.setImageDrawable(cached)
            } else {
                icon.setImageDrawable(null)

                executor.execute {
                    val drawable = try {
                        packageManager.getApplicationIcon(pkg)
                    } catch (_: PackageManager.NameNotFoundException) {
                        null
                    }

                    if (drawable != null) {
                        icons.put(pkg, drawable)
                        main.post { if (icon.tag == pkg) icon.setImageDrawable(drawable) }
                    }
                }
            }
        }
    }
}
