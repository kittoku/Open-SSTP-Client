package kittoku.osc

import android.app.Dialog
import android.content.SharedPreferences
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.preference.PreferenceManager
import com.google.android.material.card.MaterialCardView
import kittoku.osc.activity.GlassDialog
import kittoku.osc.activity.MainActivity
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue
import kittoku.osc.preference.accessor.setBooleanPrefValue
import kittoku.osc.preference.accessor.setStringPrefValue

internal class DnsPreset(val name: String, val primary: String, val secondary: String, val descRes: Int)

/**
 * Well-known public DNS servers. A choice is stored in the settings the tunnels already read:
 * "use a custom DNS" and its address (the primary), plus [KEY_SECONDARY] for the second address.
 */
internal object DnsPresets {
    const val KEY_SECONDARY = "banafsh_dns_secondary"

    val all = listOf(
        DnsPreset("Cloudflare", "1.1.1.1", "1.0.0.1", R.string.bs_dns_cloudflare),
        DnsPreset("Google DNS", "8.8.8.8", "8.8.4.4", R.string.bs_dns_google),
        DnsPreset("Quad9", "9.9.9.9", "149.112.112.112", R.string.bs_dns_quad9),
        DnsPreset("AdGuard DNS", "94.140.14.14", "94.140.15.15", R.string.bs_dns_adguard),
        DnsPreset("OpenDNS", "208.67.222.222", "208.67.220.220", R.string.bs_dns_opendns),
        DnsPreset("Control D", "76.76.2.0", "76.76.10.0", R.string.bs_dns_controld),
        DnsPreset("Cloudflare Security", "1.1.1.2", "1.0.0.2", R.string.bs_dns_cf_security),
        DnsPreset("Cloudflare Family", "1.1.1.3", "1.0.0.3", R.string.bs_dns_cf_family),
    )

    /** The preset in use; null when the server's own DNS is used or a custom address was typed by hand. */
    fun current(prefs: SharedPreferences): DnsPreset? {
        if (!getBooleanPrefValue(OscPrefKey.DNS_DO_USE_CUSTOM_SERVER, prefs)) return null

        val primary = getStringPrefValue(OscPrefKey.DNS_CUSTOM_ADDRESS, prefs).trim()
        val secondary = prefs.getString(KEY_SECONDARY, "").orEmpty().trim()

        return all.firstOrNull { it.primary == primary && it.secondary == secondary }
    }

    fun usesCustomAddress(prefs: SharedPreferences): Boolean =
        getBooleanPrefValue(OscPrefKey.DNS_DO_USE_CUSTOM_SERVER, prefs) && current(prefs) == null

    /** null: back to the DNS of the server. */
    fun apply(prefs: SharedPreferences, preset: DnsPreset?) {
        if (preset == null) {
            setBooleanPrefValue(false, OscPrefKey.DNS_DO_USE_CUSTOM_SERVER, prefs)
            prefs.edit().remove(KEY_SECONDARY).apply()
        } else {
            setBooleanPrefValue(true, OscPrefKey.DNS_DO_USE_CUSTOM_SERVER, prefs)
            setStringPrefValue(preset.primary, OscPrefKey.DNS_CUSTOM_ADDRESS, prefs)
            prefs.edit().putString(KEY_SECONDARY, preset.secondary).apply()
        }
    }

    /** The addresses the tunnel should use right now (empty: the server decides). */
    fun addresses(prefs: SharedPreferences): List<String> {
        if (!getBooleanPrefValue(OscPrefKey.DNS_DO_USE_CUSTOM_SERVER, prefs)) return emptyList()

        return listOf(
            getStringPrefValue(OscPrefKey.DNS_CUSTOM_ADDRESS, prefs).trim(),
            prefs.getString(KEY_SECONDARY, "").orEmpty().trim()
        ).filter { it.isNotEmpty() }
    }
}

/** The "DNS" window: the server's own DNS first, then the presets. */
internal object DnsDialog {
    fun show(activity: MainActivity) {
        val prefs = PreferenceManager.getDefaultSharedPreferences(activity)
        val current = DnsPresets.current(prefs)
        val usingServerDns = !getBooleanPrefValue(OscPrefKey.DNS_DO_USE_CUSTOM_SERVER, prefs)
        val density = activity.resources.displayMetrics.density

        val container = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        var dialog: Dialog? = null

        fun addRow(title: String, description: String, selected: Boolean, onPick: () -> Unit) {
            val card = activity.layoutInflater.inflate(R.layout.item_protocol, container, false) as MaterialCardView

            card.findViewById<TextView>(R.id.tvProtoName).text = title
            card.findViewById<TextView>(R.id.tvProtoDesc).text = description
            card.findViewById<ImageView>(R.id.ivProtoCheck).visibility =
                if (selected) android.view.View.VISIBLE else android.view.View.INVISIBLE
            card.strokeColor = ContextCompat.getColor(activity, if (selected) R.color.bs_dialog_link else R.color.bs_dialog_stroke)
            card.strokeWidth = ((if (selected) 2 else 1) * density).toInt()

            card.setOnClickListener {
                dialog?.dismiss()
                onPick()
                Toast.makeText(activity, R.string.bs_dns_applied_next, Toast.LENGTH_LONG).show()
            }
            container.addView(card)
        }

        addRow(
            activity.getString(R.string.bs_dns_default_name),
            activity.getString(R.string.bs_dns_default_desc),
            usingServerDns
        ) { DnsPresets.apply(prefs, null) }

        DnsPresets.all.forEach { preset ->
            addRow(
                preset.name,
                "${preset.primary} \u00B7 ${preset.secondary}\n${activity.getString(preset.descRes)}",
                current === preset
            ) { DnsPresets.apply(prefs, preset) }
        }

        if (DnsPresets.usesCustomAddress(prefs)) {
            container.addView(TextView(activity).apply {
                text = activity.getString(R.string.bs_dns_custom_in_use)
                textSize = 12f
                setTextColor(ContextCompat.getColor(activity, R.color.bs_dialog_muted))
                setPadding(0, (10 * density).toInt(), 0, 0)
            })
        }

        dialog = GlassDialog.show(
            activity,
            R.drawable.ic_gd_protocol,
            activity.getString(R.string.bs_dns_title),
            content = container,
            secondaryText = activity.getString(R.string.bs_cancel)
        )
    }
}
