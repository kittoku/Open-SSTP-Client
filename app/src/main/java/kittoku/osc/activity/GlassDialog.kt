package kittoku.osc.activity

import android.app.Activity
import android.app.Dialog
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.os.Build
import android.view.LayoutInflater
import android.view.View
import android.view.WindowManager
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import com.google.android.material.button.MaterialButton
import kittoku.osc.R


/** The app's own translucent dialog, used instead of the plain Android one. */
internal object GlassDialog {
    /** onClose gets true when the dialog was closed with the main button. */
    fun show(
        activity: Activity,
        iconRes: Int,
        title: String,
        body: CharSequence? = null,
        content: View? = null,
        primaryText: String? = null,
        onPrimary: (() -> Unit)? = null,
        secondaryText: String? = null,
        onSecondary: (() -> Unit)? = null,
        cancelable: Boolean = true,
        onClose: ((Boolean) -> Unit)? = null
    ): Dialog {
        val dialog = Dialog(activity, R.style.BsGlassDialog)
        val view = LayoutInflater.from(dialog.context).inflate(R.layout.dialog_glass, null)
        val metrics = activity.resources.displayMetrics

        view.findViewById<ImageView>(R.id.gdIcon).setImageResource(iconRes)
        view.findViewById<TextView>(R.id.gdTitle).text = title

        val bodyView = view.findViewById<TextView>(R.id.gdBody)
        if (body != null) bodyView.text = body else bodyView.visibility = View.GONE
        content?.let { view.findViewById<LinearLayout>(R.id.gdContent).addView(it) }

        view.findViewById<MaxHeightScrollView>(R.id.gdScroll).maxHeightPx = (metrics.heightPixels * 0.5f).toInt()

        var primaryClicked = false
        val primary = view.findViewById<MaterialButton>(R.id.gdPrimary)
        val secondary = view.findViewById<MaterialButton>(R.id.gdSecondary)

        if (primaryText != null) {
            primary.text = primaryText
            primary.setOnClickListener {
                primaryClicked = true
                dialog.dismiss()
                onPrimary?.invoke()
            }
        } else {
            primary.visibility = View.GONE
        }

        if (secondaryText != null) {
            secondary.text = secondaryText
            secondary.setOnClickListener {
                dialog.dismiss()
                onSecondary?.invoke()
            }
        } else {
            secondary.visibility = View.GONE
        }

        dialog.setContentView(view)
        dialog.setCancelable(cancelable)
        dialog.setOnDismissListener { onClose?.invoke(primaryClicked) }
        dialog.show()

        dialog.window?.let { window ->
            window.setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            window.setDimAmount(0.55f)

            val margin = (20 * metrics.density).toInt()
            val maxWidth = (380 * metrics.density).toInt()
            window.setLayout(minOf(metrics.widthPixels - 2 * margin, maxWidth), WindowManager.LayoutParams.WRAP_CONTENT)

            if (Build.VERSION.SDK_INT >= 31) {
                window.addFlags(WindowManager.LayoutParams.FLAG_BLUR_BEHIND)
                window.attributes = window.attributes.also { it.blurBehindRadius = 24 }
            }
        }

        return dialog
    }
}
