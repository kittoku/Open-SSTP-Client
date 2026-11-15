package kittoku.osc.activity

import android.content.Context
import android.util.AttributeSet
import android.widget.ScrollView


/** A ScrollView that never grows taller than maxHeightPx. */
class MaxHeightScrollView @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null) : ScrollView(context, attrs) {
    var maxHeightPx: Int = Int.MAX_VALUE

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val spec = if (maxHeightPx != Int.MAX_VALUE) {
            MeasureSpec.makeMeasureSpec(maxHeightPx, MeasureSpec.AT_MOST)
        } else {
            heightMeasureSpec
        }

        super.onMeasure(widthMeasureSpec, spec)
    }
}
