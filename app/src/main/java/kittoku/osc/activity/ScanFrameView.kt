package kittoku.osc.activity

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.util.AttributeSet
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import androidx.core.content.ContextCompat
import kittoku.osc.R


/** Purple scanner frame: four rounded corners and a moving scan line. */
class ScanFrameView @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null) : View(context, attrs) {
    private val density = resources.displayMetrics.density

    private val cornerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 5 * density
        color = ContextCompat.getColor(context, R.color.qr_accent)
    }

    private val linePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        strokeWidth = 3 * density
        strokeCap = Paint.Cap.ROUND
        color = ContextCompat.getColor(context, R.color.qr_accent_soft)
    }

    private val glowPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        strokeWidth = 12 * density
        strokeCap = Paint.Cap.ROUND
        color = ContextCompat.getColor(context, R.color.qr_accent)
        alpha = 60
    }

    private val cornersPath = Path()
    private val frameRect = RectF()
    private var progress = 0f

    private val animator = ValueAnimator.ofFloat(0f, 1f).apply {
        duration = 2600
        repeatCount = ValueAnimator.INFINITE
        repeatMode = ValueAnimator.REVERSE
        interpolator = AccelerateDecelerateInterpolator()
        addUpdateListener {
            progress = it.animatedValue as Float
            invalidate()
        }
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        if (!animator.isStarted) animator.start()
    }

    override fun onDetachedFromWindow() {
        animator.cancel()
        super.onDetachedFromWindow()
    }

    override fun onDraw(canvas: Canvas) {
        val w = width.toFloat()
        val h = height.toFloat()
        val inset = 18 * density
        val arm = 52 * density
        val radius = 18 * density
        val half = cornerPaint.strokeWidth

        frameRect.set(inset, inset, w - inset, h - inset)

        cornersPath.reset()
        cornersPath.addRect(frameRect.left - half, frameRect.top - half, frameRect.left + arm, frameRect.top + arm, Path.Direction.CW)
        cornersPath.addRect(frameRect.right - arm, frameRect.top - half, frameRect.right + half, frameRect.top + arm, Path.Direction.CW)
        cornersPath.addRect(frameRect.left - half, frameRect.bottom - arm, frameRect.left + arm, frameRect.bottom + half, Path.Direction.CW)
        cornersPath.addRect(frameRect.right - arm, frameRect.bottom - arm, frameRect.right + half, frameRect.bottom + half, Path.Direction.CW)

        canvas.save()
        canvas.clipPath(cornersPath)
        canvas.drawRoundRect(frameRect, radius, radius, cornerPaint)
        canvas.restore()

        val y = inset * 2 + progress * (h - inset * 4)
        canvas.drawLine(inset * 2, y, w - inset * 2, y, glowPaint)
        canvas.drawLine(inset * 2, y, w - inset * 2, y, linePaint)
    }
}
