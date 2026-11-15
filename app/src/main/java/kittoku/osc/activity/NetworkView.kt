package kittoku.osc.activity

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RadialGradient
import android.graphics.Shader
import android.os.SystemClock
import android.provider.Settings
import android.util.AttributeSet
import android.view.View
import kotlin.math.cos
import kotlin.math.exp
import kotlin.math.hypot
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.sin
import kotlin.math.sqrt
import kotlin.random.Random

/**
 * Live network background of the Home screen.
 * IDLE: a quiet drifting mesh. CONNECTING: waves of light run out of the connect button and
 * white sparks flicker on the lines. CONNECTED: one bright pulse ring, then the mesh calms down.
 * It stops drawing by itself when the screen is not visible.
 */
class NetworkView @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null) : View(context, attrs) {

    enum class Mode { IDLE, CONNECTING, CONNECTED }

    /** The connect button: waves start from its centre. */
    var anchor: View? = null

    private val d = resources.displayMetrics.density
    private val baseMs = SystemClock.uptimeMillis()
    private var motion = true

    private var mode = Mode.IDLE
    private var active = true
    private var attached = false
    private var windowVisible = true
    private var running = false

    // ---- nodes ----
    private var n = 0
    private var ox = FloatArray(0)
    private var oy = FloatArray(0)
    private var x = FloatArray(0)
    private var y = FloatArray(0)
    private var rad = FloatArray(0)
    private var phase = FloatArray(0)
    private var link = FloatArray(0)
    private var cyan = BooleanArray(0)
    private var act = FloatArray(0)
    private var energy = FloatArray(0)

    // ---- candidate lines (checked every frame against the real, drifting distance) ----
    private var pc = 0
    private var pa = IntArray(0)
    private var pb = IntArray(0)
    private var lim = FloatArray(0)

    // ---- effects ----
    private class Flash(val a: Int, val b: Int, val t: Long, val dur: Long)

    private val flashes = ArrayList<Flash>()
    private var flashEdges = IntArray(0)
    private var lastPulseMs = 0L
    private var nextWaveMs = 0L
    private var connectedAt = 0L
    private var burstStart = 0L
    private val burstDur = 1.6f

    private var cx = 0f
    private var cy = 0f
    private val loc1 = IntArray(2)
    private val loc2 = IntArray(2)

    private val bgPaint = Paint()
    private val glowPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val line = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
    }
    private val fill = Paint(Paint.ANTI_ALIAS_FLAG)
    private var bgShader: RadialGradient? = null
    private var glowPurple: RadialGradient? = null
    private var glowCyan: RadialGradient? = null

    private val blue = Color.rgb(103, 201, 241)
    private val violet = Color.rgb(163, 107, 255)
    private val white = Color.rgb(228, 246, 255)

    init {
        refreshMotion()
    }

    private fun refreshMotion() {
        motion = try {
            Settings.Global.getFloat(context.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) > 0f
        } catch (e: Exception) {
            true
        }
    }

    // ---- public control ----

    fun setMode(next: Mode, celebrate: Boolean = false) {
        if (next == mode) return
        mode = next
        flashes.clear()
        val now = SystemClock.uptimeMillis()

        when (next) {
            Mode.IDLE -> {
                java.util.Arrays.fill(act, Float.NaN)
                java.util.Arrays.fill(energy, 0f)
                connectedAt = 0L
                burstStart = 0L
            }

            Mode.CONNECTING -> {
                nextWaveMs = 0L
                lastPulseMs = now
            }

            Mode.CONNECTED -> {
                if (celebrate && motion) {
                    connectedAt = now
                    burstStart = now
                }
            }
        }
        updateRunning()
        invalidate()
    }

    /** Called by the Home screen: false while it is not on screen. */
    fun setActive(value: Boolean) {
        active = value
        if (value) refreshMotion()
        updateRunning()
    }

    private fun updateRunning() {
        val should = active && attached && windowVisible
        if (should && !running) {
            running = true
            postInvalidateOnAnimation()
        } else if (!should) {
            running = false
        }
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        attached = true
        updateRunning()
    }

    override fun onDetachedFromWindow() {
        attached = false
        running = false
        super.onDetachedFromWindow()
    }

    override fun onWindowVisibilityChanged(visibility: Int) {
        super.onWindowVisibilityChanged(visibility)
        windowVisible = visibility == VISIBLE
        updateRunning()
    }

    // ---- building the mesh ----

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        bgShader = null
        glowPurple = null
        glowCyan = null
        flashes.clear()
        flashEdges = IntArray(0)
        build(w, h)
    }

    private fun rnd(a: Float, b: Float) = a + Random.nextFloat() * (b - a)

    private fun build(w: Int, h: Int) {
        if (w <= 0 || h <= 0) {
            n = 0
            pc = 0
            return
        }

        val wd = w / d
        val hd = h / d
        val spacing = max(34f, sqrt(wd * hd / 500f))

        val bx = ArrayList<Float>()
        val by = ArrayList<Float>()
        val br = ArrayList<Float>()
        val bp = ArrayList<Float>()
        val bl = ArrayList<Float>()
        val bc = ArrayList<Boolean>()

        var yy = -spacing * 0.7f
        while (yy < hd + spacing) {
            var xx = -spacing * 0.7f
            while (xx < wd + spacing) {
                if (Random.nextFloat() >= 0.14f) {
                    bx.add((xx + rnd(-spacing * 0.8f, spacing * 0.8f)) * d)
                    by.add((yy + rnd(-spacing * 0.8f, spacing * 0.8f)) * d)
                    br.add(rnd(1f, 2.4f) * d)
                    bp.add(rnd(0f, 6.28f))
                    bl.add(rnd(spacing * 1.15f, spacing * 2.7f) * d)
                    bc.add(Random.nextFloat() < 0.56f)
                }
                xx += spacing
            }
            yy += spacing
        }

        n = bx.size
        ox = bx.toFloatArray()
        oy = by.toFloatArray()
        x = ox.copyOf()
        y = oy.copyOf()
        rad = br.toFloatArray()
        phase = bp.toFloatArray()
        link = bl.toFloatArray()
        cyan = bc.toBooleanArray()
        act = FloatArray(n) { Float.NaN }
        energy = FloatArray(n)

        // Lines that could ever exist: the nodes drift at most about 14dp each.
        val margin = 28f * d
        val ta = ArrayList<Int>()
        val tb = ArrayList<Int>()
        val tl = ArrayList<Float>()
        for (i in 0 until n) {
            for (j in i + 1 until n) {
                val l = (link[i] + link[j]) * 0.5f
                val dx = ox[i] - ox[j]
                val dy = oy[i] - oy[j]
                val far = l + margin
                if (dx > far || dx < -far || dy > far || dy < -far) continue
                if (dx * dx + dy * dy < far * far) {
                    ta.add(i)
                    tb.add(j)
                    tl.add(l)
                }
            }
        }
        pc = ta.size
        pa = ta.toIntArray()
        pb = tb.toIntArray()
        lim = tl.toFloatArray()
    }

    // ---- waves of light ----

    private fun sec(ms: Long) = (ms - baseMs) / 1000f

    private fun launchWave(nowMs: Long) {
        if (n == 0) return

        val deg = IntArray(n)
        val valid = BooleanArray(pc)
        var validCount = 0
        for (k in 0 until pc) {
            val a = pa[k]
            val b = pb[k]
            val dx = x[a] - x[b]
            val dy = y[a] - y[b]
            if (dx * dx + dy * dy < lim[k] * lim[k]) {
                valid[k] = true
                validCount++
                deg[a]++
                deg[b]++
            }
        }

        val start = IntArray(n + 1)
        for (i in 0 until n) start[i + 1] = start[i] + deg[i]
        val fillAt = start.copyOf()
        val adj = IntArray(start[n])
        val edges = IntArray(validCount)
        var ei = 0
        for (k in 0 until pc) {
            if (!valid[k]) continue
            val a = pa[k]
            val b = pb[k]
            adj[fillAt[a]++] = b
            adj[fillAt[b]++] = a
            edges[ei++] = k
        }
        flashEdges = edges

        val level = IntArray(n) { -1 }
        val queue = IntArray(n)
        var tail = 0
        val reach = 95f * d
        for (i in 0 until n) {
            if (hypot(x[i] - cx, y[i] - cy) < reach) {
                level[i] = 0
                queue[tail++] = i
            }
        }
        if (tail == 0) {
            var best = 0
            var bd = Float.MAX_VALUE
            for (i in 0 until n) {
                val dd = hypot(x[i] - cx, y[i] - cy)
                if (dd < bd) {
                    bd = dd
                    best = i
                }
            }
            level[best] = 0
            queue[tail++] = best
        }
        var head = 0
        while (head < tail) {
            val u = queue[head++]
            for (e in start[u] until start[u + 1]) {
                val v = adj[e]
                if (level[v] == -1) {
                    level[v] = level[u] + 1
                    queue[tail++] = v
                }
            }
        }

        val order = ArrayList<Int>(n)
        for (i in 0 until tail) order.add(queue[i])
        val rest = (0 until n).filter { level[it] == -1 }.sortedBy { hypot(x[it] - cx, y[it] - cy) }
        order.addAll(rest)

        val batch = max(10, Math.ceil(order.size / 22.0).toInt())
        val nowSec = sec(nowMs)
        var t = nowSec
        var s = 0
        while (s < order.size) {
            val e = min(s + batch, order.size)
            for (k in s until e) act[order[k]] = t + Random.nextFloat() * 0.04f
            t += 0.2f
            s = e
        }
        nextWaveMs = nowMs + ((t - nowSec) * 1000f).toLong() + 1500L
    }

    // ---- drawing ----

    private fun updateCenter() {
        val a = anchor
        if (a != null && a.width > 0 && a.isAttachedToWindow) {
            a.getLocationInWindow(loc1)
            getLocationInWindow(loc2)
            cx = loc1[0] - loc2[0] + a.width / 2f
            cy = loc1[1] - loc2[1] + a.height / 2f
        } else {
            cx = width / 2f
            cy = height * 0.33f
        }
    }

    private fun ensureShaders() {
        val w = width.toFloat()
        val h = height.toFloat()
        if (bgShader == null) {
            val r = hypot(w * 0.5f, h * 0.6f)
            bgShader = RadialGradient(
                w * 0.5f, h * 0.4f, r,
                intArrayOf(Color.rgb(0x15, 0x15, 0x2C), Color.rgb(0x0B, 0x0D, 0x18), Color.rgb(0x07, 0x09, 0x10)),
                floatArrayOf(0f, 0.42f, 1f), Shader.TileMode.CLAMP
            )
        }
        if (glowPurple == null) {
            glowPurple = RadialGradient(
                0f, 0f, 96f * d,
                intArrayOf(Color.argb(46, 163, 107, 255), Color.argb(14, 163, 107, 255), Color.argb(0, 163, 107, 255)),
                floatArrayOf(0f, 0.55f, 1f), Shader.TileMode.CLAMP
            )
            glowCyan = RadialGradient(
                0f, 0f, 96f * d,
                intArrayOf(Color.argb(70, 103, 201, 241), Color.argb(22, 103, 201, 241), Color.argb(0, 103, 201, 241)),
                floatArrayOf(0f, 0.55f, 1f), Shader.TileMode.CLAMP
            )
        }
    }

    private fun stroke(color: Int, alpha: Float, width: Float) {
        line.color = color
        line.alpha = (alpha.coerceIn(0f, 1f) * 255f).toInt()
        line.strokeWidth = width
    }

    override fun onDraw(canvas: Canvas) {
        val nowMs = SystemClock.uptimeMillis()
        val t = sec(nowMs)
        val w = width.toFloat()
        val h = height.toFloat()
        if (w <= 0f || h <= 0f) return

        updateCenter()
        ensureShaders()

        // background
        bgPaint.shader = bgShader
        canvas.drawRect(0f, 0f, w, h, bgPaint)
        bgPaint.shader = null

        // soft light around the button
        canvas.save()
        canvas.translate(cx, cy)
        glowPaint.shader = if (mode == Mode.IDLE) glowPurple else glowCyan
        canvas.drawCircle(0f, 0f, 96f * d, glowPaint)
        glowPaint.shader = null
        canvas.restore()

        // drifting and glow energy of every node
        for (i in 0 until n) {
            if (motion) {
                val p = phase[i]
                x[i] = ox[i] + (sin(t * 0.32f + p) * 10f + cos(t * 0.21f + p) * 4f) * d
                y[i] = oy[i] + (cos(t * 0.28f + p) * 10f + sin(t * 0.23f + p) * 4f) * d
            }
            val a = act[i]
            if (!a.isNaN()) {
                val age = t - a
                energy[i] = if (age > 0f) min(1f, age / 0.05f) * exp(-max(0f, age - 0.05f) * 5.5f) else 0f
            } else {
                energy[i] = 0f
            }
        }

        // brightness right after connecting
        var boost = 1f
        var boosting = false
        if (mode == Mode.CONNECTED && connectedAt != 0L) {
            val bt = (nowMs - connectedAt) / 1000f
            if (bt < 2.5f) {
                boost = 1f + 0.85f * exp(-(bt / 0.55f).pow(1.4f))
                boosting = true
            }
        }

        // while connecting: waves from the button and white sparks on random lines
        if (mode == Mode.CONNECTING && motion && n > 0) {
            if (nowMs >= nextWaveMs) launchWave(nowMs)
            if (nowMs - lastPulseMs > 250 && flashEdges.isNotEmpty()) {
                lastPulseMs = nowMs
                val count = 1 + Random.nextInt(2)
                for (q in 0 until count) {
                    val k = flashEdges[Random.nextInt(flashEdges.size)]
                    flashes.add(Flash(pa[k], pb[k], nowMs, 450L + Random.nextInt(150)))
                }
            }
        }
        var f = flashes.size - 1
        while (f >= 0) {
            if (nowMs - flashes[f].t > flashes[f].dur) flashes.removeAt(f)
            f--
        }

        // lines
        for (k in 0 until pc) {
            val a = pa[k]
            val b = pb[k]
            val dx = x[a] - x[b]
            val dy = y[a] - y[b]
            val l = lim[k]
            if (dx > l || dx < -l || dy > l || dy < -l) continue
            val d2 = dx * dx + dy * dy
            if (d2 >= l * l) continue
            val dist = sqrt(d2)
            val alpha = min(0.35f, (1f - dist / l) * 0.2f * boost)
            stroke(blue, alpha * 0.75f, 0.7f * d)
            canvas.drawLine(x[a], y[a], x[b], y[b], line)

            val ee = min(energy[a], energy[b])
            if (ee > 0.06f) {
                stroke(white, ee * 0.30f, 0.8f * d)
                canvas.drawLine(x[a], y[a], x[b], y[b], line)
            }
        }

        // white sparks
        for (fl in flashes) {
            val age = (nowMs - fl.t).toFloat() / fl.dur
            val alpha = max(0f, 1f - age) * 0.42f
            if (alpha <= 0f) continue
            stroke(white, alpha, 1.05f * d)
            canvas.drawLine(x[fl.a], y[fl.a], x[fl.b], y[fl.b], line)
            fill.color = white
            fill.alpha = (alpha * 255f).toInt()
            canvas.drawCircle(x[fl.a], y[fl.a], 1.7f * d, fill)
            canvas.drawCircle(x[fl.b], y[fl.b], 1.7f * d, fill)
        }

        // nodes
        for (i in 0 until n) {
            val pulse = 0.75f + 0.25f * sin(t * 1.05f + phase[i])
            val c = if (cyan[i]) blue else violet
            fill.color = c
            fill.alpha = (min(1f, 0.22f * pulse * boost) * 255f).toInt()
            canvas.drawCircle(x[i], y[i], rad[i] * 2.8f * pulse * boost, fill)
            fill.color = c
            fill.alpha = (min(1f, 0.85f * boost) * 255f).toInt()
            canvas.drawCircle(x[i], y[i], rad[i] * 0.65f, fill)
            if (energy[i] > 0.06f) {
                fill.color = Color.rgb(228, 245, 255)
                fill.alpha = (energy[i] * 0.3f * 255f).toInt()
                canvas.drawCircle(x[i], y[i], rad[i] * 1.1f, fill)
            }
        }

        // one bright ring when the connection is established
        var bursting = false
        if (mode == Mode.CONNECTED && burstStart != 0L) {
            val age = (nowMs - burstStart) / 1000f
            if (age < burstDur) {
                bursting = true
                val p = age / burstDur
                val ease = 1f - (1f - p).pow(2.2f)
                val radius = ease * max(w, h) * 0.85f
                val pulse = 0.7f + 0.3f * sin(age * 22f)
                val alpha = (1f - p) * (0.35f + 0.35f * pulse)
                stroke(blue, alpha * 0.18f, 26f * d)
                canvas.drawCircle(cx, cy, radius, line)
                stroke(Color.rgb(210, 236, 250), alpha, (1.4f + (1f - p) * 1.8f) * d)
                canvas.drawCircle(cx, cy, radius, line)
            } else {
                burstStart = 0L
            }
        }

        // keep drawing only while the screen is visible; slower when nothing special happens
        if (running && motion) {
            if (mode == Mode.CONNECTING || bursting || boosting) {
                postInvalidateOnAnimation()
            } else {
                postInvalidateDelayed(33)
            }
        }
    }
}
