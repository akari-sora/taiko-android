package org.d2rmobile.diagnostics

import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.view.MotionEvent
import android.view.View

/** Draws the shared native controls. GameActivity owns every touch event. */
internal class TouchControlOverlay(private val owner: MainActivity) : View(owner) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private var initialized = false
    private var attached = false

    init {
        tag = "touch-control-overlay"
        isClickable = false
        isLongClickable = false
        isFocusable = false
        importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
        visibility = GONE
        initialized = true
    }

    private fun publishVisibility() {
        if (initialized) nativeSetVisible(owner, attached && isShown && windowVisibility == VISIBLE)
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        attached = true
        publishVisibility()
    }

    override fun onDetachedFromWindow() {
        attached = false
        publishVisibility()
        super.onDetachedFromWindow()
    }

    override fun onVisibilityChanged(changedView: View, visibility: Int) {
        super.onVisibilityChanged(changedView, visibility)
        publishVisibility()
        if (visibility == VISIBLE) postInvalidateOnAnimation()
    }

    override fun onWindowVisibilityChanged(visibility: Int) {
        super.onWindowVisibilityChanged(visibility)
        publishVisibility()
        if (visibility == VISIBLE) postInvalidateOnAnimation()
    }

    override fun onTouchEvent(event: MotionEvent): Boolean = false

    /** The same read-only shared layout/state used for rendering. */
    internal fun controlSnapshot(): FloatArray? = nativeSnapshot(owner)

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        publishVisibility() // Native attach may finish after View attachment.
        val state = controlSnapshot()
        if (state != null && state.size == SNAPSHOT_SIZE && state[0] == 1f && state[1] == 1f) {
            val location = IntArray(2)
            getLocationInWindow(location)
            val saved = canvas.save()
            canvas.translate(state[2] - location[0], state[3] - location[1])
            canvas.scale(state[4], state[4])
            canvas.clipRect(0f, 0f, state[5], state[6])
            val radius = state[14]
            circle(canvas, state[12], state[13], radius, state[15] == 1f)
            val x = state[12] + state[8] / 32767f * radius * .65f
            val y = state[13] - state[9] / 32767f * radius * .65f
            paint.style = Paint.Style.FILL
            paint.color = Color.argb(180, 220, 195, 125)
            canvas.drawCircle(x, y, radius * .32f, paint)
            for (id in 0..12) {
                val at = HEADER + id * RECORD
                if (state[at + 4] != 1f) continue
                val cx = state[at + 1]
                val cy = state[at + 2]
                val r = state[at + 3]
                circle(canvas, cx, cy, r, state[at + 5] == 1f)
                paint.style = Paint.Style.FILL
                paint.color = Color.rgb(235, 220, 176)
                paint.textAlign = Paint.Align.CENTER
                paint.textSize = r * .65f
                val label = if (id == 12) if (state[16] == 1f) "II" else "I" else LABELS[id]
                canvas.drawText(label, cx, cy - (paint.ascent() + paint.descent()) / 2, paint)
            }
            canvas.restoreToCount(saved)
        } else if (state != null && state.size == SNAPSHOT_SIZE && state[5] > 0f && state[5] < state[6]) {
            paint.style = Paint.Style.FILL
            paint.color = Color.rgb(235, 220, 176)
            paint.textAlign = Paint.Align.CENTER
            paint.textSize = 18f * resources.displayMetrics.density
            canvas.drawText("Rotate to landscape", width / 2f, height / 2f, paint)
        }
        if (attached && isShown) postInvalidateDelayed(33)
    }

    private fun circle(canvas: Canvas, x: Float, y: Float, radius: Float, pressed: Boolean) {
        paint.style = Paint.Style.FILL
        paint.color = if (pressed) Color.argb(180, 120, 91, 39) else Color.argb(115, 15, 17, 20)
        canvas.drawCircle(x, y, radius, paint)
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = if (pressed) 2.5f else 1.5f
        paint.color = Color.argb(210, 201, 177, 112)
        canvas.drawCircle(x, y, radius, paint)
    }

    companion object {
        private const val HEADER = 17
        private const val RECORD = 6
        private const val SNAPSHOT_SIZE = HEADER + RECORD * 13
        private val LABELS = arrayOf("A", "B", "X", "Y", "R", "", "←", "↑", "↓", "→", "+", "−")
        init { System.loadLibrary("d2r_diagnostics") }
        @JvmStatic private external fun nativeSetVisible(activity: MainActivity, visible: Boolean): Boolean
        @JvmStatic private external fun nativeSnapshot(activity: MainActivity): FloatArray?
    }
}
