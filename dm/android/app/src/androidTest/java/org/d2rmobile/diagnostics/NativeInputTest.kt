package org.d2rmobile.diagnostics

import android.app.AlertDialog
import android.content.Intent
import android.os.SystemClock
import android.test.InstrumentationTestCase
import android.view.InputDevice
import android.view.MotionEvent
import android.view.SurfaceView
import android.view.View
import android.view.ViewGroup
import android.widget.ScrollView
import org.json.JSONObject
import java.io.File

/** OS-injected events traverse the real GameActivity buffer and original touch HLE. */
@Suppress("DEPRECATION")
class NativeInputTest : InstrumentationTestCase() {
    private fun start(): MainActivity = instrumentation.startActivitySync(
        Intent(instrumentation.targetContext, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
    ) as MainActivity

    private fun waitFor(activity: MainActivity, predicate: (JSONObject) -> Boolean): JSONObject {
        val deadline = SystemClock.uptimeMillis() + 10_000
        var last = JSONObject()
        while (SystemClock.uptimeMillis() < deadline) {
            last = JSONObject(activity.runInputDiagnostics(false))
            if (predicate(last)) return last
            SystemClock.sleep(10)
        }
        fail("Native input condition timed out: $last")
        return last
    }

    private fun ready(activity: MainActivity): JSONObject = waitFor(activity) {
        var diagnosticsDone = false
        instrumentation.runOnMainSync {
            diagnosticsDone = activity.window.decorView.findViewWithTag<View>("diagnostics-run")?.isEnabled == true
        }
        diagnosticsDone && it.optBoolean("available") && it.optBoolean("focused") && it.optBoolean("resumed") &&
            it.getJSONObject("viewport").optDouble("width") > 0 &&
            it.getJSONObject("viewport").optDouble("height") > 0 && it.optBoolean("hleResolved")
    }

    private fun descendants(view: View): List<View> = listOf(view) +
        if (view is ViewGroup) (0 until view.childCount).flatMap { descendants(view.getChildAt(it)) } else emptyList()

    private fun exposeSurface(activity: MainActivity): Pair<SurfaceView, List<Pair<View, Int>>> {
        lateinit var result: Pair<SurfaceView, List<Pair<View, Int>>>
        instrumentation.runOnMainSync {
            val views = descendants(activity.window.decorView)
            val surface = views.filterIsInstance<SurfaceView>().single()
            val overlays = views.filterIsInstance<ScrollView>().map { it as View to it.visibility }
            overlays.forEach { it.first.visibility = View.INVISIBLE }
            result = surface to overlays
        }
        instrumentation.waitForIdleSync()
        return result
    }

    private fun restore(overlays: List<Pair<View, Int>>) = instrumentation.runOnMainSync {
        overlays.forEach { it.first.visibility = it.second }
    }

    private fun inject(surface: SurfaceView, viewport: JSONObject, down: Long, action: Int,
                       vararg points: Triple<Int, Float, Float>) {
        val location = IntArray(2)
        instrumentation.runOnMainSync { surface.getLocationOnScreen(location) }
        val properties = points.map { MotionEvent.PointerProperties().apply {
            id = it.first; toolType = MotionEvent.TOOL_TYPE_FINGER
        } }.toTypedArray()
        val coordinates = points.map { point -> MotionEvent.PointerCoords().apply {
            x = location[0] + viewport.getDouble("left").toFloat() + viewport.getDouble("width").toFloat() * point.second
            y = location[1] + viewport.getDouble("top").toFloat() + viewport.getDouble("height").toFloat() * point.third
            pressure = if ((action and MotionEvent.ACTION_MASK) == MotionEvent.ACTION_UP) 0f else 1f
            size = 0.05f
        } }.toTypedArray()
        val event = MotionEvent.obtain(down, SystemClock.uptimeMillis(), action, points.size,
            properties, coordinates, 0, 0, 1f, 1f, 0, 0, InputDevice.SOURCE_TOUCHSCREEN, 0)
        try { instrumentation.sendPointerSync(event) } finally { event.recycle() }
    }

    private fun readAfter(activity: MainActivity, previous: JSONObject, accepted: Long = 1): JSONObject {
        waitFor(activity) { it.optLong("accepted") >= previous.getLong("accepted") + accepted }
        return JSONObject(activity.runInputDiagnostics())
    }

    private fun expectPoint(receipt: JSONObject, index: Int, id: Int, x: Int, y: Int, attr: Int) {
        assertEquals(1, receipt.getInt("statesWritten"))
        assertFalse(receipt.getBoolean("gamePlayable"))
        val point = receipt.getJSONArray("touches").getJSONObject(index)
        assertEquals(id, point.getInt("id"))
        assertTrue("x: $point", kotlin.math.abs(x - point.getInt("x")) <= 1)
        assertTrue("y: $point", kotlin.math.abs(y - point.getInt("y")) <= 1)
        assertEquals(attr, point.getInt("attributes"))
    }

    private fun save(name: String, samples: List<JSONObject>) {
        File(instrumentation.targetContext.filesDir, name).writeText(
            JSONObject().put("syntheticInputOnly", true).put("gamePlayable", false)
                .put("samples", org.json.JSONArray(samples)).toString(2)
        )
    }

    fun testOsMotionEventsReachOriginalTouchHleWithStableFingerSlots() {
        val activity = start()
        val (surface, overlays) = exposeSurface(activity)
        try {
            var before = ready(activity)
            val viewport = before.getJSONObject("viewport")
            val down = SystemClock.uptimeMillis()
            val samples = mutableListOf<JSONObject>()
            inject(surface, viewport, down, MotionEvent.ACTION_DOWN, Triple(7, 0.25f, 0.25f))
            var current = readAfter(activity, before)
            expectPoint(current, 0, 0, 320, 180, 1); samples += current
            before = current
            inject(surface, viewport, down, MotionEvent.ACTION_POINTER_DOWN or (1 shl MotionEvent.ACTION_POINTER_INDEX_SHIFT),
                Triple(7, 0.25f, 0.25f), Triple(23, 0.75f, 0.75f))
            current = readAfter(activity, before)
            expectPoint(current, 0, 0, 320, 180, 0); expectPoint(current, 1, 1, 960, 540, 1); samples += current
            before = current
            inject(surface, viewport, down, MotionEvent.ACTION_MOVE, Triple(23, 0.5f, 0.75f), Triple(7, 0.25f, 0.5f))
            current = readAfter(activity, before)
            expectPoint(current, 0, 0, 320, 360, 0); expectPoint(current, 1, 1, 640, 540, 0); samples += current
            before = current
            inject(surface, viewport, down, MotionEvent.ACTION_POINTER_UP or (1 shl MotionEvent.ACTION_POINTER_INDEX_SHIFT),
                Triple(23, 0.5f, 0.75f), Triple(7, 0.25f, 0.5f))
            current = readAfter(activity, before)
            expectPoint(current, 0, 0, 320, 360, 2); expectPoint(current, 1, 1, 640, 540, 0)
            assertEquals(1, current.getInt("activePointers")); samples += current
            before = current
            inject(surface, viewport, down, MotionEvent.ACTION_UP, Triple(23, 0.5f, 0.75f))
            current = readAfter(activity, before)
            expectPoint(current, 0, 1, 640, 540, 2); samples += current
            assertEquals(0, JSONObject(activity.runInputDiagnostics()).getJSONArray("touches").length())
            save("touch-device-route.json", samples)
        } finally {
            restore(overlays)
            instrumentation.runOnMainSync { activity.finish() }
        }
    }

    fun testCancelFocusLossAndActivityReplacementDoNotReplayTouches() {
        val activity = start()
        val (surface, overlays) = exposeSurface(activity)
        var replacement: MainActivity? = null
        var dialog: AlertDialog? = null
        try {
            var before = ready(activity)
            val viewport = before.getJSONObject("viewport")
            val down = SystemClock.uptimeMillis()
            val samples = mutableListOf<JSONObject>()
            inject(surface, viewport, down, MotionEvent.ACTION_DOWN, Triple(7, 0.5f, 0.5f))
            // Metadata polling does not consume a pending Start before CANCEL.
            before = waitFor(activity) { it.optLong("accepted") > before.getLong("accepted") }
            inject(surface, viewport, down, MotionEvent.ACTION_CANCEL, Triple(7, 0.5f, 0.5f))
            var current = readAfter(activity, before)
            assertEquals(0, current.getJSONArray("touches").length()); samples += current
            before = current
            inject(surface, viewport, SystemClock.uptimeMillis(), MotionEvent.ACTION_DOWN, Triple(7, 0.5f, 0.5f))
            current = readAfter(activity, before)
            expectPoint(current, 0, 0, 640, 360, 1); samples += current
            instrumentation.runOnMainSync { dialog = AlertDialog.Builder(activity).setTitle("Input lifecycle test").create().also { it.show() } }
            waitFor(activity) { !it.optBoolean("focused") && it.optInt("activePointers") == 0 }
            current = JSONObject(activity.runInputDiagnostics())
            assertEquals(0, current.getJSONArray("touches").length()); samples += current
            assertTrue("Focus loss must preserve the HID sampling sequence", current.getLong("sampling") > samples[samples.size - 2].getLong("sampling"))
            instrumentation.runOnMainSync { dialog?.dismiss(); dialog = null }
            before = ready(activity)
            inject(surface, viewport, SystemClock.uptimeMillis(), MotionEvent.ACTION_DOWN, Triple(7, 0.25f, 0.25f))
            current = readAfter(activity, before)
            expectPoint(current, 0, 0, 320, 180, 1); samples += current
            replacement = start()
            val next = ready(replacement!!)
            assertTrue(next.getLong("generation") > current.getLong("generation"))
            assertEquals(0, next.getInt("activePointers"))
            assertFalse(JSONObject(activity.runInputDiagnostics(false)).getBoolean("available"))
            val empty = JSONObject(replacement!!.runInputDiagnostics())
            assertEquals(0, empty.getJSONArray("touches").length()); samples += empty
            save("touch-device-lifecycle.json", samples)
        } finally {
            instrumentation.runOnMainSync { dialog?.dismiss() }
            restore(overlays)
            instrumentation.runOnMainSync { activity.finish(); replacement?.finish() }
        }
    }

    /** Compare the OS window facts with the adapter; do not synthesize callbacks. */
    fun testDialogWindowFocusMatchesNativeBinding() {
        val activity = start()
        var dialog: AlertDialog? = null
        val samples = mutableListOf<JSONObject>()
        fun snapshot(): JSONObject {
            val receipt = JSONObject(activity.runInputDiagnostics(false))
            instrumentation.runOnMainSync {
                receipt.put("activityWindowFocus", activity.hasWindowFocus())
                    .put("decorWindowFocus", activity.window.decorView.hasWindowFocus())
                    .put("dialogWindowFocus", dialog?.window?.decorView?.hasWindowFocus() == true)
                    .put("javaWindowFocus", activity.windowFocusReceipt())
            }
            return receipt
        }
        try {
            ready(activity)
            samples += snapshot()
            instrumentation.runOnMainSync {
                dialog = AlertDialog.Builder(activity).setTitle("Window focus delivery test")
                    .create().also { it.show() }
            }
            val deadline = SystemClock.uptimeMillis() + 10_000
            var current = snapshot()
            while (SystemClock.uptimeMillis() < deadline &&
                (!current.optBoolean("dialogWindowFocus") || current.optBoolean("focused"))) {
                SystemClock.sleep(20)
                current = snapshot()
            }
            samples += current
            assertTrue("Dialog must receive actual window focus: $current", current.getBoolean("dialogWindowFocus"))
            assertFalse("Activity OS window must lose focus: $current", current.getBoolean("activityWindowFocus"))
            assertFalse("Native binding must follow actual Activity window: $current", current.getBoolean("focused"))
            assertEquals(2, current.getInt("oeFocus"))
            instrumentation.runOnMainSync { dialog?.dismiss(); dialog = null }
            ready(activity)
            current = snapshot(); samples += current
            assertTrue(current.getBoolean("activityWindowFocus"))
            assertTrue(current.getBoolean("focused"))
        } finally {
            save("touch-window-focus.json", samples + snapshot())
            instrumentation.runOnMainSync { dialog?.dismiss(); activity.finish() }
        }
    }
}
