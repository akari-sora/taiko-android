package org.d2rmobile.diagnostics

import android.app.AlertDialog
import android.app.UiAutomation
import android.content.Intent
import android.graphics.Bitmap
import android.os.Build
import android.os.SystemClock
import android.test.InstrumentationTestCase
import android.util.AtomicFile
import android.view.InputDevice
import android.view.MotionEvent
import android.view.SurfaceView
import android.view.View
import android.view.ViewGroup
import android.widget.ScrollView
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** OS touch -> existing GameActivity collector -> original dm_tc -> actual
 * ARM64 SDK Npad fixture. The overlay draws only. No original gameplay claim. */
@Suppress("DEPRECATION")
class NativeTouchControlsTest : InstrumentationTestCase() {
    private data class Point(val id: Int, val x: Float, val y: Float)
    private lateinit var activity: MainActivity
    private lateinit var overlay: TouchControlOverlay
    private lateinit var surface: SurfaceView
    private val steps = JSONArray()
    private var token = 0L
    private var downTime = 0L

    private fun waitFor(label: String, predicate: () -> Boolean) {
        val until = SystemClock.uptimeMillis() + 15_000
        while (SystemClock.uptimeMillis() < until) {
            if (predicate()) return
            SystemClock.sleep(10)
        }
        fail("Timed out: $label")
    }

    private fun descendants(view: View): List<View> = listOf(view) + if (view is ViewGroup)
        (0 until view.childCount).flatMap { descendants(view.getChildAt(it)) } else emptyList()

    private fun snapshot(): FloatArray {
        var value: FloatArray? = null
        instrumentation.runOnMainSync { value = overlay.controlSnapshot() }
        return value ?: error("Active Activity has no controls snapshot")
    }

    private fun start() {
        val monitor = instrumentation.addMonitor(MainActivity::class.java.name, null, false)
        try {
            activity = instrumentation.startActivitySync(Intent(instrumentation.targetContext, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)) as MainActivity
            waitFor("native Activity ready") {
                // Rotation can replace the instance returned by startActivitySync.
                // Select the real OS-created replacement, then read its native
                // owner state; a retired Activity must continue to be rejected.
                val latest = monitor.lastActivity as? MainActivity
                if (latest != null && !latest.isDestroyed) activity = latest
                val input = JSONObject(activity.runInputDiagnostics(false))
                !activity.isDestroyed && input.optBoolean("focused") && input.optBoolean("resumed") &&
                    input.optBoolean("windowAvailable") && input.optInt("nativeWidth") > input.optInt("nativeHeight")
            }
        } finally { instrumentation.removeMonitor(monitor) }
        instrumentation.runOnMainSync { DiagnosticCoordinator.cancel(activity) }
        DiagnosticCoordinator.awaitWorkerQuiescence(activity)
        instrumentation.runOnMainSync {
            val views = descendants(activity.window.decorView)
            overlay = views.filterIsInstance<TouchControlOverlay>().single()
            surface = views.filterIsInstance<SurfaceView>().single()
            views.filterIsInstance<ScrollView>().forEach { it.visibility = View.INVISIBLE }
            overlay.visibility = View.VISIBLE
            surface.isFocusableInTouchMode = true
            surface.requestFocus()
        }
        waitFor("visible controls activated") { snapshot()[1] == 1f }
        token = NativeController.begin()
        assertTrue("Actual Npad fixture unavailable", token != 0L)
        neutral(poll("initial neutral"))
    }

    private fun inject(action: Int, vararg points: Point) {
        val current = snapshot()
        val origin = IntArray(2)
        instrumentation.runOnMainSync { surface.getLocationOnScreen(origin) }
        val before = JSONObject(activity.runInputDiagnostics(false)).getLong("accepted")
        if (action == MotionEvent.ACTION_DOWN) downTime = SystemClock.uptimeMillis()
        val properties = points.map { MotionEvent.PointerProperties().apply {
            id = it.id; toolType = MotionEvent.TOOL_TYPE_FINGER
        } }.toTypedArray()
        val coordinates = points.map { point -> MotionEvent.PointerCoords().apply {
            x = origin[0] + current[2] + point.x * current[4]
            y = origin[1] + current[3] + point.y * current[4]
            pressure = 1f; size = .05f
        } }.toTypedArray()
        val event = MotionEvent.obtain(downTime, SystemClock.uptimeMillis(), action, points.size,
            properties, coordinates, 0, 0, 1f, 1f, 0, 0, InputDevice.SOURCE_TOUCHSCREEN, 0)
        try { instrumentation.sendPointerSync(event) } finally { event.recycle() }
        waitFor("GameActivity accepts touch action=$action") {
            JSONObject(activity.runInputDiagnostics(false)).getLong("accepted") > before
        }
    }

    private fun poll(label: String): JSONObject {
        val guest = JSONObject(NativeController.poll(token))
        assertEquals("PASS", guest.getString("status"))
        assertFalse(guest.getBoolean("gamePlayable"))
        assertFalse(guest.getJSONObject("adapter").getBoolean("productComplete"))
        assertEquals("DIAGNOSTIC_RAW", guest.getJSONObject("adapter").getString("mode"))
        val ui = snapshot()
        steps.put(JSONObject().put("step", label).put("guest", guest)
            .put("controls", JSONArray(ui.toList()))
            .put("raw", JSONObject(activity.runInputDiagnostics(true, token))))
        return guest.getJSONObject("full")
    }

    private fun neutral(state: JSONObject) {
        assertEquals(0L, state.getLong("buttons"))
        val axes = state.getJSONArray("axes")
        for (i in 0..3) assertEquals(0, axes.getInt(i))
    }

    private fun retained(name: String, body: () -> Unit) {
        val report = JSONObject().put("passed", false).put("steps", steps)
            .put("gamePlayable", false).put("originalGameVerified", false)
            .put("route", "OS touch -> GameActivity -> original dm_tc -> actual ARM64 SDK Npad fixture")
            .put("device", JSONObject().put("model", Build.MODEL).put("fingerprint", Build.FINGERPRINT))
        try {
            assertTrue("Cannot rotate actual OS display for landscape controls", instrumentation.uiAutomation.setRotation(UiAutomation.ROTATION_FREEZE_90))
            start(); body(); report.put("passed", true)
        }
        catch (error: Throwable) {
            report.put("error", error.toString())
            report.put("failureOwner", runCatching { JSONObject(NativeDiagnosticOwner.sessionStatus()) }.getOrNull())
            if (::activity.isInitialized) {
                report.put("failureInput", runCatching { JSONObject(activity.runInputDiagnostics(false)) }.getOrNull())
                instrumentation.runOnMainSync {
                    report.put("activityDestroyed", activity.isDestroyed)
                        .put("orientation", activity.resources.configuration.orientation)
                        .put("rotation", activity.windowManager.defaultDisplay.rotation)
                        .put("windowFocus", activity.window.decorView.hasWindowFocus())
                    if (::surface.isInitialized) {
                        val location = IntArray(2)
                        surface.getLocationOnScreen(location)
                        report.put("surface", JSONObject().put("x", location[0]).put("y", location[1])
                            .put("width", surface.width).put("height", surface.height))
                    }
                }
                if (::overlay.isInitialized) report.put("failureControls", runCatching { JSONArray(snapshot().toList()) }.getOrNull())
            }
            val screenshot = instrumentation.uiAutomation.takeScreenshot()
            if (screenshot != null) File(instrumentation.targetContext.filesDir, "$name-failure.png").outputStream().use {
                screenshot.compress(Bitmap.CompressFormat.PNG, 100, it)
                screenshot.recycle()
            }
            throw error
        }
        finally {
            if (::overlay.isInitialized) instrumentation.runOnMainSync { overlay.visibility = View.GONE }
            if (token != 0L) {
                val closed = NativeController.end(token)
                report.put("cleanupClosed", closed)
                assertTrue("Controller fixture cleanup failed", closed)
            }
            val file = AtomicFile(File(instrumentation.targetContext.filesDir, name))
            val stream = file.startWrite()
            try { stream.write(report.toString(2).toByteArray()); file.finishWrite(stream) }
            catch (error: Throwable) { file.failWrite(stream); throw error }
            if (::activity.isInitialized) instrumentation.runOnMainSync { activity.finish() }
            instrumentation.uiAutomation.setRotation(UiAutomation.ROTATION_UNFREEZE)
        }
    }

    fun testVisibleControlsIndependentFingersAndRealRawTouch() = retained("touch-controls-os-npad.json") {
        val ui = snapshot()
        assertEquals(0f, ui[17 + 5 * 6 + 4]) // Portal requires the absent native binding consumer.
        val radius = ui[14]
        val joy = Point(7, ui[12], ui[13])
        val moved = Point(7, joy.x + radius * .8f, joy.y - radius * .8f)
        val skill = Point(9, ui[17 + 6 + 1], ui[17 + 6 + 2]) // Original B target.
        inject(MotionEvent.ACTION_DOWN, joy)
        inject(MotionEvent.ACTION_MOVE, moved)
        val move = poll("original diagonal stick")
        assertTrue(move.getJSONArray("axes").getInt(0) > 0)
        assertTrue(move.getJSONArray("axes").getInt(1) > 0)
        inject(MotionEvent.ACTION_POINTER_DOWN or (1 shl MotionEvent.ACTION_POINTER_INDEX_SHIFT), moved, skill)
        waitFor("stationary original skill settle") { snapshot()[7].toInt() and 2 != 0 }
        val both = poll("independent stick and stationary B skill")
        assertEquals(2L, both.getLong("buttons"))
        assertTrue(both.getJSONArray("axes").getInt(0) > 0)
        assertEquals(2, JSONObject(activity.runInputDiagnostics(true, token)).getJSONArray("touches").length())
        val aim = Point(9, skill.x - radius, skill.y - radius)
        inject(MotionEvent.ACTION_MOVE, moved, aim)
        val directed = poll("independent right-stick drag aim")
        assertTrue(directed.getJSONArray("axes").getInt(2) < 0)
        assertTrue(directed.getJSONArray("axes").getInt(3) > 0)
        val screenshot = instrumentation.uiAutomation.takeScreenshot()
        if (screenshot != null) File(instrumentation.targetContext.filesDir, "touch-controls-visible.png").outputStream().use {
            screenshot.compress(Bitmap.CompressFormat.PNG, 100, it)
            screenshot.recycle()
        }
        inject(MotionEvent.ACTION_CANCEL, moved, aim)
        neutral(poll("OS CANCEL clears buttons, axes and pending edges"))
        neutral(poll("cancel stays neutral"))
    }

    fun testHideAndDialogFocusRetireUnsampledPresses() = retained("touch-controls-owner-cancel.json") {
        val ui = snapshot()
        val main = Point(3, ui[18], ui[19])
        inject(MotionEvent.ACTION_DOWN, main)
        instrumentation.runOnMainSync { overlay.visibility = View.GONE }
        neutral(poll("hidden overlay cancels unconsumed A"))
        neutral(poll("hidden overlay leaves no short-tap latch"))
        instrumentation.runOnMainSync { overlay.visibility = View.VISIBLE }
        waitFor("controls restored") { snapshot()[1] == 1f }
        inject(MotionEvent.ACTION_DOWN, main)
        lateinit var dialog: AlertDialog
        instrumentation.runOnMainSync {
            dialog = AlertDialog.Builder(activity).setMessage("Touch controls focus cancellation").setPositiveButton("OK", null).show()
        }
        waitFor("dialog receives window focus") { !JSONObject(activity.runInputDiagnostics(false)).getBoolean("focused") }
        neutral(poll("real dialog focus loss cancels unread A"))
        instrumentation.runOnMainSync { dialog.dismiss() }
        waitFor("focus restored") { JSONObject(activity.runInputDiagnostics(false)).getBoolean("focused") }
        neutral(poll("focus restore cannot replay old A"))
    }
}
