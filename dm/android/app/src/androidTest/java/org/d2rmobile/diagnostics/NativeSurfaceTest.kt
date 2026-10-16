package org.d2rmobile.diagnostics

import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.os.SystemClock
import android.test.InstrumentationTestCase
import android.view.SurfaceView
import android.view.View
import android.view.ViewGroup
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Actual guest GPU pixels -> checked readback -> native window -> compositor.
 * Authored shaders/geometry remain distinct from an original D2R game frame. */
@Suppress("DEPRECATION")
class NativeSurfaceTest : InstrumentationTestCase() {
    private val activities = mutableListOf<MainActivity>()
    private val overlays = mutableListOf<Pair<View, Int>>()

    private fun start(): MainActivity = (instrumentation.startActivitySync(
        Intent(instrumentation.targetContext, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
    ) as MainActivity).also { activities.add(it); ready(it) }

    private fun await(label: String, predicate: () -> Boolean) {
        val deadline = SystemClock.uptimeMillis() + 25_000
        while (SystemClock.uptimeMillis() < deadline) {
            if (predicate()) return
            SystemClock.sleep(10)
        }
        fail("Timed out: $label")
    }

    private fun ready(activity: MainActivity) {
        try {
            await("automatic diagnostics") {
                var enabled = false
                instrumentation.runOnMainSync {
                    enabled = activity.window.decorView.findViewWithTag<View>("diagnostics-run")?.isEnabled == true
                }
                enabled
            }
            DiagnosticCoordinator.awaitWorkerQuiescence(activity)
            await("resumed surface") { JSONObject(NativeGraphics.surfaceSnapshot(activity)).optBoolean("available") }
        } catch (failure: AssertionError) {
            captureReadiness(activity, "ready-timeout")
            throw failure
        }
    }

    private fun captureReadiness(activity: MainActivity, label: String) {
        val states = JSONArray()
        (activities + activity).distinct().forEach { candidate ->
            val state = JSONObject().put("identity", System.identityHashCode(candidate))
                .put("isRequested", candidate === activity)
            instrumentation.runOnMainSync {
                val decor = candidate.window.decorView
                val button = decor.findViewWithTag<View>("diagnostics-run")
                state.put("destroyed", candidate.isDestroyed).put("finishing", candidate.isFinishing)
                    .put("windowFocus", candidate.hasWindowFocus()).put("decorFocus", decor.hasWindowFocus())
                    .put("decorAttached", decor.isAttachedToWindow)
                    .put("buttonPresent", button != null).put("buttonEnabled", button?.isEnabled)
                    .put("statusText", decor.findViewWithTag<TextView>("diagnostics-status")?.text?.toString()?.take(4096))
                    .put("windowFocusReceipt", candidate.windowFocusReceipt())
            }
            state.put("input", runCatching { JSONObject(candidate.runInputDiagnostics(false)) }.getOrElse {
                JSONObject().put("error", it.toString().take(4096))
            }).put("surface", runCatching { JSONObject(NativeGraphics.surfaceSnapshot(candidate)) }.getOrElse {
                JSONObject().put("error", it.toString().take(4096))
            })
            states.put(state)
        }
        val report = JSONObject().put("label", label).put("activities", states)
            .put("nativeOwner", runCatching { JSONObject(NativeDiagnosticOwner.sessionStatus()) }.getOrElse {
                JSONObject().put("error", it.toString().take(4096))
            })
        File(activity.filesDir, "surface-readiness-$label.json").writeText(report.toString(2))
    }

    private fun descendants(view: View): List<View> = listOf(view) +
        if (view is ViewGroup) (0 until view.childCount).flatMap { descendants(view.getChildAt(it)) } else emptyList()

    private fun expose(activity: MainActivity): SurfaceView {
        lateinit var surface: SurfaceView
        instrumentation.runOnMainSync {
            val views = descendants(activity.window.decorView)
            surface = views.filterIsInstance<SurfaceView>().single()
            views.filterIsInstance<ScrollView>().forEach {
                overlays.add(it to it.visibility)
                it.visibility = View.INVISIBLE
            }
        }
        instrumentation.waitForIdleSync()
        return surface
    }

    private fun matches(bitmap: Bitmap, x: Int, y: Int, green: Boolean): Boolean {
        if (x !in 0 until bitmap.width || y !in 0 until bitmap.height) return false
        val pixel = bitmap.getPixel(x, y)
        return kotlin.math.abs(Color.red(pixel) - if (green) 0 else 255) <= 3 &&
            kotlin.math.abs(Color.green(pixel) - if (green) 255 else 0) <= 3 && Color.blue(pixel) <= 3
    }

    private fun observe(activity: MainActivity, surface: SurfaceView, name: String): JSONObject {
        val location = IntArray(2)
        var width = 0
        var height = 0
        instrumentation.runOnMainSync {
            surface.getLocationOnScreen(location)
            width = surface.width; height = surface.height
        }
        assertTrue(width > 0 && height > 0)
        val points = listOf(Triple(.65, .65, true), Triple(.10, .10, false), Triple(.90, .65, false))
        var captured: Bitmap? = null
        try {
            await("GPU triangle visible in compositor screenshot") {
                captured?.recycle()
                captured = instrumentation.uiAutomation.takeScreenshot()
                captured?.let { bitmap -> points.all { (u, v, green) ->
                    matches(bitmap, location[0] + (width * u).toInt(), location[1] + (height * v).toInt(), green)
                } } == true
            }
        } finally {
            captured?.let { bitmap ->
                File(activity.filesDir, "$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
                bitmap.recycle()
            }
        }
        return JSONObject().put("screenshot", "$name.png").put("observed", true)
            .put("surfaceLeft", location[0]).put("surfaceTop", location[1])
            .put("surfaceWidth", width).put("surfaceHeight", height)
            .put("source", "actual-guest-GPU-readback")
    }

    private fun draw(activity: MainActivity, surface: SurfaceView, name: String): JSONObject {
        await("current display cadence") {
            JSONObject(NativeGraphics.surfaceSnapshot(activity)).optLong("cadenceSerial") > 0
        }
        val before = JSONObject(NativeGraphics.surfaceSnapshot(activity))
        var nextTick = before
        await("next real display callback") {
            nextTick = JSONObject(NativeGraphics.surfaceSnapshot(activity))
            nextTick.optLong("owner") == before.getLong("owner") &&
                nextTick.optLong("epoch") == before.getLong("epoch") &&
                nextTick.optLong("cadenceSerial") > before.getLong("cadenceSerial") &&
                nextTick.optLong("frameTimeNs") > before.getLong("frameTimeNs")
        }
        val raw = NativeGraphics.runDrawDiagnostics(activity, true)
        File(activity.filesDir, "$name-native.json").writeText(raw)
        val result = JSONObject(raw)
        assertEquals(result.toString(), "PASS", result.getString("status"))
        assertFalse(result.getBoolean("gamePlayable"))
        assertEquals("NOT_RUN", result.getString("originalGame"))
        val presentation = result.getJSONObject("presentation")
        assertTrue(presentation.getBoolean("accepted"))
        assertTrue(presentation.getBoolean("locked"))
        assertTrue(presentation.getBoolean("postSucceeded"))
        assertEquals(before.getLong("owner"), presentation.getLong("owner"))
        assertEquals(before.getLong("epoch"), presentation.getLong("epoch"))
        assertEquals("NOT_RUN", presentation.getString("displayObservation"))
        result.put("screenObservation", observe(activity, surface, name))
        result.put("displayCadence", JSONObject().put("source", "Android-Choreographer-FrameCallback")
            .put("owner", before.getLong("owner")).put("epoch", before.getLong("epoch"))
            .put("firstSerial", before.getLong("cadenceSerial")).put("nextSerial", nextTick.getLong("cadenceSerial"))
            .put("firstTimeNs", before.getLong("frameTimeNs")).put("nextTimeNs", nextTick.getLong("frameTimeNs")))
        return result
    }

    fun testGuestGpuDrawVisibleAndActivityRecovery() = visibleScenario()

    private fun visibleScenario() {
        val first = start()
        val firstSurface = expose(first)
        val reports = JSONArray()
        reports.put(draw(first, firstSurface, "surface-first"))
        reports.put(draw(first, firstSurface, "surface-repeat"))

        val initial = JSONObject(NativeGraphics.surfaceSnapshot(first))
        var resizedWidth = 0
        var resizedHeight = 0
        instrumentation.runOnMainSync {
            resizedWidth = firstSurface.width * 3 / 4
            resizedHeight = firstSurface.height * 2 / 3
            firstSurface.layoutParams = firstSurface.layoutParams.apply {
                width = resizedWidth; height = resizedHeight
            }
        }
        await("real SurfaceView resize") {
            val state = JSONObject(NativeGraphics.surfaceSnapshot(first))
            state.optBoolean("available") && state.optLong("epoch") > initial.getLong("epoch") &&
                state.optInt("width") == resizedWidth && state.optInt("height") == resizedHeight
        }
        reports.put(draw(first, firstSurface, "surface-resized"))

        val old = JSONObject(NativeGraphics.surfaceSnapshot(first))
        instrumentation.runOnMainSync { assertTrue(first.moveTaskToBack(true)) }
        await("background closes presentation") { !JSONObject(NativeGraphics.surfaceSnapshot(first)).optBoolean("available") }
        assertEquals(0L, JSONObject(NativeGraphics.surfaceSnapshot(first)).getLong("cadenceSerial"))
        // startActivitySync waits for onCreate; REORDER_TO_FRONT resumes this
        // existing Activity and correctly does not create another instance.
        instrumentation.runOnMainSync {
            first.startActivity(Intent(instrumentation.targetContext, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT))
        }
        val foreground = first
        ready(foreground)
        val resumed = JSONObject(NativeGraphics.surfaceSnapshot(foreground))
        assertTrue(resumed.getLong("owner") != old.getLong("owner") || resumed.getLong("epoch") > old.getLong("epoch"))
        // The real frontend projects its idle diagnostics mode on resume. This
        // authored Surface scenario must expose its target again afterward.
        reports.put(draw(foreground, expose(foreground), "surface-resumed"))

        val monitor = instrumentation.addMonitor(MainActivity::class.java.name, null, false)
        val replacement: MainActivity
        try {
            instrumentation.runOnMainSync { foreground.recreate() }
            replacement = instrumentation.waitForMonitorWithTimeout(monitor, 25_000) as? MainActivity
                ?: throw AssertionError("Activity replacement did not arrive")
        } finally { instrumentation.removeMonitor(monitor) }
        activities.add(replacement)
        captureReadiness(replacement, "monitor-returned")
        ready(replacement)
        assertFalse(JSONObject(NativeGraphics.surfaceSnapshot(foreground)).optBoolean("receiverMatches"))
        reports.put(draw(replacement, expose(replacement), "surface-recreated"))
        File(replacement.filesDir, "surface-report.json").writeText(
            JSONObject().put("status", "PASS").put("gamePlayable", false).put("originalGame", "NOT_RUN")
                .put("route", "guest-NVN-Vulkan-readback-native-window-compositor")
                .put("phases", reports).toString(2))
    }

    override fun tearDown() {
        instrumentation.runOnMainSync {
            overlays.forEach { (view, visibility) -> view.visibility = visibility }
            activities.forEach { if (!it.isDestroyed) it.finish() }
        }
        super.tearDown()
    }
}
