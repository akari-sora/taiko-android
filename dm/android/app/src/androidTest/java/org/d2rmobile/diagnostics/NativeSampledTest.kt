package org.d2rmobile.diagnostics

import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Build
import android.os.SystemClock
import android.test.InstrumentationTestCase
import android.util.AtomicFile
import android.view.View
import android.view.ViewGroup
import android.view.SurfaceView
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Authored host leaf on the real guest stack; actual NVN/Vulkan/Surface route. */
@Suppress("DEPRECATION")
class NativeSampledTest : InstrumentationTestCase() {
    private fun descendants(view: View): List<View> = listOf(view) +
        if (view is ViewGroup) (0 until view.childCount).flatMap { descendants(view.getChildAt(it)) } else emptyList()

    private fun observeWindow(activity: MainActivity, surface: SurfaceView, frame: Int) {
        val colors = if (frame == 0) listOf(Color.RED, Color.GREEN, Color.BLUE, Color.YELLOW)
            else listOf(Color.CYAN, Color.MAGENTA, Color.WHITE, Color.BLACK)
        val points = listOf(
            Triple("clamp-top-left", 10 to 10, colors[0]), Triple("clamp-top-right", 53 to 10, colors[1]),
            Triple("clamp-bottom-left", 10 to 53, colors[2]), Triple("clamp-bottom-right", 53 to 53, colors[3]),
            Triple("nearest-left", 30 to 24, colors[0]), Triple("nearest-right", 33 to 24, colors[1]),
            Triple("outside-draw", 2 to 2, Color.BLACK)
        )
        val started = SystemClock.uptimeMillis()
        val deadline = started + 5_000
        val receipt = JSONObject().put("sourcekind", "AuthoredHostLeaf+AuthoredTranslatorFixture").put("scanout", "NOT_PROVEN")
            .put("screenshot", "sampled-compositor-$frame.png").put("tolerance", 3).put("sourceWidth", 64)
            .put("sourceHeight", 64).put("crop", JSONArray(listOf(0, 0, 0, 0)))
        var captured: Bitmap? = null
        var matched = false
        var attempts = 0
        try {
            while (!matched && SystemClock.uptimeMillis() < deadline) {
                val location = IntArray(2)
                var width = 0
                var height = 0
                var exposed = false
                instrumentation.runOnMainSync {
                    surface.getLocationOnScreen(location)
                    width = surface.width; height = surface.height
                    exposed = surface.isShown &&
                        !activity.window.decorView.findViewWithTag<View>("diagnostics-scroll").isShown &&
                        !activity.window.decorView.findViewWithTag<View>("touch-control-overlay").isShown
                }
                captured?.recycle()
                captured = instrumentation.uiAutomation.takeScreenshot()
                val bitmap = captured
                val samples = JSONArray()
                matched = bitmap != null && exposed && width > 0 && height > 0
                for ((name, source, expected) in points) {
                    // Sample the center of a known interior source pixel using
                    // the real SurfaceView bounds in screenshot coordinates.
                    val x = location[0] + ((source.first + 0.5) * width / 64).toInt()
                    val y = location[1] + ((source.second + 0.5) * height / 64).toInt()
                    val inBounds = bitmap != null && x in 0 until bitmap.width && y in 0 until bitmap.height
                    val actual = if (inBounds) bitmap!!.getPixel(x, y) else 0
                    val channelsMatch = inBounds && kotlin.math.abs(Color.red(actual) - Color.red(expected)) <= 3 &&
                        kotlin.math.abs(Color.green(actual) - Color.green(expected)) <= 3 &&
                        kotlin.math.abs(Color.blue(actual) - Color.blue(expected)) <= 3 &&
                        kotlin.math.abs(Color.alpha(actual) - Color.alpha(expected)) <= 3
                    matched = matched && channelsMatch
                    samples.put(JSONObject().put("name", name).put("sourceX", source.first).put("sourceY", source.second)
                        .put("screenX", x).put("screenY", y).put("inBounds", inBounds).put("matched", channelsMatch)
                        .put("expectedRgba", JSONArray(listOf(Color.red(expected), Color.green(expected), Color.blue(expected), Color.alpha(expected))))
                        .put("actualRgba", JSONArray(listOf(Color.red(actual), Color.green(actual), Color.blue(actual), Color.alpha(actual)))))
                }
                attempts++
                receipt.put("surfaceLeft", location[0]).put("surfaceTop", location[1]).put("surfaceWidth", width)
                    .put("surfaceHeight", height).put("surfaceExposed", exposed).put("samples", samples)
                    .put("screenshotWidth", bitmap?.width ?: 0).put("screenshotHeight", bitmap?.height ?: 0)
                if (!matched) SystemClock.sleep(20)
            }
        } finally {
            receipt.put("status", if (matched) "PASS" else "FAIL").put("matched", matched)
                .put("attempts", attempts).put("elapsedMs", SystemClock.uptimeMillis() - started)
            val visualFile = AtomicFile(File(activity.filesDir, "sampled-visual-$frame.json"))
            val visualStream = visualFile.startWrite()
            try { visualStream.write((receipt.toString(2) + "\n").toByteArray()); visualFile.finishWrite(visualStream) }
            catch (error: Throwable) { visualFile.failWrite(visualStream); throw error }
            try {
                captured?.let { bitmap ->
                    val screenshotFile = AtomicFile(File(activity.filesDir, "sampled-compositor-$frame.png"))
                    val imageStream = screenshotFile.startWrite()
                    try {
                        check(bitmap.compress(Bitmap.CompressFormat.PNG, 100, imageStream))
                        screenshotFile.finishWrite(imageStream)
                    } catch (error: Throwable) { screenshotFile.failWrite(imageStream); throw error }
                }
            } finally { captured?.recycle() }
        }
        assertTrue("Actual sampled NVN pixels not visible: $receipt", matched)
    }

    fun testActualSampledTextureThroughNvnAndWindow() {
        val activity = instrumentation.startActivitySync(
            Intent(instrumentation.targetContext, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        ) as MainActivity
        val executor = Executors.newSingleThreadExecutor()
        var running: java.util.concurrent.Future<String>? = null
        try {
            val deadline = SystemClock.uptimeMillis() + 20_000
            var ready = false
            while (!ready && SystemClock.uptimeMillis() < deadline) {
                instrumentation.runOnMainSync {
                    ready = activity.window.decorView.findViewWithTag<View>("diagnostics-run")?.isEnabled == true
                }
                if (!ready) SystemClock.sleep(10)
            }
            assertTrue("Automatic diagnostics did not finish", ready)
            DiagnosticCoordinator.awaitWorkerQuiescence(activity)
            lateinit var surface: SurfaceView
            instrumentation.runOnMainSync {
                val decor = activity.window.decorView
                surface = descendants(decor).filterIsInstance<SurfaceView>().single()
                decor.findViewWithTag<View>("diagnostics-scroll").visibility = View.INVISIBLE
                assertTrue("Actual native Surface is hidden", surface.isShown)
                assertFalse("Controls cover GPU pixels", decor.findViewWithTag<View>("touch-control-overlay").isShown)
            }
            instrumentation.waitForIdleSync()
            val result = executor.submit(Callable { NativeGraphics.runSampledDiagnostics() })
            running = result
            for (frame in 0..1) {
                var observation: JSONObject? = null
                val frameDeadline = SystemClock.uptimeMillis() + 20_000
                while (SystemClock.uptimeMillis() < frameDeadline) {
                    val value = JSONObject(NativeGraphics.sampledFrameSnapshot())
                    if (value.getBoolean("active") && value.getInt("frame") == frame + 1) { observation = value; break }
                    if (result.isDone) throw AssertionError("Sampled path ended before frame $frame: ${result.get()}")
                    SystemClock.sleep(10)
                }
                val observed = observation ?: throw AssertionError("No actual sampled Surface post for frame $frame")
                assertFalse(NativeGraphics.acknowledgeSampledFrame(observed.getLong("id") + 1, frame + 1))
                try { observeWindow(activity, surface, frame) }
                finally { assertTrue(NativeGraphics.acknowledgeSampledFrame(observed.getLong("id"), frame + 1)) }
            }
            val raw = result.get(30, TimeUnit.SECONDS)
            val report = JSONObject(raw).put("device", JSONObject().put("model", Build.MODEL)
                .put("apiLevel", Build.VERSION.SDK_INT).put("fingerprint", Build.FINGERPRINT))
            val reportFile = AtomicFile(File(activity.filesDir, "sampled-report.json"))
            val stream = reportFile.startWrite()
            try { stream.write((report.toString(2) + "\n").toByteArray()); reportFile.finishWrite(stream) }
            catch (error: Throwable) { reportFile.failWrite(stream); throw error }
            assertEquals(report.toString(), "PASS", report.getString("status"))
            assertEquals("AndroidNVNSampledDraw", report.getString("suite"))
            assertEquals("NOT_RUN", report.getString("originalGame"))
            assertEquals("NOT_RUN", report.getString("originalArmGameEntry"))
            assertFalse(report.getBoolean("gamePlayable"))
            assertTrue(report.getBoolean("ownedGuestStackOutputs"))
            assertEquals(2L, report.getLong("successfulPresents"))
            assertEquals(5L, report.getLong("gpuSubmits"))
            assertEquals(5L, report.getLong("gpuCompleted"))
            assertEquals(2L, report.getLong("gpuDraws"))
            assertEquals(0L, report.getLong("validationErrors"))
            val frames = report.getJSONArray("frames")
            assertEquals(2, frames.length())
            var previous = 0L
            for (frame in 0..1) {
                val value = frames.getJSONObject(frame)
                for (key in listOf("sourceUpdated", "publicationHeld", "retentionPassed", "pixelsPassed",
                        "guardsPassed", "acceptedAndPosted", "compositorAcknowledged")) assertTrue(value.toString(), value.getBoolean(key))
                assertTrue(value.getLong("uploadFence") > previous)
                assertTrue(value.getLong("drawFence") > value.getLong("uploadFence"))
                assertTrue(value.getLong("completedFence") >= value.getLong("drawFence"))
                previous = value.getLong("completedFence")
            }
            assertFalse(frames.getJSONObject(0).getString("rgbaSha256") == frames.getJSONObject(1).getString("rgbaSha256"))
            val checks = report.getJSONArray("checks")
            assertTrue(checks.length() > 0)
            for (i in 0 until checks.length()) assertEquals(checks.getJSONObject(i).toString(), "PASS", checks.getJSONObject(i).getString("status"))
            assertEquals("None", JSONObject(NativeDiagnosticOwner.sessionStatus()).getString("role"))
        } finally {
            val cleanupDeadline = SystemClock.uptimeMillis() + 25_000
            while (running?.isDone == false && SystemClock.uptimeMillis() < cleanupDeadline) {
                val value = JSONObject(NativeGraphics.sampledFrameSnapshot())
                if (value.getBoolean("active") && value.getInt("frame") > 0)
                    NativeGraphics.acknowledgeSampledFrame(value.getLong("id"), value.getInt("frame"))
                SystemClock.sleep(10)
            }
            executor.shutdown()
            executor.awaitTermination(30, TimeUnit.SECONDS)
            instrumentation.runOnMainSync { activity.finish() }
        }
    }
}
