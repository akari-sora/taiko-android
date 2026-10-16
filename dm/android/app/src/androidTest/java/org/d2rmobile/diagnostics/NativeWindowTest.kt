package org.d2rmobile.diagnostics

import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Build
import android.os.SystemClock
import android.test.InstrumentationTestCase
import android.util.AtomicFile
import android.view.View
import android.view.MotionEvent
import android.view.InputDevice
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
class NativeWindowTest : InstrumentationTestCase() {
    private fun descendants(view: View): List<View> = listOf(view) +
        if (view is ViewGroup) (0 until view.childCount).flatMap { descendants(view.getChildAt(it)) } else emptyList()

    private fun observeWindow(activity: MainActivity, surface: SurfaceView) {
        val points = listOf(
            Triple("red", 16 to 8, Color.RED), Triple("green", 48 to 8, Color.GREEN),
            Triple("blue", 16 to 36, Color.BLUE), Triple("yellow", 48 to 36, Color.YELLOW),
            Triple("cyan-marker", 8 to 10, Color.CYAN)
        )
        val started = SystemClock.uptimeMillis()
        val deadline = started + 5_000
        val receipt = JSONObject().put("sourcekind", "AuthoredHostLeaf").put("scanout", "NOT_PROVEN")
            .put("screenshot", "window-compositor.png").put("tolerance", 3).put("sourceWidth", 64)
            .put("sourceHeight", 48).put("crop", JSONArray(listOf(0, 0, 0, 0)))
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
                    val y = location[1] + ((source.second + 0.5) * height / 48).toInt()
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
            val visualFile = AtomicFile(File(activity.filesDir, "window-visual.json"))
            val visualStream = visualFile.startWrite()
            try { visualStream.write((receipt.toString(2) + "\n").toByteArray()); visualFile.finishWrite(visualStream) }
            catch (error: Throwable) { visualFile.failWrite(visualStream); throw error }
            try {
                captured?.let { bitmap ->
                    val screenshotFile = AtomicFile(File(activity.filesDir, "window-compositor.png"))
                    val imageStream = screenshotFile.startWrite()
                    try {
                        check(bitmap.compress(Bitmap.CompressFormat.PNG, 100, imageStream))
                        screenshotFile.finishWrite(imageStream)
                    } catch (error: Throwable) { screenshotFile.failWrite(imageStream); throw error }
                }
            } finally { captured?.recycle() }
        }
        assertTrue("Authored NVN window pixels not visible: $receipt", matched)
    }

    fun testActualNvnWindowOnGuestStack() {
        val activity = instrumentation.startActivitySync(
            Intent(instrumentation.targetContext, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        ) as MainActivity
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
                assertTrue("Native GameActivity SurfaceView is hidden", surface.isShown)
                assertFalse("Touch controls cover the authored frame", decor.findViewWithTag<View>("touch-control-overlay").isShown)
            }
            instrumentation.waitForIdleSync()
            val raw = NativeGraphics.runWindowDiagnostics()
            val device = JSONObject().put("model", Build.MODEL).put("apiLevel", Build.VERSION.SDK_INT)
                .put("fingerprint", Build.FINGERPRINT)
            val reportFile = AtomicFile(File(instrumentation.targetContext.filesDir, "window-report.json"))
            val stream = reportFile.startWrite()
            try {
                stream.write((raw.trimEnd().dropLast(1) + ",\"device\":" + device + "}\n").toByteArray())
                reportFile.finishWrite(stream)
            } catch (error: Throwable) { reportFile.failWrite(stream); throw error }
            val report = JSONObject(raw)
            assertEquals(report.toString(), "PASS", report.getString("status"))
            assertEquals("AndroidNVNWindow", report.getString("suite"))
            assertEquals("AuthoredHostLeaf", report.getString("sourcekind"))
            assertEquals("NOT_RUN", report.getString("originalGame"))
            assertEquals("NOT_RUN", report.getString("originalArmGameEntry"))
            assertEquals("NOT_RUN", report.getString("originalImportRelocations"))
            assertEquals("NOT_PROVEN", report.getString("scanout"))
            assertFalse(report.getBoolean("gamePlayable"))
            assertTrue(report.getBoolean("ownedGuestStackOutputs"))
            for (key in listOf("loadGeneration", "bindingEpoch", "viBinding", "oeEpoch", "surfaceOwner",
                    "surfaceEpoch", "cadenceSerial", "frameTimeNs")) assertTrue(key, report.getLong(key) > 0)
            assertEquals(4L, report.getLong("successfulPresents"))
            assertEquals(5L, report.getLong("gpuSubmits"))
            assertEquals(5L, report.getLong("gpuCompleted"))
            assertEquals(0L, report.getLong("validationErrors"))
            assertEquals(0x140000L, report.getLong("poolOffset"))
            assertEquals(0xc0000L, report.getLong("poolBytes"))
            assertEquals(report.getLong("surfacePostsBefore") + 4, report.getLong("surfacePostsAfter"))
            assertEquals(report.getLong("surfaceAcceptedBefore") + 4, report.getLong("surfaceAcceptedAfter"))
            val frames = report.getJSONArray("frames")
            assertEquals(4, frames.length())
            var previousFence = 0L
            var previousTick = 0L
            var revision = 0L
            val imageHash = "bdb096a32a5510e1b77f7fc84ffdd7c8b23eae6e96802b3631c2aadf559cc33d"
            for (i in 0 until frames.length()) {
                val frame = frames.getJSONObject(i)
                assertEquals(i % 2, frame.getInt("slot"))
                assertEquals(if (i == 1 || i == 2) 1 else 0, frame.getInt("interval"))
                assertEquals(if (i % 2 == 0) "linear" else "block-linear", frame.getString("layout"))
                assertTrue(frame.toString(), frame.getBoolean("pixelsPassed"))
                assertTrue(frame.toString(), frame.getBoolean("clearPixelsPassed"))
                assertTrue(frame.toString(), frame.getBoolean("acceptedAndPosted"))
                assertEquals((i + 1).toLong(), frame.getLong("successfulPresents"))
                assertEquals(report.getLong("surfaceOwner"), frame.getLong("surfaceOwner"))
                assertEquals(report.getLong("surfaceEpoch"), frame.getLong("surfaceEpoch"))
                if (i == 0) revision = frame.getLong("windowRevision")
                assertTrue(revision > 0)
                assertEquals(revision, frame.getLong("windowRevision"))
                assertTrue(frame.getLong("renderFence") > previousFence)
                assertTrue(frame.getLong("completedFence") >= frame.getLong("renderFence"))
                previousFence = frame.getLong("renderFence")
                if (i == 0) assertTrue(frame.getLong("dependencyFence") > 0)
                else assertEquals(0L, frame.getLong("dependencyFence"))
                if (frame.getInt("interval") == 1) {
                    assertTrue(frame.getLong("cadenceSerial") > previousTick)
                    previousTick = frame.getLong("cadenceSerial")
                }
                assertEquals("ff0000ff00ff00ff0000ffffffff00ff", frame.getString("cornerRgbaHex"))
                assertEquals(imageHash, frame.getString("publishedRgbaSha256"))
                assertEquals(if (i == 2) "[8,6,40,30]" else "[0,0,0,0]", frame.getJSONArray("crop").toString())
            }
            val checks = report.getJSONArray("checks")
            assertEquals(15, checks.length())
            for (i in 0 until checks.length()) {
                val check = checks.getJSONObject(i)
                assertEquals(check.toString(), "PASS", check.getString("status"))
            }
            instrumentation.waitForIdleSync()
            observeWindow(activity, surface)
            assertEquals("None", JSONObject(NativeDiagnosticOwner.sessionStatus()).getString("role"))
        } finally { instrumentation.runOnMainSync { activity.finish() } }
    }

    private fun awaitCondition(label: String, predicate: () -> Boolean) {
        val deadline = SystemClock.uptimeMillis() + 20_000
        while (SystemClock.uptimeMillis() < deadline) {
            if (predicate()) return
            SystemClock.sleep(10)
        }
        fail("Timed out: $label")
    }

    private fun exposeSampledSurface(activity: MainActivity): SurfaceView {
        lateinit var surface: SurfaceView
        instrumentation.runOnMainSync {
            val decor = activity.window.decorView
            surface = descendants(decor).filterIsInstance<SurfaceView>().single()
            decor.findViewWithTag<View>("diagnostics-scroll").visibility = View.INVISIBLE
            assertFalse(decor.findViewWithTag<View>("touch-control-overlay").isShown)
        }
        instrumentation.waitForIdleSync()
        return surface
    }

    private fun observeSampledSurface(activity: MainActivity, surface: SurfaceView, frame: Int) {
        val expected = if (frame == 0) listOf(Color.RED, Color.GREEN, Color.BLUE, Color.YELLOW)
            else listOf(Color.CYAN, Color.MAGENTA, Color.WHITE, Color.BLACK)
        val points = listOf(16 to 16, 48 to 16, 16 to 48, 48 to 48, 2 to 2)
        val samples = JSONArray()
        var bitmap: Bitmap? = null
        var matched = false
        try {
            awaitCondition("same NVN window frame $frame in compositor") {
                val location = IntArray(2)
                var width = 0
                var height = 0
                instrumentation.runOnMainSync {
                    surface.getLocationOnScreen(location)
                    width = surface.width; height = surface.height
                }
                bitmap?.recycle()
                bitmap = instrumentation.uiAutomation.takeScreenshot()
                val image = bitmap
                while (samples.length() > 0) samples.remove(samples.length() - 1)
                matched = image != null && width > 0 && height > 0
                for ((i, point) in points.withIndex()) {
                    val x = location[0] + ((point.first + .5) * width / 64).toInt()
                    val y = location[1] + ((point.second + .5) * height / 64).toInt()
                    val inBounds = image != null && x in 0 until image.width && y in 0 until image.height
                    val actual = if (inBounds) image!!.getPixel(x, y) else 0
                    val color = if (i < 4) expected[i] else Color.BLACK
                    val match = inBounds && listOf(Color.red(actual) - Color.red(color),
                        Color.green(actual) - Color.green(color), Color.blue(actual) - Color.blue(color),
                        Color.alpha(actual) - Color.alpha(color)).all { kotlin.math.abs(it) <= 3 }
                    samples.put(JSONObject().put("x", x).put("y", y).put("expected", color)
                        .put("actual", actual).put("matched", match))
                    matched = matched && match
                }
                matched
            }
        } finally {
            File(activity.filesDir, "window-recreate-visual-$frame.json").writeText(JSONObject()
                .put("status", if (matched) "PASS" else "FAIL").put("sourcekind", "AuthoredTranslatorFixture")
                .put("scanout", "NOT_PROVEN").put("samples", samples).toString(2))
            bitmap?.let { image ->
                try { File(activity.filesDir, "window-recreate-compositor-$frame.png").outputStream().use {
                    check(image.compress(Bitmap.CompressFormat.PNG, 100, it))
                } } finally { image.recycle() }
            }
        }
    }

    private fun injectContact(surface: SurfaceView, input: JSONObject, action: Int, down: Long) {
        val viewport = input.getJSONObject("viewport")
        val location = IntArray(2)
        instrumentation.runOnMainSync { surface.getLocationOnScreen(location) }
        val event = MotionEvent.obtain(down, SystemClock.uptimeMillis(), action,
            location[0] + viewport.getDouble("left").toFloat() + viewport.getDouble("width").toFloat() / 2,
            location[1] + viewport.getDouble("top").toFloat() + viewport.getDouble("height").toFloat() / 2, 0)
        event.source = InputDevice.SOURCE_TOUCHSCREEN
        try { instrumentation.sendPointerSync(event) } finally { event.recycle() }
    }

    /** Keep one actual guest invocation, runtime, window, descriptors and GPU
     * resources alive while the OS destroys and replaces the Activity/Surface. */
    fun testSameNvnWindowDrawAndInputAfterActivityRecreate() {
        val first = instrumentation.startActivitySync(Intent(instrumentation.targetContext, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)) as MainActivity
        var replacement: MainActivity? = null
        val executor = Executors.newSingleThreadExecutor()
        var running: java.util.concurrent.Future<String>? = null
        val inputReceipts = JSONArray()
        try {
            awaitCondition("initial automatic diagnostics") {
                var ready = false
                instrumentation.runOnMainSync { ready = first.window.decorView.findViewWithTag<View>("diagnostics-run")?.isEnabled == true }
                ready
            }
            DiagnosticCoordinator.awaitWorkerQuiescence(first)
            val firstSurface = exposeSampledSurface(first)
            val result = executor.submit(Callable { NativeGraphics.runSampledDiagnostics() })
            running = result
            fun observation(frame: Int): JSONObject {
                var receipt = JSONObject()
                awaitCondition("sampled GPU post $frame") {
                    if (result.isDone) throw AssertionError("Window draw ended early: ${result.get()}")
                    receipt = JSONObject(NativeGraphics.sampledFrameSnapshot())
                    receipt.optBoolean("active") && receipt.optInt("frame") == frame
                }
                return receipt
            }
            val firstPost = observation(1)
            observeSampledSurface(first, firstSurface, 0)
            var initialInput = JSONObject(first.runInputDiagnostics(false))
            val down = SystemClock.uptimeMillis()
            val acceptedBefore = initialInput.getLong("accepted")
            injectContact(firstSurface, initialInput, MotionEvent.ACTION_DOWN, down)
            awaitCondition("first producer accepts actual touch") {
                initialInput = JSONObject(first.runInputDiagnostics(false))
                initialInput.optInt("activePointers") == 1 && initialInput.optLong("accepted") > acceptedBefore
            }
            inputReceipts.put(initialInput)
            val oldSurface = JSONObject(NativeGraphics.surfaceSnapshot(first))
            val monitor = instrumentation.addMonitor(MainActivity::class.java.name, null, false)
            val next: MainActivity
            try {
                instrumentation.runOnMainSync { first.recreate() }
                next = instrumentation.waitForMonitorWithTimeout(monitor, 20_000) as? MainActivity
                    ?: throw AssertionError("Activity replacement did not arrive")
            } finally { instrumentation.removeMonitor(monitor) }
            replacement = next
            // The currently executing native diagnostic retains its owner.
            // Cancel only the replacement's automatic diagnostic request; it
            // must not begin another runtime while this one is deliberately live.
            instrumentation.runOnMainSync { DiagnosticCoordinator.cancel(next) }
            var newInput = JSONObject()
            awaitCondition("replacement actual focus, input and Surface") {
                newInput = JSONObject(next.runInputDiagnostics(false))
                val state = JSONObject(NativeGraphics.surfaceSnapshot(next))
                newInput.optBoolean("available") && newInput.optBoolean("focused") && newInput.optBoolean("resumed") &&
                    state.optBoolean("available") && state.optLong("owner") != oldSurface.getLong("owner")
            }
            assertEquals("Old contact leaked into replacement", 0, newInput.getInt("activePointers"))
            assertTrue(newInput.getLong("generation") > initialInput.getLong("generation"))
            assertFalse(JSONObject(first.runInputDiagnostics(false)).getBoolean("available"))
            assertFalse(JSONObject(NativeGraphics.surfaceSnapshot(first)).getBoolean("receiverMatches"))
            inputReceipts.put(newInput)
            val nextSurface = exposeSampledSurface(next)
            // End the OS's old pointer stream after checking native handover
            // cancelled it, then demonstrate a fresh event at the new producer.
            injectContact(nextSurface, newInput, MotionEvent.ACTION_UP, down)
            val nextAcceptedBefore = newInput.getLong("accepted")
            val nextDown = SystemClock.uptimeMillis()
            injectContact(nextSurface, newInput, MotionEvent.ACTION_DOWN, nextDown)
            awaitCondition("replacement producer accepts actual touch") {
                newInput = JSONObject(next.runInputDiagnostics(false))
                newInput.optInt("activePointers") == 1 && newInput.optLong("accepted") > nextAcceptedBefore
            }
            inputReceipts.put(newInput)
            injectContact(nextSurface, newInput, MotionEvent.ACTION_UP, nextDown)
            awaitCondition("replacement touch released") { JSONObject(next.runInputDiagnostics(false)).optInt("activePointers") == 0 }
            assertTrue(NativeGraphics.acknowledgeSampledFrame(firstPost.getLong("id"), 1))
            val secondPost = observation(2)
            try { observeSampledSurface(next, nextSurface, 1) }
            finally { assertTrue(NativeGraphics.acknowledgeSampledFrame(secondPost.getLong("id"), 2)) }
            val report = JSONObject(result.get(30, TimeUnit.SECONDS))
            report.put("inputProducerHandover", inputReceipts).put("activityRecreate", true)
                .put("device", JSONObject().put("model", Build.MODEL).put("apiLevel", Build.VERSION.SDK_INT))
            File(next.filesDir, "window-recreate-report.json").writeText(report.toString(2))
            assertEquals(report.toString(), "PASS", report.getString("status"))
            assertTrue(report.toString(), report.getBoolean("surfaceReplaced"))
            assertTrue(report.toString(), report.getBoolean("staleTicketRefused"))
            assertEquals(2L, report.getLong("gpuDraws"))
            val frames = report.getJSONArray("frames")
            val before = frames.getJSONObject(0)
            val after = frames.getJSONObject(1)
            for (key in listOf("windowRevision", "loadGeneration", "bindingEpoch")) {
                assertTrue(before.getLong(key) > 0)
                assertEquals("Recreation replaced $key", before.getLong(key), after.getLong(key))
            }
            assertEquals(oldSurface.getLong("owner"), before.getLong("surfaceOwner"))
            assertEquals(newInput.getLong("generation"), after.getLong("surfaceOwner"))
            assertTrue(after.getLong("surfaceOwner") != before.getLong("surfaceOwner"))
            assertEquals(before.getLong("surfacePosts") + 1, after.getLong("surfacePosts"))
            assertFalse(report.getBoolean("gamePlayable"))
            assertEquals("NOT_RUN", report.getString("originalGame"))
            val checks = report.getJSONArray("checks")
            for (i in 0 until checks.length()) assertEquals(checks.getJSONObject(i).toString(), "PASS", checks.getJSONObject(i).getString("status"))
        } finally {
            val deadline = SystemClock.uptimeMillis() + 35_000
            while (running?.isDone == false && SystemClock.uptimeMillis() < deadline) {
                val value = JSONObject(NativeGraphics.sampledFrameSnapshot())
                if (value.optBoolean("active") && value.optInt("frame") > 0)
                    NativeGraphics.acknowledgeSampledFrame(value.getLong("id"), value.getInt("frame"))
                SystemClock.sleep(10)
            }
            executor.shutdown()
            val retired = executor.awaitTermination(35, TimeUnit.SECONDS)
            if (running?.isDone == true) {
                val raw = running.get(1, TimeUnit.SECONDS)
                File(instrumentation.targetContext.filesDir, "window-recreate-native.json").writeText(raw)
            }
            File(instrumentation.targetContext.filesDir, "window-recreate-input.json").writeText(inputReceipts.toString(2))
            assertTrue("Live window probe did not retire", retired)
            instrumentation.runOnMainSync { if (!first.isDestroyed) first.finish(); replacement?.finish() }
        }
    }
}
