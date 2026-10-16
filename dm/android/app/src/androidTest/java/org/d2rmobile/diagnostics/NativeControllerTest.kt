package org.d2rmobile.diagnostics

import android.app.AlertDialog
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import android.test.InstrumentationTestCase
import android.util.AtomicFile
import android.view.InputDevice
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.SurfaceView
import android.widget.ScrollView
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Real OS injection -> GameActivity swapped arrays -> actual ARM64 SDK guest.
 * Virtual device calibration is explicit diagnostic input, not hardware discovery.
 */
@Suppress("DEPRECATION")
class NativeControllerTest : InstrumentationTestCase() {
    private val sources = InputDevice.SOURCE_GAMEPAD or InputDevice.SOURCE_JOYSTICK
    private val reportNames = listOf("phase0-report.json", "phase1a-report.json",
        "phase1b-report.json", "kernel-report.json", "services-report.json")
    private var lastEventTime = 0L

    private fun start() = instrumentation.startActivitySync(
        Intent(instrumentation.targetContext, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
    ) as MainActivity

    private fun waitFor(label: String, predicate: () -> Boolean) {
        val deadline = SystemClock.uptimeMillis() + 30_000
        while (SystemClock.uptimeMillis() < deadline) {
            if (predicate()) return
            SystemClock.sleep(10)
        }
        fail("Timed out: $label; collector=${ControllerDevices.receipt()}; owner=${NativeDiagnosticOwner.sessionStatus()}")
    }

    private fun ready(activity: MainActivity, automatic: Boolean): JSONObject {
        var metadata = JSONObject()
        waitFor("Activity ready automatic=$automatic") {
            var complete = false
            instrumentation.runOnMainSync {
                complete = activity.window.decorView.findViewWithTag<View>("diagnostics-run")?.isEnabled == true
            }
            metadata = JSONObject(activity.runInputDiagnostics(false))
            metadata.optBoolean("available") && metadata.optBoolean("focused") &&
                metadata.optBoolean("resumed") && metadata.optBoolean("windowAvailable") &&
                metadata.optLong("nativeWidth") > 0 && metadata.optLong("nativeHeight") > 0 &&
                (!automatic || complete) && JSONObject(ControllerDevices.receipt()).optBoolean("ready")
        }
        return metadata
    }

    private fun descendants(view: View): List<View> = listOf(view) +
        if (view is ViewGroup) (0 until view.childCount).flatMap { descendants(view.getChildAt(it)) } else emptyList()

    private fun expose(activity: MainActivity) {
        instrumentation.runOnMainSync {
            val views = descendants(activity.window.decorView)
            views.filterIsInstance<ScrollView>().forEach { it.visibility = View.INVISIBLE }
            views.filterIsInstance<SurfaceView>().single().apply {
                isFocusable = true
                isFocusableInTouchMode = true
                requestFocus()
            }
        }
        instrumentation.waitForIdleSync()
    }

    private fun save(name: String, report: JSONObject) {
        report.put("syntheticInputOnly", true).put("gamePlayable", false)
            .put("physicalControllerVerified", false)
            .put("route", "OS injection -> GameActivity swapped arrays -> actual ARM64 SDK GetNpadState")
            .put("calibration", "debug diagnostic virtual source; not physical device discovery")
            .put("device", JSONObject().put("model", Build.MODEL).put("apiLevel", Build.VERSION.SDK_INT)
                .put("fingerprint", Build.FINGERPRINT))
        val file = AtomicFile(File(instrumentation.targetContext.filesDir, name))
        val stream = file.startWrite()
        try { stream.write(report.toString(2).toByteArray()); file.finishWrite(stream) }
        catch (error: Throwable) { file.failWrite(stream); throw error }
    }

    private fun register(activity: MainActivity, token: Long) {
        // Android OS injection can use either virtual-keyboard or virtual device 0.
        for (id in listOf(-1, 0)) assertTrue("Cannot register diagnostic virtual id=$id",
            ControllerDevices.registerDiagnosticVirtual(activity, id, sources, token))
        lastEventTime = SystemClock.uptimeMillis()
    }

    private fun time(): Long {
        // Events must be newer than registration/lifecycle fences, not merely
        // equal after Android's millisecond timestamp conversion.
        waitFor("OS event time advances beyond registration/previous event") {
            SystemClock.uptimeMillis() > lastEventTime
        }
        return SystemClock.uptimeMillis().also { lastEventTime = it }
    }

    private fun accepted(action: () -> Unit): JSONObject {
        val before = JSONObject(ControllerDevices.receipt()).getLong("accepted")
        action()
        var after = JSONObject()
        waitFor("real collector accepts OS event") {
            after = JSONObject(ControllerDevices.receipt())
            after.optLong("accepted") > before
        }
        return after
    }

    private fun key(code: Int, down: Boolean): JSONObject = accepted {
        val timestamp = time()
        val event = KeyEvent(timestamp, timestamp, if (down) KeyEvent.ACTION_DOWN else KeyEvent.ACTION_UP,
            code, 0, 0, -1, 0, 0, InputDevice.SOURCE_GAMEPAD)
        assertTrue("OS rejected controller key injection", instrumentation.uiAutomation.injectInputEvent(event, true))
    }

    private fun motion(values: Map<Int, Float>, history: Boolean = false): JSONObject = accepted {
        val timestamp = time()
        val property = MotionEvent.PointerProperties().apply { id = 0; toolType = MotionEvent.TOOL_TYPE_UNKNOWN }
        val coordinate = MotionEvent.PointerCoords().apply { values.forEach { (axis, value) -> setAxisValue(axis, value) } }
        val event = MotionEvent.obtain(timestamp, timestamp, MotionEvent.ACTION_MOVE, 1,
            arrayOf(property), arrayOf(coordinate), 0, 0, 1f, 1f, -1, 0, InputDevice.SOURCE_JOYSTICK, 0)
        if (history) event.addBatch(time(), arrayOf(coordinate), 0)
        try { assertTrue("OS rejected joystick injection", instrumentation.uiAutomation.injectInputEvent(event, true)) }
        finally { event.recycle() }
    }

    private fun poll(token: Long, steps: JSONArray, label: String): JSONObject {
        val report = JSONObject(NativeController.poll(token))
        steps.put(JSONObject().put("step", label).put("collector", JSONObject(ControllerDevices.receipt()))
            .put("guest", report))
        assertEquals("Guest poll failed: $report", "PASS", report.getString("status"))
        assertFalse(report.getBoolean("gamePlayable"))
        assertFalse(report.getBoolean("physicalControllerVerified"))
        assertEquals("DIAGNOSTIC_RAW", report.getJSONObject("adapter").getString("mode"))
        assertFalse(report.getJSONObject("adapter").getBoolean("productComplete"))
        assertEquals(1, report.getJSONObject("full").getInt("attributes"))
        assertEquals(0, report.getJSONObject("handheld").getInt("attributes"))
        val hits = report.getJSONArray("forceHits")
        assertEquals(11, hits.length())
        val names = mutableSetOf<String>()
        for (i in 0 until hits.length()) {
            assertTrue(names.add(hits.getJSONObject(i).getString("name")))
            assertTrue(hits.getJSONObject(i).getLong("hits") > 0)
        }
        for (gate in 1..6) assertEquals("NOT_RUN", report.getJSONObject("gates").getString("G$gate"))
        return report
    }

    private fun buttons(report: JSONObject) = report.getJSONObject("full").getLong("buttons")
    private fun neutral(report: JSONObject) {
        assertEquals(0L, buttons(report))
        val axes = report.getJSONObject("full").getJSONArray("axes")
        for (i in 0..3) assertEquals(0, axes.getInt(i))
    }

    private fun retained(name: String, body: (MainActivity, Long, JSONArray, JSONObject) -> Unit) {
        val activity = start()
        var token = 0L
        val steps = JSONArray()
        val evidence = JSONObject().put("passed", false).put("steps", steps)
        try {
            expose(activity); ready(activity, true)
            DiagnosticCoordinator.awaitWorkerQuiescence(activity)
            token = NativeController.begin()
            assertTrue("Persistent controller owner unavailable", token != 0L)
            register(activity, token)
            neutral(poll(token, steps, "initial neutral guest"))
            body(activity, token, steps, evidence)
            evidence.put("passed", true)
        } catch (error: Throwable) { evidence.put("error", error.toString()); throw error }
        finally {
            if (token != 0L) {
                val closed = runCatching { NativeController.end(token) }.getOrDefault(false)
                evidence.put("cleanupClosed", closed)
                try { assertTrue("Controller cleanup retained ownership", closed) }
                finally { save(name, evidence); instrumentation.runOnMainSync { activity.finish() } }
            } else { save(name, evidence); instrumentation.runOnMainSync { activity.finish() } }
            instrumentation.waitForIdleSync()
        }
    }

    fun testActualSyntheticGuestResolvesAllElevenHidExports() {
        val activity = start()
        try {
            ready(activity, true); DiagnosticCoordinator.awaitWorkerQuiescence(activity)
            val report = JSONObject(activity.runControllerDiagnostics())
            save("controller-sdk-report.json", report)
            assertEquals("PASS", report.getString("status"))
            assertEquals(11, report.getJSONArray("forceHits").length())
            assertEquals(3, report.getInt("authorityChecks"))
            assertEquals(0, report.getInt("deniedRegistrations"))
            assertEquals(0L, report.getLong("sdkFallbackCalls"))
            assertFalse(report.getJSONObject("adapter").getBoolean("productComplete"))
        } finally { instrumentation.runOnMainSync { activity.finish() }; instrumentation.waitForIdleSync() }
    }

    fun testOsKeyShortPressReachesGuestExactlyOnce() = retained("controller-os-key.json") { _, token, steps, evidence ->
        evidence.put("down", key(KeyEvent.KEYCODE_BUTTON_A, true))
        evidence.put("up", key(KeyEvent.KEYCODE_BUTTON_A, false))
        assertEquals(1L, buttons(poll(token, steps, "A down/up between guest polls")))
        neutral(poll(token, steps, "next guest poll consumes no duplicate A"))
    }

    fun testSourceRetirementCancelsPendingPress() = retained("controller-os-source-cancel.json") { activity, token, steps, evidence ->
        evidence.put("down", key(KeyEvent.KEYCODE_BUTTON_B, true))
        for (id in listOf(-1, 0)) assertTrue(ControllerDevices.removeDiagnosticVirtual(activity, id, token))
        neutral(poll(token, steps, "device retirement cancels unsampled B"))
        register(activity, token)
        key(KeyEvent.KEYCODE_BUTTON_A, true); key(KeyEvent.KEYCODE_BUTTON_A, false)
        assertEquals(1L, buttons(poll(token, steps, "fresh device generation accepts new A")))
        neutral(poll(token, steps, "fresh generation has no retired B"))
    }

    fun testOsJoystickAndDigitalAnalogTriggerUnion() = retained("controller-os-joystick.json") { _, token, steps, evidence ->
        val axes = mapOf(MotionEvent.AXIS_X to 0.5f, MotionEvent.AXIS_Y to -0.5f,
            MotionEvent.AXIS_Z to -0.75f, MotionEvent.AXIS_RZ to 0.75f)
        evidence.put("joystick", motion(axes, history = true)).put("requestedHistorySamples", 1)
        val moved = poll(token, steps, "OS joystick history batch final state")
            .getJSONObject("full").getJSONArray("axes")
        val expected = listOf(16384, 16384, -24575, -24575)
        for (i in 0..3) assertTrue("axis[$i]=$moved", kotlin.math.abs(moved.getInt(i) - expected[i]) <= 1)
        motion(mapOf(MotionEvent.AXIS_LTRIGGER to 1f))
        assertEquals(256L, buttons(poll(token, steps, "analog left trigger pressed")))
        key(KeyEvent.KEYCODE_BUTTON_L2, true)
        motion(emptyMap())
        assertEquals(256L, buttons(poll(token, steps, "digital trigger remains after analog release")))
        key(KeyEvent.KEYCODE_BUTTON_L2, false)
        neutral(poll(token, steps, "both trigger channels released"))
    }

    fun testOsFocusAndReplacementCancelPendingInputAndResumeOneDeferredBatch() {
        val original = start()
        var replacement: MainActivity? = null
        var dialog: AlertDialog? = null
        var token = 0L
        val steps = JSONArray()
        val evidence = JSONObject().put("steps", steps).put("passed", false)
        fun reports() = reportNames.associateWith { File(instrumentation.targetContext.filesDir, it).readBytes() }
        fun unchanged(before: Map<String, ByteArray>) {
            val after = reports()
            before.forEach { (name, bytes) -> assertTrue("Retained owner overwrote $name", bytes.contentEquals(after.getValue(name))) }
        }
        try {
            expose(original)
            val first = ready(original, true)
            val batchStarts = DiagnosticCoordinator.awaitWorkerQuiescence(original)
            val before = reports()
            token = NativeController.begin(); assertTrue(token != 0L); register(original, token)
            key(KeyEvent.KEYCODE_BUTTON_A, true); key(KeyEvent.KEYCODE_BUTTON_A, false)
            instrumentation.runOnMainSync { dialog = AlertDialog.Builder(original).setTitle("Controller focus cancellation").create().also { it.show() } }
            waitFor("actual OS dialog focus loss") {
                !JSONObject(original.runInputDiagnostics(false)).optBoolean("focused") &&
                    !JSONObject(ControllerDevices.receipt()).optBoolean("ready")
            }
            neutral(poll(token, steps, "focus loss cancels pending unsampled A"))
            instrumentation.runOnMainSync { dialog?.dismiss(); dialog = null }
            ready(original, false)
            lastEventTime = SystemClock.uptimeMillis()
            key(KeyEvent.KEYCODE_BUTTON_B, true); key(KeyEvent.KEYCODE_BUTTON_B, false)
            replacement = start(); expose(replacement!!)
            val latest = ready(replacement!!, false)
            assertTrue(latest.getLong("generation") > first.getLong("generation"))
            assertFalse(JSONObject(original.runInputDiagnostics(false)).optBoolean("available"))
            neutral(poll(token, steps, "replacement cancels old Activity pending B"))
            assertFalse("Retired Activity registered a successor source",
                ControllerDevices.registerDiagnosticVirtual(original, -1, sources, token))
            register(replacement!!, token)
            key(KeyEvent.KEYCODE_BUTTON_A, true); key(KeyEvent.KEYCODE_BUTTON_A, false)
            assertEquals(1L, buttons(poll(token, steps, "replacement fresh input reaches retained guest")))
            try { replacement!!.runServiceDiagnostics(); fail("Unrelated diagnostics entered controller owner") }
            catch (expected: DiagnosticOwnershipException) { evidence.put("unrelatedOwnerRefused", expected.message) }
            unchanged(before)
            assertTrue(NativeController.end(token)); token = 0
            ready(replacement!!, true)
            val resumed = DiagnosticCoordinator.awaitWorkerQuiescence(replacement!!)
            assertEquals("Only latest deferred automatic batch resumes", batchStarts + 1, resumed)
            val completed = reports()
            DiagnosticCoordinator.ownerReleased(); DiagnosticCoordinator.readinessChanged()
            assertEquals(resumed, DiagnosticCoordinator.awaitWorkerQuiescence(replacement!!))
            unchanged(completed)
            evidence.put("batchStartsBefore", batchStarts).put("batchStartsAfter", resumed).put("passed", true)
        } catch (error: Throwable) { evidence.put("error", error.toString()); throw error }
        finally {
            if (token != 0L) evidence.put("cleanupClosed", runCatching { NativeController.end(token) }.getOrDefault(false))
            try { save("controller-os-lifecycle.json", evidence) }
            finally {
                instrumentation.runOnMainSync { dialog?.dismiss(); original.finish(); replacement?.finish() }
                instrumentation.waitForIdleSync()
            }
        }
    }
}
