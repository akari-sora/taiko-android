package org.d2rmobile.diagnostics

import android.content.Intent
import android.os.Build
import android.os.Looper
import android.os.SystemClock
import android.test.InstrumentationTestCase
import android.util.AtomicFile
import android.view.View
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Synthetic OBS/PARAM contracts; original-game execution remains explicitly NOT_RUN. */
@Suppress("DEPRECATION")
class NativeObservationTest : InstrumentationTestCase() {
    private fun waitForNativeActivity(activity: MainActivity) {
        val deadline = SystemClock.uptimeMillis() + 30_000
        var last = JSONObject()
        while (SystemClock.uptimeMillis() < deadline) {
            var diagnosticsDone = false
            instrumentation.runOnMainSync {
                diagnosticsDone = activity.window.decorView
                    .findViewWithTag<View>("diagnostics-run")?.isEnabled == true
            }
            // Metadata-only polling does not consume touch states or dispatch
            // observations while the default diagnostics still own the runtime.
            last = JSONObject(activity.runInputDiagnostics(false))
            val viewport = last.optJSONObject("viewport")
            if (diagnosticsDone && last.optBoolean("available") &&
                last.optBoolean("resumed") && last.optBoolean("focused") &&
                last.optBoolean("hleResolved") && viewport != null &&
                viewport.optDouble("width") > 0 && viewport.optDouble("height") > 0 &&
                viewport.optDouble("density") > 0) return
            SystemClock.sleep(10)
        }
        fail("Native Activity/diagnostics readiness timed out: $last")
    }

    private fun save(report: JSONObject) {
        val file = AtomicFile(File(instrumentation.targetContext.filesDir, "observation-report.json"))
        val stream = file.startWrite()
        try {
            stream.write(report.toString(2).toByteArray(Charsets.UTF_8))
            file.finishWrite(stream)
        } catch (error: Exception) {
            file.failWrite(stream)
            throw error
        }
    }

    fun testObservationParametersCopyClockAndLifetimeContracts() {
        val activity = instrumentation.startActivitySync(
            Intent(instrumentation.targetContext, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        ) as MainActivity
        try {
            waitForNativeActivity(activity)
            assertNotSame("Native probes must run off the UI thread", Looper.getMainLooper(), Looper.myLooper())
            val report = JSONObject(activity.runObservationDiagnostics()).apply {
                put("device", JSONObject().apply {
                    put("manufacturer", Build.MANUFACTURER)
                    put("model", Build.MODEL)
                    put("hardware", Build.HARDWARE)
                    put("apiLevel", Build.VERSION.SDK_INT)
                    put("release", Build.VERSION.RELEASE)
                    put("buildFingerprint", Build.FINGERPRINT)
                    put("supportedAbis", JSONArray(Build.SUPPORTED_ABIS.toList()))
                })
            }
            // Retain failed native receipts as well as successful ones.
            save(report)
            assertEquals(6, report.get("schemaVersion"))
            assertEquals("4", report.getString("phase"))
            assertSame(java.lang.Boolean.TRUE, report.get("syntheticOnly"))
            assertSame(java.lang.Boolean.FALSE, report.get("gamePlayable"))
            val expected = setOf("observation-frame", "parameter-execution", "checked-copy",
                "ui-clock", "lifetime-reload", "profile-authority")
            val checks = report.getJSONArray("checks")
            assertEquals(expected.size, checks.length())
            val observed = mutableSetOf<String>()
            for (index in 0 until checks.length()) {
                val check = checks.getJSONObject(index)
                val id = check.getString("id")
                assertTrue("Unexpected or duplicate observation check: $id", id in expected && observed.add(id))
                assertEquals("Observation fixture failed: $check", "PASS", check.getString("status"))
                assertTrue("Observation check needs an explanation: $id",
                    check.get("detail") is String && check.getString("detail").isNotBlank())
            }
            assertEquals(expected, observed)
            val gates = report.getJSONObject("gates")
            assertEquals(6, gates.length())
            for (gate in 1..6) assertEquals("NOT_RUN", gates.getString("G$gate"))
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
        }
    }
}
