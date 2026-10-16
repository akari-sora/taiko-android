package org.d2rmobile.diagnostics

import android.content.Intent
import android.os.Build
import android.test.InstrumentationTestCase
import android.util.AtomicFile
import org.json.JSONObject
import java.io.File

/** Authored WFE/SVC36 proof through the real runtime; never original-game boot. */
@Suppress("DEPRECATION")
class NativeWaitTest : InstrumentationTestCase() {
    private external fun nativeWait(): String

    fun testNativeBusyMutexAndOwnedVoidSvc36() {
        val activity = instrumentation.startActivitySync(
            Intent(instrumentation.targetContext, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        ) as MainActivity
        try {
            instrumentation.runOnMainSync { DiagnosticCoordinator.cancel(activity) }
            DiagnosticCoordinator.awaitWorkerQuiescence(activity)
            instrumentation.waitForIdleSync()
            // A hang is classified by the caller's external command timeout.
            // No local timer, signal, SEV/SEVL, or fake acquisition rescues WFE.
            val report = JSONObject(nativeWait()).apply {
                put("device", JSONObject().apply {
                    put("model", Build.MODEL)
                    put("hardware", Build.HARDWARE)
                    put("apiLevel", Build.VERSION.SDK_INT)
                    put("fingerprint", Build.FINGERPRINT)
                })
            }
            val target = AtomicFile(File(instrumentation.targetContext.filesDir, "native-wait-report.json"))
            val stream = target.startWrite()
            try {
                stream.write(report.toString(2).toByteArray(Charsets.UTF_8))
                target.finishWrite(stream)
            } catch (error: Exception) {
                target.failWrite(stream)
                throw error
            }
            assertEquals(2, report.getInt("schemaVersion"))
            assertTrue(report.getBoolean("syntheticOnly"))
            assertFalse(report.getBoolean("gamePlayable"))
            assertEquals("NOT_RUN", report.getString("originalSdk"))
            // Unsupported hardware is retained explicitly and cannot count as PASS.
            assertEquals(report.toString(), "PASS", report.getString("status"))
            assertTrue(report.getBoolean("eventStream"))
            assertEquals(1L, report.getLong("svc36Calls"))
            assertEquals(10, report.getInt("mutexCases"))
            assertEquals(4, report.getInt("contendedCases"))
            val layouts = report.getJSONArray("layouts")
            assertEquals(2, layouts.length())
            for (index in 0 until layouts.length()) {
                val layout = layouts.getJSONObject(index)
                assertEquals(if (index == 0) "native_wait_entry" else "native_wait_compact_entry", layout.getString("symbol"))
                assertEquals(if (index == 0) 45 else 39, layout.getInt("nativeUnionWords"))
                assertEquals(5, layout.getInt("mutexCases"))
                assertEquals(2, layout.getInt("contendedCases"))
            }
            assertEquals("NOT_MEASURED", report.getString("hardwareFailedStores"))
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
        }
    }
}
