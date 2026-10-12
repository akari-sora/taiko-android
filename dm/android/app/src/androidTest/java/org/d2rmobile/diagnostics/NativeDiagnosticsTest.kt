package org.d2rmobile.diagnostics

import android.test.InstrumentationTestCase
import org.json.JSONObject

/** Requires a physical or emulated ARM64 device; never substitutes build success for probes. */
@Suppress("DEPRECATION")
class NativeDiagnosticsTest : InstrumentationTestCase() {
    fun testNativeProbesAndGateContractAreRepeatable() {
        val activity = instrumentation.startActivitySync(
            android.content.Intent(instrumentation.targetContext, MainActivity::class.java)
                .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        ) as MainActivity
        repeat(2) {
            val report = JSONObject(activity.runDiagnostics())
            assertFalse(report.getBoolean("gamePlayable"))
            val checks = report.getJSONArray("checks")
            val expected = setOf("abi", "wx", "x18", "hle", "signal", "tls", "thread", "vulkan")
            assertEquals(expected.size, checks.length())
            val observed = mutableSetOf<String>()
            for (index in 0 until checks.length()) {
                val check = checks.getJSONObject(index)
                val id = check.getString("id")
                assertTrue("Unexpected or duplicate check: $id", id in expected && observed.add(id))
                assertEquals("Probe failed: $check", "PASS", check.getString("status"))
            }
            assertEquals(expected, observed)
            val gates = report.getJSONObject("gates")
            assertEquals("PENDING", gates.getString("G0"))
            for (gate in 1..6) assertEquals("NOT_RUN", gates.getString("G$gate"))
        }
    }
}
