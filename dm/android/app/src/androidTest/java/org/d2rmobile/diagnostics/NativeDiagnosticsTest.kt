package org.d2rmobile.diagnostics

import android.test.InstrumentationTestCase
import android.os.SystemClock
import android.view.View
import org.json.JSONObject

/** Requires a physical or emulated ARM64 device; never substitutes build success for probes. */
@Suppress("DEPRECATION")
class NativeDiagnosticsTest : InstrumentationTestCase() {
    private fun waitForAutomaticBatch(activity: MainActivity) {
        val deadline = SystemClock.uptimeMillis() + 30_000
        var last = JSONObject()
        while (SystemClock.uptimeMillis() < deadline) {
            var completed = false
            instrumentation.runOnMainSync {
                completed = activity.window.decorView
                    .findViewWithTag<View>("diagnostics-run")?.isEnabled == true
            }
            // This path is deliberately metadata-only: readiness polling cannot
            // compete with the automatic batch's mutating native group scopes.
            last = JSONObject(activity.runInputDiagnostics(false))
            val viewport = last.optJSONObject("viewport")
            if (completed && last.optBoolean("available") && last.optBoolean("focused") &&
                last.optBoolean("resumed") && last.optBoolean("hleResolved") &&
                viewport != null && viewport.optDouble("width") > 0 &&
                viewport.optDouble("height") > 0 && viewport.optDouble("density") > 0) return
            SystemClock.sleep(10)
        }
        fail("Automatic diagnostics/native window readiness timed out: $last; ${NativeDiagnosticOwner.sessionStatus()}")
    }

    /** Synthetic files/accounts cannot establish original-game save or gameplay parity. */
    fun testHostServicesAndSaveTransactionsAreRepeatable() {
        val activity = instrumentation.startActivitySync(
            android.content.Intent(instrumentation.targetContext, MainActivity::class.java)
                .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK or android.content.Intent.FLAG_ACTIVITY_CLEAR_TASK)
        ) as MainActivity
        try {
            waitForAutomaticBatch(activity)
            repeat(2) {
                val report = JSONObject(activity.runServiceDiagnostics())
                assertEquals(5, report.get("schemaVersion"))
                assertEquals("3", report.getString("phase"))
                assertSame(java.lang.Boolean.TRUE, report.get("syntheticOnly"))
                assertSame(java.lang.Boolean.FALSE, report.get("gamePlayable"))
                val environment = report.getJSONObject("environment")
                assertEquals("arm64-v8a", environment.getString("abi"))
                assertTrue("Page size must be an integer", environment.get("pageSize") is Int || environment.get("pageSize") is Long)
                val pageSize = environment.getLong("pageSize")
                assertTrue("Page size must be a positive power of two", pageSize > 0 && (pageSize and (pageSize - 1)) == 0L)
                val checks = report.getJSONArray("checks")
                val expected = setOf("account", "events", "time", "filesystem", "save_transactions", "lifetime")
                assertEquals(expected.size, checks.length())
                val observed = mutableSetOf<String>()
                for (index in 0 until checks.length()) {
                    val check = checks.getJSONObject(index)
                    val id = check.getString("id")
                    assertTrue("Unexpected or duplicate check: $id", id in expected && observed.add(id))
                    assertEquals("Service fixture failed: $check", "PASS", check.getString("status"))
                    assertTrue("Service check needs an explanation: $id", check.get("detail") is String && check.getString("detail").isNotBlank())
                }
                assertEquals(expected, observed)
                val gates = report.getJSONObject("gates")
                assertEquals(6, gates.length())
                for (gate in 1..6) assertEquals("NOT_RUN", gates.getString("G$gate"))
            }
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
        }
    }

    fun testKernelServicesAndLifetimeAreRepeatable() {
        val activity = instrumentation.startActivitySync(
            android.content.Intent(instrumentation.targetContext, MainActivity::class.java)
                .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK or android.content.Intent.FLAG_ACTIVITY_CLEAR_TASK)
        ) as MainActivity
        try {
            waitForAutomaticBatch(activity)
            repeat(2) {
                val report = JSONObject(activity.runKernelDiagnostics())
                assertEquals(4, report.get("schemaVersion"))
                assertEquals("2", report.getString("phase"))
                assertSame(java.lang.Boolean.TRUE, report.get("syntheticOnly"))
                assertSame(java.lang.Boolean.FALSE, report.get("gamePlayable"))
                val environment = report.getJSONObject("environment")
                assertEquals("arm64-v8a", environment.getString("abi"))
                assertTrue("Page size must be an integer", environment.get("pageSize") is Int || environment.get("pageSize") is Long)
                val pageSize = environment.getLong("pageSize")
                assertTrue("Page size must be a positive power of two", pageSize > 0 && (pageSize and (pageSize - 1)) == 0L)
                val checks = report.getJSONArray("checks")
                val expected = setOf("registry", "memory", "threads", "clock", "lifetime")
                assertEquals(expected.size, checks.length())
                val observed = mutableSetOf<String>()
                for (index in 0 until checks.length()) {
                    val check = checks.getJSONObject(index)
                    val id = check.getString("id")
                    assertTrue("Unexpected or duplicate check: $id", id in expected && observed.add(id))
                    assertEquals("Kernel fixture failed: $check", "PASS", check.getString("status"))
                    assertTrue("Kernel check needs an explanation: $id", check.get("detail") is String && check.getString("detail").isNotBlank())
                }
                assertEquals(expected, observed)
                val gates = report.getJSONObject("gates")
                assertEquals(6, gates.length())
                for (gate in 1..6) assertEquals("NOT_RUN", gates.getString("G$gate"))
            }
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
        }
    }

    fun testProductionModuleFixturesAndProvenanceAreRepeatable() {
        val activity = instrumentation.startActivitySync(
            android.content.Intent(instrumentation.targetContext, MainActivity::class.java)
                .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK or android.content.Intent.FLAG_ACTIVITY_CLEAR_TASK)
        ) as MainActivity
        try {
            waitForAutomaticBatch(activity)
            repeat(2) {
                val report = JSONObject(activity.runModuleDiagnostics())
                assertEquals(3, report.getInt("schemaVersion"))
                assertEquals("1B", report.getString("phase"))
                assertTrue(report.getBoolean("syntheticOnly"))
                assertFalse(report.getBoolean("gamePlayable"))
                val pageSize = report.getJSONObject("environment").getLong("pageSize")
                assertTrue("Page size must be a positive power of two", pageSize > 0 && (pageSize and (pageSize - 1)) == 0L)
                val checks = report.getJSONArray("checks")
                val expected = setOf("modules", "relocations", "permissions", "initializers", "imports", "guest_stack")
                assertEquals(expected.size, checks.length())
                val observed = mutableSetOf<String>()
                for (index in 0 until checks.length()) {
                    val check = checks.getJSONObject(index)
                    val id = check.getString("id")
                    assertTrue("Unexpected or duplicate check: $id", id in expected && observed.add(id))
                    assertEquals("Module fixture failed: $check", "PASS", check.getString("status"))
                }
                assertEquals(expected, observed)
                val modules = report.getJSONArray("modules")
                assertEquals(3, modules.length())
                val names = mutableSetOf<String>()
                val digestPattern = Regex("[0-9a-fA-F]{64}")
                for (index in 0 until modules.length()) {
                    val module = modules.getJSONObject(index)
                    val name = module.getString("name")
                    assertTrue("Missing or duplicate module name: $name", name.isNotBlank() && names.add(name))
                    for (field in listOf("buildId", "sourceSha256", "imageSha256")) {
                        assertTrue("Incomplete module provenance: $name.$field", digestPattern.matches(module.getString(field)))
                    }
                }
                val gates = report.getJSONObject("gates")
                assertEquals(6, gates.length())
                for (gate in 1..6) assertEquals("NOT_RUN", gates.getString("G$gate"))
            }
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
        }
    }

    fun testRewrittenGuestFixturesAndGateContractAreRepeatable() {
        val activity = instrumentation.startActivitySync(
            android.content.Intent(instrumentation.targetContext, MainActivity::class.java)
                .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK or android.content.Intent.FLAG_ACTIVITY_CLEAR_TASK)
        ) as MainActivity
        try {
            waitForAutomaticBatch(activity)
            repeat(2) {
                val report = JSONObject(activity.runGuestDiagnostics())
                assertEquals(2, report.getInt("schemaVersion"))
                assertEquals("1A", report.getString("phase"))
                assertTrue(report.getBoolean("syntheticOnly"))
                assertFalse(report.getBoolean("gamePlayable"))
                assertTrue(report.getJSONObject("environment").getLong("pageSize") > 0)
                val checks = report.getJSONArray("checks")
                val expected = setOf("rewrite", "threads", "frame", "signal", "loader")
                assertEquals(expected.size, checks.length())
                val observed = mutableSetOf<String>()
                for (index in 0 until checks.length()) {
                    val check = checks.getJSONObject(index)
                    val id = check.getString("id")
                    assertTrue("Unexpected or duplicate check: $id", id in expected && observed.add(id))
                    assertEquals("Guest fixture failed: $check", "PASS", check.getString("status"))
                }
                assertEquals(expected, observed)
                val gates = report.getJSONObject("gates")
                for (gate in 1..6) assertEquals("NOT_RUN", gates.getString("G$gate"))
            }
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
        }
    }

    fun testNativeProbesAndGateContractAreRepeatable() {
        val activity = instrumentation.startActivitySync(
            android.content.Intent(instrumentation.targetContext, MainActivity::class.java)
                .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK or android.content.Intent.FLAG_ACTIVITY_CLEAR_TASK)
        ) as MainActivity
        try {
            waitForAutomaticBatch(activity)
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
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
        }
    }
}
