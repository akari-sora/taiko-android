package org.d2rmobile.diagnostics

import android.content.Intent
import android.os.Build
import android.os.SystemClock
import android.test.InstrumentationTestCase
import android.util.AtomicFile
import android.view.View
import org.json.JSONObject
import java.io.File
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit

/** Actual guest recorder and Vulkan publication; authored input, no game proof. */
@Suppress("DEPRECATION")
class NativeGraphicsTest : InstrumentationTestCase() {
    private fun start() = instrumentation.startActivitySync(
        Intent(instrumentation.targetContext, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
    ) as MainActivity

    private fun waitFor(label: String, predicate: () -> Boolean) {
        val deadline = SystemClock.uptimeMillis() + 20_000
        while (SystemClock.uptimeMillis() < deadline) {
            if (predicate()) return
            SystemClock.sleep(10)
        }
        fail("Timed out: $label; owner=${NativeDiagnosticOwner.sessionStatus()}")
    }

    private fun ready(activity: MainActivity): Long {
        waitFor("automatic diagnostics finish") {
            var enabled = false
            instrumentation.runOnMainSync {
                enabled = activity.window.decorView.findViewWithTag<View>("diagnostics-run")?.isEnabled == true
            }
            enabled
        }
        return DiagnosticCoordinator.awaitWorkerQuiescence(activity)
    }

    private fun save(name: String, nativeReport: String) {
        // JSONObject converts unsigned values above Long.MAX_VALUE into Double.
        // Preserve native decimal integers exactly for the independent validator.
        val body = nativeReport.trimEnd()
        check(body.endsWith("}"))
        val device = JSONObject().put("model", Build.MODEL)
            .put("apiLevel", Build.VERSION.SDK_INT).put("fingerprint", Build.FINGERPRINT)
        val document = body.dropLast(1) + ",\"device\":" + device.toString() + "}\n"
        val file = AtomicFile(File(instrumentation.targetContext.filesDir, name))
        val stream = file.startWrite()
        try { stream.write(document.toByteArray()); file.finishWrite(stream) }
        catch (error: Throwable) { file.failWrite(stream); throw error }
    }

    private fun completed(report: JSONObject) {
        assertEquals(report.toString(), "PASS", report.getString("status"))
        assertEquals("Completed", report.getString("outcome"))
        assertEquals("android-graphics-sdk", report.getString("suite"))
        assertFalse(report.getBoolean("gamePlayable"))
        assertTrue(report.getBoolean("syntheticOnly"))
        assertEquals("NOT_RUN", report.getString("originalGame"))
        assertEquals("offscreen-diagnostic", report.getString("capability"))
        assertEquals(3, report.getInt("authorityChecks"))
        assertEquals(70404, report.getInt("verifiedDataBytes"))
        assertTrue(report.getBoolean("dataOraclePassed"))
        assertTrue(report.getBoolean("shapePassed"))
        assertTrue(report.getBoolean("forceBootstrapMatched"))
        assertTrue(report.getLong("loadGeneration") > 0)
        assertEquals(1L, report.getLong("fence"))
        assertEquals(1L, report.getLong("completedFence"))
        val checks = report.getJSONArray("checks")
        val expected = setOf("exact-graph-bootstrap", "forced-bootstrap-exports",
            "guest-callback-growth", "full-byte-data-oracle", "actual-vulkan-operations",
            "no-unavailable-host-or-validation-errors")
        val ids = mutableSetOf<String>()
        for (i in 0 until checks.length()) {
            val check = checks.getJSONObject(i)
            assertTrue(ids.add(check.getString("id")))
            assertTrue(check.toString(), check.getBoolean("passed"))
        }
        assertEquals(expected, ids)
        val gpu = report.getJSONObject("gpu")
        assertEquals(1L, gpu.getLong("submits"))
        assertEquals(1L, gpu.getLong("completed"))
        assertEquals(0L, gpu.getLong("failed"))
        assertEquals(0L, gpu.getLong("validationErrors"))
        assertTrue(gpu.getLong("uniformUpdates") >= 60)
        assertTrue(gpu.getLong("bufferCopies") > 0)
        assertTrue(gpu.getLong("imageUploads") > 0)
        assertTrue(gpu.getLong("imageDownloads") >= 2)
        assertTrue(gpu.getLong("renderPasses") > 0)
        assertTrue(gpu.getString("device").isNotEmpty())
    }

    private fun retained(report: JSONObject, gpuOnly: Boolean) {
        assertEquals(report.toString(), "PASS", report.getString("status"))
        assertEquals("android-graphics-retention", report.getString("suite"))
        assertEquals(2097152L, report.getLong("verifiedUnchangedBytes"))
        for (field in listOf("poolFinalizeRetained", "textureFinalizeRetained", "nonquiescent",
            "resetRefused", "shutdownRefused", "objectsAndHeapUnchanged")) {
            assertTrue(field, report.getBoolean(field))
        }
        for (field in listOf("protectResult", "shrinkResult", "mapResult", "unmapPinnedSourceResult")) {
            assertEquals(field, 64001L, report.getLong(field))
        }
        assertFalse(report.getBoolean("readLeaseHeldForShutdown"))
        assertFalse(report.getBoolean("gamePlayable"))
        val reason = report.getString("shutdownReason")
        if (gpuOnly) assertEquals("graphics work still retains guest memory", reason)
        else assertTrue(reason, reason.contains("guest invocations"))
    }

    fun testGuestNvnGraphicsPipelineAndPixels() {
        val activity = start()
        ready(activity)
        try {
            val raw = NativeGraphics.runDrawDiagnostics(activity, false)
            save("graphics-draw-report.json", raw)
            val report = JSONObject(raw)
            assertEquals(report.toString(), "PASS", report.getString("status"))
            assertEquals("android-authored-draw", report.getString("suite"))
            assertEquals("AuthoredTranslatorFixture", report.getString("sourcekind"))
            assertFalse(report.getBoolean("gamePlayable"))
            assertEquals("NOT_RUN", report.getString("originalGame"))
            for (key in listOf("dataOraclePassed", "arraysPassed", "indexedPassed",
                    "pipelineRollbackPassed", "lateInvalidNoEffects", "retentionPassed")) {
                assertTrue("$key: $report", report.getBoolean(key))
            }
            assertEquals(64, report.getInt("imageWidth"))
            assertEquals(64, report.getInt("imageHeight"))
            assertFalse(report.getJSONObject("presentation").getBoolean("requested"))
            assertFalse(report.getJSONObject("presentation").getBoolean("accepted"))
        } finally { instrumentation.runOnMainSync { activity.finish() } }
    }

    fun testOriginalViServicesOnGuestStack() {
        val activity = start()
        ready(activity)
        try {
            val raw = NativeGraphics.runViDiagnostics()
            save("vi-report.json", raw)
            val report = JSONObject(raw)
            assertEquals(report.toString(), "PASS", report.getString("status"))
            assertEquals("AndroidVI", report.getString("suite"))
            assertEquals("authored-host-leaf-to-real-VI-HLE-in-actual-GuestStack", report.getString("scope"))
            assertEquals("NOT_RUN", report.getString("originalGame"))
            assertEquals("NOT_RUN", report.getString("originalArmGameEntry"))
            assertEquals("NOT_RUN", report.getString("originalImportRelocations"))
            assertEquals("NOT_RUN", report.getString("presentation"))
            assertFalse(report.getBoolean("gamePlayable"))
            assertEquals(4, report.getInt("forcedExports"))
            assertEquals(3, report.getInt("authorityChecks"))
            assertTrue(report.getBoolean("ownedGuestStackOutputs"))
            val generation = report.getLong("loadGeneration")
            assertTrue(generation > 0)
            assertEquals(generation, report.getLong("runtimeGeneration"))
            for (key in listOf("viBinding", "oeEpoch", "surfaceOwner", "surfaceEpoch",
                    "surfaceWidth", "surfaceHeight")) assertTrue(key, report.getLong(key) > 0)
            val tokens = listOf("displayToken", "layerToken", "nativeWindowToken")
                .map { report.getLong(it) }
            assertTrue(tokens.all { it > 0 })
            assertEquals(3, tokens.toSet().size)
            assertEquals(report.getLong("surfacePostsBefore"), report.getLong("surfacePostsAfterCalls"))
            assertEquals(report.getLong("surfacePostsBefore"), report.getLong("surfacePostsAfter"))
            val expected = setOf("unchanged-authored-graphics-bootstrap", "four-actual-forced-exports",
                "trusted-host-leaf-on-owned-guest-stack", "actual-vi-initialize-open-create-query",
                "host-context-output-slots-refused", "forged-parent-output-unchanged",
                "second-layer-refused-first-preserved", "repeated-display-native-queries",
                "native-token-matches-live-surface", "stale-generation-output-unchanged",
                "no-unavailable-host-calls", "shutdown-retires-vi-and-refuses-token",
                "runtime-resources-retired", "vi-does-not-post-surface")
            val checks = report.getJSONArray("checks")
            val ids = mutableSetOf<String>()
            for (i in 0 until checks.length()) {
                val check = checks.getJSONObject(i)
                assertTrue(ids.add(check.getString("id")))
                assertEquals(check.toString(), "PASS", check.getString("status"))
            }
            assertEquals(expected, ids)
            assertEquals("None", JSONObject(NativeDiagnosticOwner.sessionStatus()).getString("role"))
        } finally { instrumentation.runOnMainSync { activity.finish() } }
    }

    fun testOriginalShadersThroughGuestNvnCompute() {
        val activity = start()
        ready(activity)
        try {
            val raw = NativeGraphics.runComputeDiagnostics()
            save("graphics-compute-report.json", raw)
            val report = JSONObject(raw)
            assertEquals(report.toString(), "PASS", report.getString("status"))
            assertFalse(report.getBoolean("gamePlayable"))
            assertEquals("NOT_RUN", report.getString("originalGame"))
            assertEquals(4, report.getInt("verifiedOriginalKernels"))
            assertTrue(report.getLong("gpuDispatches") >= 4)
            assertTrue(report.getBoolean("dataOraclePassed"))
            val checks = report.getJSONArray("checks")
            assertTrue(checks.length() > 0)
            for (i in 0 until checks.length()) {
                assertEquals(checks.getJSONObject(i).toString(), "PASS", checks.getJSONObject(i).getString("status"))
            }
        } finally { instrumentation.runOnMainSync { activity.finish() } }
    }

    fun testGuestCrossSubmitFailuresAndRetention() {
        val activity = start()
        ready(activity)
        try {
            val raw = activity.runGraphicsExtendedDiagnostics()
            save("graphics-extended-report.json", raw)
            val report = JSONObject(raw)
            assertEquals(report.toString(), "PASS", report.getString("status"))
            assertEquals("android-graphics-extended", report.getString("suite"))
            assertFalse(report.getBoolean("gamePlayable"))
            assertTrue(report.getBoolean("syntheticOnly"))
            assertEquals("NOT_RUN", report.getString("originalGame"))
            assertEquals(1779208L, report.getLong("verifiedDataBytes"))
            val expected = listOf("cross-submit-buffer-copy", "cross-submit-uniform-copy",
                "cross-submit-image-by-value-alias", "cpu-edit-after-successful-wait",
                "same-pool-overlapping-copy", "late-unsupported-whole-submit",
                "preaccept-allocation-refusal", "preaccept-submit-refusal", "accepted-device-loss",
                "accepted-publication-refusal", "held-gpu-retention-and-retirement",
                "clean-reload-after-terminal-cases")
            val checks = report.getJSONArray("checks")
            assertEquals(expected.size, report.getInt("checkCount"))
            assertEquals(expected.size, checks.length())
            var generation = 0L
            for (i in expected.indices) {
                val check = checks.getJSONObject(i)
                assertEquals(expected[i], check.getString("id"))
                assertTrue(check.toString(), check.getBoolean("passed"))
                assertTrue(check.getBoolean("baselinePassed"))
                assertTrue(check.getBoolean("closed"))
                assertTrue(check.getLong("loadGeneration") > generation)
                generation = check.getLong("loadGeneration")
                if (i < 5) {
                    assertEquals(65536L, check.getLong("verifiedDataBytes"))
                    assertTrue(check.getBoolean("firstPending"))
                    assertEquals(3L, check.getLong("submits"))
                    assertEquals(3L, check.getLong("completed"))
                    assertEquals(3L, check.getLong("completedFence"))
                    assertEquals(0L, check.getLong("failed"))
                    assertEquals(if (i == 3) 2L else 1L, check.getLong("guestWaits"))
                } else if (i < 10) {
                    val accepted = i >= 8
                    assertEquals(262144L, check.getLong("verifiedDataBytes"))
                    assertEquals(if (accepted) 2L else 1L, check.getLong("submits"))
                    assertEquals(1L, check.getLong("completed"))
                    assertEquals(1L, check.getLong("completedFence"))
                    assertEquals(if (accepted) 1L else 0L, check.getLong("failed"))
                    assertTrue(check.getLong("queueError") > 0)
                    if (accepted) {
                        assertEquals(3L, check.getLong("waitResult"))
                        assertEquals(3L, check.getLong("guestWaits"))
                        assertTrue(check.getBoolean("suffixRejected"))
                        assertTrue(check.getBoolean("suffixUnchanged"))
                        assertEquals(3L, check.getLong("suffixWaitResult"))
                    }
                    if (i == 5) {
                        assertEquals(2L, check.getLong("queueErrorCode"))
                        assertEquals(27L, check.getLong("queueErrorOperation")) // Recorder ABI OP_DISPATCH.
                    }
                } else if (i == 10) retained(check.getJSONObject("retention"), true)
            }
            assertEquals("None", JSONObject(NativeDiagnosticOwner.sessionStatus()).getString("role"))
        } finally { instrumentation.runOnMainSync { activity.finish() } }
    }

    fun testGuestRecordedVulkanDataAndReload() {
        val activity = start()
        ready(activity)
        try {
            val firstRaw = activity.runGraphicsDiagnostics()
            val first = JSONObject(firstRaw)
            save("graphics-report.json", firstRaw)
            completed(first)
            val secondRaw = activity.runGraphicsDiagnostics()
            val second = JSONObject(secondRaw)
            save("graphics-reload-report.json", secondRaw)
            completed(second)
            assertTrue(second.getLong("loadGeneration") > first.getLong("loadGeneration"))
            assertEquals("None", JSONObject(NativeDiagnosticOwner.sessionStatus()).getString("role"))
        } finally { instrumentation.runOnMainSync { activity.finish() } }
    }

    fun testPublicationHoldKeepsOwnershipAndDefersBatch() {
        val activity = start()
        val baseline = ready(activity)
        var replacement: MainActivity? = null
        var token = 0L
        var barrier = 0L
        var waiter: FutureTask<String>? = null
        try {
            barrier = NativeGraphics.armPublicationBarrier()
            assertTrue(barrier > 0)
            token = NativeGraphics.begin()
            assertTrue(token > 0)
            waitFor("actual GPU fence reaches publication hold") {
                JSONObject(NativeGraphics.publicationBarrierSnapshot(barrier)).getBoolean("entered")
            }
            val hold = JSONObject(NativeGraphics.publicationBarrierSnapshot(barrier))
            val pendingRaw = NativeGraphics.poll(token)
            val pending = JSONObject(pendingRaw)
            save("graphics-held-report.json", pendingRaw)
            assertEquals("Pending", pending.getString("outcome"))
            assertEquals(0L, pending.getLong("completedFence"))
            assertTrue(pending.getBoolean("publicationHeld"))
            assertTrue(pending.getBoolean("pendingDataUntouched"))
            assertEquals(hold.getLong("loadGeneration"), pending.getLong("loadGeneration"))
            val retainedRaw = NativeGraphics.retentionSnapshot(barrier)
            save("graphics-retention-report.json", retainedRaw)
            retained(JSONObject(retainedRaw), true)
            assertFalse(NativeGraphics.end(token))
            assertFalse(NativeGraphics.releasePublicationBarrier(barrier + 1))
            val retainedToken = token
            val currentWaiter = FutureTask { NativeGraphics.waitForCompletion(retainedToken, 30_000_000_000L) }
            waiter = currentWaiter
            Thread(currentWaiter, "graphics-native-wait").start()
            waitFor("native waiter retains diagnostic borrower") {
                JSONObject(NativeDiagnosticOwner.sessionStatus()).getBoolean("groupActive")
            }
            // Metadata controls must remain usable while the normal waiter owns
            // the probe mutex and guest invocation; no timing-only inference.
            assertTrue(JSONObject(NativeGraphics.publicationBarrierSnapshot(barrier)).getBoolean("entered"))
            val waitingRaw = NativeGraphics.retentionSnapshot(barrier)
            save("graphics-waiting-retention-report.json", waitingRaw)
            retained(JSONObject(waitingRaw), false)
            assertFalse(NativeGraphics.end(token))
            assertEquals(0L, NativeDiagnosticOwner.beginAutomaticBatch())
            val currentActivity = start()
            replacement = currentActivity
            assertEquals("PersistentGraphics", JSONObject(NativeDiagnosticOwner.sessionStatus()).getString("role"))
            assertTrue(NativeGraphics.releasePublicationBarrier(barrier))
            val resultRaw = currentWaiter.get(20, TimeUnit.SECONDS)
            val result = JSONObject(resultRaw)
            save("graphics-barrier-completed-report.json", resultRaw)
            completed(result)
            assertTrue(NativeGraphics.end(token))
            assertFalse(NativeGraphics.end(token))
            token = 0
            assertEquals(baseline + 1, ready(currentActivity))
            DiagnosticCoordinator.ownerReleased()
            assertEquals(baseline + 1, DiagnosticCoordinator.awaitWorkerQuiescence(currentActivity))
        } finally {
            if (barrier > 0) NativeGraphics.releasePublicationBarrier(barrier)
            try { waiter?.get(35, TimeUnit.SECONDS) }
            finally {
                try {
                    if (token > 0) assertTrue("Graphics cleanup retained ownership", NativeGraphics.end(token))
                } finally { instrumentation.runOnMainSync { replacement?.finish(); activity.finish() } }
            }
        }
    }
}
