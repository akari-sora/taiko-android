package org.d2rmobile.diagnostics

import android.app.AlertDialog
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import android.test.InstrumentationTestCase
import android.util.AtomicFile
import android.view.View
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** Separates synthetic guest contracts from actual OS lifecycle delivery. */
@Suppress("DEPRECATION")
class NativeAppletTest : InstrumentationTestCase() {
    private val reportNames = listOf("phase0-report.json", "phase1a-report.json",
        "phase1b-report.json", "kernel-report.json", "services-report.json")

    private fun start(): MainActivity = instrumentation.startActivitySync(
        Intent(instrumentation.targetContext, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
    ) as MainActivity

    private fun waitFor(label: String, condition: () -> Boolean) {
        val deadline = SystemClock.uptimeMillis() + 30_000
        while (SystemClock.uptimeMillis() < deadline) {
            if (condition()) return
            SystemClock.sleep(10)
        }
        fail("Timed out: $label; owner=${NativeDiagnosticOwner.sessionStatus()}")
    }

    private fun metadata(activity: MainActivity) = JSONObject(activity.runInputDiagnostics(false))

    private fun waitReady(activity: MainActivity, automaticComplete: Boolean): JSONObject {
        var last = JSONObject()
        waitFor("native Activity readiness, automaticComplete=$automaticComplete") {
            var complete = false
            instrumentation.runOnMainSync {
                complete = activity.window.decorView.findViewWithTag<View>("diagnostics-run")?.isEnabled == true
            }
            last = metadata(activity)
            last.optBoolean("available") && last.optBoolean("focused") && last.optBoolean("resumed") &&
                last.optBoolean("windowAvailable") && last.optLong("nativeWidth") > 0 &&
                last.optLong("nativeHeight") > 0 && (!automaticComplete || complete)
        }
        return last
    }

    private fun save(name: String, report: JSONObject) {
        report.put("device", JSONObject().put("manufacturer", Build.MANUFACTURER)
            .put("model", Build.MODEL).put("apiLevel", Build.VERSION.SDK_INT)
            .put("buildFingerprint", Build.FINGERPRINT)
            .put("supportedAbis", JSONArray(Build.SUPPORTED_ABIS.toList())))
        val file = AtomicFile(File(instrumentation.targetContext.filesDir, name))
        val stream = file.startWrite()
        try {
            stream.write(report.toString(2).toByteArray(Charsets.UTF_8))
            file.finishWrite(stream)
        } catch (error: Exception) {
            file.failWrite(stream)
            throw error
        }
    }

    private fun reports(): Map<String, ByteArray> = reportNames.associateWith {
        File(instrumentation.targetContext.filesDir, it).readBytes()
    }

    private fun unchanged(before: Map<String, ByteArray>) {
        val after = reports()
        before.forEach { (name, bytes) ->
            assertTrue("Deferred work overwrote $name", bytes.contentEquals(after.getValue(name)))
        }
    }

    private fun deferred(activity: MainActivity) {
        waitFor("replacement Activity explicitly deferred") {
            var result = false
            instrumentation.runOnMainSync {
                val decor = activity.window.decorView
                result = decor.findViewWithTag<View>("diagnostics-run")?.isEnabled == false &&
                    decor.findViewWithTag<TextView>("diagnostics-status")?.text.toString()
                        .contains("deferred", ignoreCase = true)
            }
            result
        }
    }

    private fun expectOwnershipRefusal(name: String, evidence: JSONArray, call: () -> String) {
        try {
            call()
            fail("$name entered while persistent OE owns the process")
        } catch (expected: DiagnosticOwnershipException) {
            evidence.put(JSONObject().put("entry", name).put("refused", true)
                .put("detail", expected.message))
        }
    }

    fun testSyntheticAppletGuestExportsNotificationsParametersAndSdkThreads() {
        val activity = start()
        try {
            waitReady(activity, true)
            val report = JSONObject(activity.runAppletDiagnostics())
            save("applet-report.json", report)
            assertEquals(7, report.getInt("schemaVersion"))
            assertEquals("5", report.getString("phase"))
            assertTrue(report.getBoolean("syntheticOnly"))
            assertFalse(report.getBoolean("gamePlayable"))
            val expected = setOf("exports", "notifications", "parameters", "sdk_copy", "preflight", "lifetime")
            val observed = mutableSetOf<String>()
            val checks = report.getJSONArray("checks")
            assertEquals(expected.size, checks.length())
            for (index in 0 until checks.length()) {
                val check = checks.getJSONObject(index)
                val id = check.getString("id")
                assertTrue("Unexpected or duplicate applet check: $id", id in expected && observed.add(id))
                assertEquals("Applet fixture failed: $check", "PASS", check.getString("status"))
                assertTrue(check.getString("detail").isNotBlank())
            }
            assertEquals(expected, observed)
            for (gate in 1..6) assertEquals("NOT_RUN", report.getJSONObject("gates").getString("G$gate"))
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
        }
    }

    fun testPersistentAppletReceivesOsLifecycleAndDefersOldAndReplacementBatches() {
        val original = start()
        var pending: MainActivity? = null
        var latest: MainActivity? = null
        var dialog: AlertDialog? = null
        var token = 0L
        var loadBarrier = 0L
        var beginThread: Thread? = null
        val beginToken = AtomicLong(0)
        val beginError = AtomicReference<Throwable?>(null)
        val beginDone = CountDownLatch(1)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val steps = JSONArray()
        val refusals = JSONArray()
        val evidence = JSONObject().put("syntheticOnly", true).put("gamePlayable", false)
            .put("steps", steps).put("ownershipRefusals", refusals).put("passed", false)

        fun poll(label: String, predicate: (JSONObject) -> Boolean): JSONObject {
            var last = JSONObject()
            waitFor(label) {
                last = JSONObject(NativeApplet.poll(token))
                steps.put(JSONObject().put("step", label).put("uptimeMillis", SystemClock.uptimeMillis())
                    .put("receipt", last))
                predicate(last)
            }
            assertTrue(last.getBoolean("open"))
            assertTrue(last.getBoolean("syntheticOnly"))
            assertFalse(last.getBoolean("gamePlayable"))
            for (gate in 1..6) assertEquals("NOT_RUN", last.getJSONObject("gates").getString("G$gate"))
            return last
        }

        try {
            val initial = waitReady(original, true)
            instrumentation.waitForIdleSync()
            val initialBatchStarts = DiagnosticCoordinator.awaitWorkerQuiescence(original)
            val baseline = reports()
            // Deterministically park the old Activity's already-running process
            // worker immediately before it attempts native process ownership.
            DiagnosticCoordinator.setBeforeOwnershipObserver(original) {
                entered.countDown()
                check(release.await(30, TimeUnit.SECONDS)) { "Scheduler ownership barrier timed out" }
            }
            instrumentation.runOnMainSync { DiagnosticCoordinator.request(original) }
            assertTrue("Old batch never reached pre-ownership boundary", entered.await(10, TimeUnit.SECONDS))
            pending = start()
            val pendingMetadata = waitReady(pending!!, false)
            assertTrue(pendingMetadata.getLong("generation") > initial.getLong("generation"))
            loadBarrier = NativeApplet.armLoadBarrier()
            assertTrue("Could not arm actual runtime-load barrier", loadBarrier != 0L)
            beginThread = Thread({
                try { beginToken.set(NativeApplet.begin()) }
                catch (error: Throwable) { beginError.set(error) }
                finally { beginDone.countDown() }
            }, "applet-runtime-load-proof").also { it.start() }
            var held = JSONObject()
            waitFor("actual HleRuntime.load holds lifecycle lock") {
                held = JSONObject(NativeApplet.loaderSnapshot())
                assertFalse("Runtime-load barrier timed out: $held", held.optBoolean("timedOut"))
                held.optBoolean("waiting")
            }
            assertEquals("Begin unexpectedly finished while its load barrier is held", 1L, beginDone.count)
            assertEquals(1, held.getInt("adapterFocus"))
            val heldRevision = held.getLong("revision")
            instrumentation.runOnMainSync {
                dialog = AlertDialog.Builder(pending!!).setTitle("Runtime load publication test")
                    .create().also { it.show() }
            }
            var published = JSONObject()
            waitFor("real dialog fact publishes while runtime lifecycle lock remains held") {
                published = JSONObject(NativeApplet.loaderSnapshot())
                assertFalse("Runtime-load barrier timed out: $published", published.optBoolean("timedOut"))
                published.optBoolean("waiting") && !published.optBoolean("released") &&
                    published.optLong("revision") > heldRevision &&
                    !published.optBoolean("focused") && !published.optBoolean("stopped") &&
                    published.optInt("adapterFocus") == 2
            }
            assertEquals("Begin completed before load barrier release", 1L, beginDone.count)
            evidence.put("runtimeLoadHeld", held).put("osPublicationWhileRuntimeLoadHeld", published)
            assertTrue("Could not release actual runtime-load barrier", NativeApplet.releaseLoadBarrier(loadBarrier))
            assertTrue("Native begin failed to finish after releasing load", beginDone.await(10, TimeUnit.SECONDS))
            beginThread!!.join(1_000)
            assertFalse("Native begin thread still running", beginThread!!.isAlive)
            beginError.get()?.let { throw AssertionError("Persistent begin failed", it) }
            token = beginToken.get()
            assertTrue("Persistent applet could not acquire the idle process", token != 0L)
            poll("load completes with latest dialog inactive fact") {
                it.optLong("generation") == pendingMetadata.getLong("generation") &&
                    it.optInt("guestFocus") == 2 && it.optInt("adapterFocus") == 2
            }
            instrumentation.runOnMainSync { dialog?.dismiss(); dialog = null }
            val first = poll("replacement resumed and focused") {
                it.optLong("generation") == pendingMetadata.getLong("generation") &&
                    it.optInt("guestFocus") == 1 && it.optInt("adapterFocus") == 1
            }
            val epoch = first.getLong("epoch")
            evidence.put("preOwnershipBarrierReached", true).put("persistentToken", token)
            release.countDown()
            deferred(pending!!)
            unchanged(baseline)
            assertFalse(metadata(original).getBoolean("available"))

            expectOwnershipRefusal("services", refusals) { pending!!.runServiceDiagnostics() }
            expectOwnershipRefusal("observation", refusals) { pending!!.runObservationDiagnostics() }
            expectOwnershipRefusal("input-sampling", refusals) { pending!!.runInputDiagnostics() }
            expectOwnershipRefusal("wrong-role-services", refusals) { pending!!.runServiceDiagnostics(token) }
            assertTrue(metadata(pending!!).getBoolean("available"))
            assertEquals("PersistentApplet", JSONObject(NativeDiagnosticOwner.sessionStatus()).getString("role"))
            unchanged(baseline)

            instrumentation.runOnMainSync {
                dialog = AlertDialog.Builder(pending!!).setTitle("OE lifecycle test").create().also { it.show() }
            }
            val inactive = poll("dialog focus loss without STOP") {
                !it.optBoolean("focused") && !it.optBoolean("stopped") &&
                    it.optInt("guestFocus") == 2 && it.optInt("adapterFocus") == 2
            }
            assertEquals(epoch, inactive.getLong("epoch"))
            instrumentation.runOnMainSync { dialog?.dismiss(); dialog = null }
            poll("dialog dismissed") { it.optBoolean("resumed") && it.optBoolean("focused") &&
                it.optInt("guestFocus") == 1 && it.optInt("adapterFocus") == 1 }

            assertTrue("OS Home action failed", instrumentation.uiAutomation.performGlobalAction(2))
            poll("Home STOP") { it.optBoolean("stopped") && it.optInt("guestFocus") == 3 &&
                it.optInt("adapterFocus") == 3 }
            instrumentation.targetContext.startActivity(
                Intent(instrumentation.targetContext, MainActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_REORDER_TO_FRONT)
            )
            waitReady(pending!!, false)
            val returned = poll("return to existing Activity") { it.optBoolean("resumed") &&
                it.optBoolean("focused") && !it.optBoolean("stopped") &&
                it.optInt("guestFocus") == 1 && it.optInt("adapterFocus") == 1 }
            assertEquals(first.getLong("generation"), returned.getLong("generation"))
            assertEquals(epoch, returned.getLong("epoch"))

            instrumentation.runOnMainSync { pending!!.finish() }
            instrumentation.waitForIdleSync()
            latest = start()
            val latestMetadata = waitReady(latest!!, false)
            val replacement = poll("latest Activity replaces destroyed pending ticket") {
                it.optLong("generation") == latestMetadata.getLong("generation") &&
                    it.optInt("guestFocus") == 1 && it.optInt("adapterFocus") == 1
            }
            assertTrue(replacement.getLong("generation") > first.getLong("generation"))
            assertEquals(epoch, replacement.getLong("epoch"))
            deferred(latest!!)
            unchanged(baseline)
            assertFalse(metadata(pending!!).getBoolean("available"))

            assertTrue("Orderly applet teardown retained ownership", NativeApplet.end(token))
            token = 0
            beginToken.set(0)
            waitReady(latest!!, true)
            instrumentation.waitForIdleSync()
            val completedBatchStarts = DiagnosticCoordinator.awaitWorkerQuiescence(latest!!)
            assertEquals("Only the latest deferred ticket may run", initialBatchStarts + 1, completedBatchStarts)
            val resumed = reports().mapValues { JSONObject(String(it.value, Charsets.UTF_8)) }
            val batches = resumed.values.map { it.getJSONObject("diagnosticBatch") }
            val batchToken = batches.first().getLong("sessionToken")
            assertTrue(batchToken > 0)
            for ((name, report) in resumed) {
                val batch = report.getJSONObject("diagnosticBatch")
                assertEquals("Wrong Activity ran $name", latestMetadata.getLong("generation"), batch.getLong("activityGeneration"))
                assertEquals(batchToken, batch.getLong("sessionToken"))
                val checks = report.getJSONArray("checks")
                for (index in 0 until checks.length()) assertEquals("Resumed $name failed", "PASS",
                    checks.getJSONObject(index).getString("status"))
                assertFalse(report.getBoolean("gamePlayable"))
                for (gate in 1..6) assertEquals("NOT_RUN", report.getJSONObject("gates").getString("G$gate"))
            }
            evidence.put("resumedBatch", batches.first()).put("resumedReportCount", resumed.size)
            // Duplicate release/readiness notifications must not create a new
            // request after the latest ticket was consumed.
            val completed = reports()
            DiagnosticCoordinator.ownerReleased()
            DiagnosticCoordinator.readinessChanged()
            instrumentation.waitForIdleSync()
            val afterDuplicateStarts = DiagnosticCoordinator.awaitWorkerQuiescence(latest!!)
            assertEquals("Duplicate release/readiness started another batch", completedBatchStarts, afterDuplicateStarts)
            unchanged(completed)
            evidence.put("batchStartsBeforeDeferred", initialBatchStarts)
                .put("batchStartsAfterResume", completedBatchStarts)
                .put("batchStartsAfterDuplicateSignals", afterDuplicateStarts)
            evidence.put("passed", true)
        } catch (error: Throwable) {
            evidence.put("error", error.toString())
            throw error
        } finally {
            release.countDown()
            DiagnosticCoordinator.setBeforeOwnershipObserver(original, null)
            if (loadBarrier != 0L) runCatching { NativeApplet.releaseLoadBarrier(loadBarrier) }
            beginThread?.join(11_000)
            evidence.put("beginThreadJoined", beginThread?.isAlive != true)
            if (token == 0L) token = beginToken.get()
            if (token != 0L) evidence.put("cleanupClosed", runCatching { NativeApplet.end(token) }.getOrDefault(false))
            try {
                save("applet-os-lifecycle.json", evidence)
            } finally {
                instrumentation.runOnMainSync { dialog?.dismiss(); original.finish(); pending?.finish(); latest?.finish() }
                instrumentation.waitForIdleSync()
            }
        }
    }
}
