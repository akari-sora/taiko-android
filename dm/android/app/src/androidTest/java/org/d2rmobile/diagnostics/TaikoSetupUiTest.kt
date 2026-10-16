package org.d2rmobile.diagnostics

import android.app.Activity
import android.content.ContextWrapper
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.test.InstrumentationTestCase
import android.widget.Button
import android.widget.TextView
import java.io.File
import java.util.UUID
import org.json.JSONObject
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Exercises setup controls against real local inspection; no original game bytes are needed. */
@Suppress("DEPRECATION")
class TaikoSetupUiTest : InstrumentationTestCase() {
    fun testMissingCompiledBuildRefusesBeforeOriginalExecution() {
        assertFalse("This content-free regression APK must have no retail provider", NativeOriginal.hasCompiledBuild())
        withSetup { setup ->
            val activity = setup.view.context as MainActivity
            DiagnosticCoordinator.awaitWorkerQuiescence(activity)
            val report = JSONObject(NativeOriginal.run(activity))
            assertEquals("BLOCKED", report.getString("status"))
            assertFalse(report.getBoolean("modulesLoaded"))
            assertFalse(report.getBoolean("nnMainAttempted"))
            assertFalse(report.getBoolean("gamePlayable"))
            assertTrue(report.getBoolean("cleanupComplete"))
            assertFalse(NativeOriginal.contentInUse())
        }
    }
    fun testImportButtonOpensDocumentTreePicker() {
        withSetup { setup ->
            // IntentFilter accepts a null action, so installing this blocking monitor
            // before explicit MainActivity launch would intercept that launch as well.
            val monitor = instrumentation.addMonitor(IntentFilter(Intent.ACTION_OPEN_DOCUMENT_TREE), null, true)
            try {
                onMain("click import") {
                    assertTrue(setup.view.findViewWithTag<Button>("taiko-content-choose").performClick())
                }
                assertEquals("Import must request the system document-tree picker", 1, monitor.hits)
            } finally { instrumentation.removeMonitor(monitor) }
        }
    }

    fun testPickerCancellationAndMissingReadGrantNeverClaimVerifiedContent() {
        withSetup { setup ->
            onMain("handle cancelled and write-only picker results") {
                val status = setup.view.findViewWithTag<TextView>("taiko-content-status")
                val initial = status.text.toString()
                assertTrue(setup.onActivityResult(TaikoSetupUi.TREE_REQUEST, Activity.RESULT_CANCELED, null))
                assertEquals(initial, status.text.toString())
                assertFalse(setup.onActivityResult(TaikoSetupUi.TREE_REQUEST + 1, Activity.RESULT_OK, null))
                val writeOnly = Intent().setData(Uri.parse("content://example.invalid/tree/taiko"))
                    .addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
                assertTrue(setup.onActivityResult(TaikoSetupUi.TREE_REQUEST, Activity.RESULT_OK, writeOnly))
                assertTrue(status.text.toString().contains("讀取權限"))
                assertFalse(status.text.toString().contains("內容已驗證"))
                assertFalse(setup.view.findViewWithTag<Button>("taiko-content-cancel").isEnabled)
            }
        }
    }

    fun testLocalInspectionRetryAndOriginalLaunchRemainDistinct() {
        withSetup { setup ->
            onMain("start content inspection") { setup.onStart() }
            awaitIdle(setup)
            onMain("retry content inspection") {
                val status = setup.view.findViewWithTag<TextView>("taiko-content-status")
                assertFalse(status.text.toString().contains("內容已驗證"))
                assertTrue(setup.view.findViewWithTag<Button>("taiko-content-choose").isEnabled)
                assertTrue(setup.view.findViewWithTag<Button>("taiko-content-retry").performClick())
                assertFalse(setup.view.findViewWithTag<Button>("taiko-content-retry").isEnabled)
            }
            awaitIdle(setup)
            onMain("check diagnostics and launch state") {
                val activity = setup.view.context as Activity
                assertNotNull(activity.window.decorView.findViewWithTag<Button>("diagnostics-run"))
                assertFalse(activity.window.decorView.findViewWithTag<Button>("original-entry-run").isEnabled)
                assertTrue(activity.window.decorView.findViewWithTag<TextView>("original-entry-status")
                    .text.toString().contains("尚未觀察到原版畫面"))
            }
        }
    }

    private fun awaitIdle(setup: TaikoSetupUi) {
        val deadline = SystemClock.uptimeMillis() + 10000
        var idle = false
        while (!idle && SystemClock.uptimeMillis() < deadline) {
            onMain("observe inspection completion") {
                idle = setup.view.findViewWithTag<Button>("taiko-content-retry").isEnabled
            }
            if (!idle) SystemClock.sleep(20)
        }
        assertTrue("Local inspection must finish and allow retry", idle)
    }

    private fun withSetup(action: (TaikoSetupUi) -> Unit) {
        // startActivitySync and waitForIdleSync have no timeout. A continuously paced
        // GameActivity must be observed through its lifecycle rather than global idleness.
        val activityMonitor = instrumentation.addMonitor(MainActivity::class.java.name, null, false)
        val activity = try {
            instrumentation.targetContext.startActivity(Intent(instrumentation.targetContext, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
            val observed = activityMonitor.waitForActivityWithTimeout(10000)
            assertNotNull("MainActivity onCreate was not observed within 10 seconds", observed)
            observed as MainActivity
        } finally { instrumentation.removeMonitor(activityMonitor) }
        val scratch = File(activity.cacheDir, "taiko-ui-${UUID.randomUUID()}")
        val context = object : ContextWrapper(activity) {
            override fun getFilesDir() = File(scratch, "files").apply { mkdirs() }
        }
        var setup: TaikoSetupUi? = null
        try {
            onMain("create isolated setup controls") { setup = TaikoSetupUi(activity, context) }
            action(requireNotNull(setup))
        } finally {
            onMain("destroy setup controls and finish Activity") { setup?.destroy(); activity.finish() }
            scratch.deleteRecursively()
        }
    }

    private fun <T> onMain(step: String, action: () -> T): T {
        val handler = Handler(Looper.getMainLooper())
        val done = CountDownLatch(1)
        val result = AtomicReference<Result<T>?>(null)
        val task = Runnable {
            try { result.set(runCatching(action)) } finally { done.countDown() }
        }
        assertTrue("Could not schedule UI step: $step", handler.post(task))
        if (!done.await(10, TimeUnit.SECONDS)) {
            handler.removeCallbacks(task)
            fail("UI step did not finish within 10 seconds: $step")
        }
        return requireNotNull(result.get()).getOrThrow()
    }
}
