package org.d2rmobile.diagnostics

import android.content.Intent
import android.os.SystemClock
import android.test.InstrumentationTestCase
import android.view.SurfaceView
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import org.json.JSONObject
import java.io.File

/** Explicit retail startup attempt, never an automatic synthetic-suite member.
 * Once trusted capsules exist this deliberately enters the original program.
 * A timeout/crash is a real failed attempt; the durable native journal survives. */
@Suppress("DEPRECATION")
class NativeOriginalTest : InstrumentationTestCase() {
    fun testCheckedOriginalEntry() {
        val activity = instrumentation.startActivitySync(
            Intent(instrumentation.targetContext, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        ) as MainActivity
        try {
            val deadline = SystemClock.uptimeMillis() + 30_000
            var ready = false
            while (!ready && SystemClock.uptimeMillis() < deadline) {
                instrumentation.runOnMainSync {
                    ready = activity.window.decorView.findViewWithTag<View>("diagnostics-run")?.isEnabled == true
                }
                if (!ready) SystemClock.sleep(10)
            }
            assertTrue("automatic diagnostics did not finish", ready)
            DiagnosticCoordinator.awaitWorkerQuiescence(activity)
            val lastReport = File(activity.filesDir, "original-entry-last.json")
            assertTrue("could not remove the previous attempt receipt", !lastReport.exists() || lastReport.delete())
            val frontend = JSONObject()
            instrumentation.runOnMainSync {
                val decor = activity.window.decorView
                val launch = decor.findViewWithTag<Button>("original-entry-run")
                val diagnostics = decor.findViewWithTag<View>("diagnostics-scroll")
                val controls = decor.findViewWithTag<View>("touch-control-overlay")
                val surface = descendants(decor).filterIsInstance<SurfaceView>().single()
                assertTrue("real launch button was not enabled", launch.isEnabled)
                assertEquals(View.VISIBLE, diagnostics.visibility)
                assertEquals(View.GONE, controls.visibility)
                assertTrue("real launch button did not dispatch", launch.performClick())
                // The native completion is posted back onto this same queue:
                // these are synchronous observations of actual launch mode.
                assertEquals("diagnostics still cover the GameActivity surface", View.INVISIBLE, diagnostics.visibility)
                assertEquals("draw-only controls were not exposed", View.VISIBLE, controls.visibility)
                assertTrue("GameActivity surface did not receive focus", surface.hasFocus())
                assertFalse("a second launch was offered during the request", launch.isEnabled)
                frontend.put("launchMode", JSONObject()
                    .put("diagnosticsVisible", diagnostics.isShown)
                    .put("controlsVisible", controls.isShown)
                    .put("surfaceFocused", surface.hasFocus())
                    .put("launchEnabled", launch.isEnabled))
            }
            val completedDeadline = SystemClock.uptimeMillis() + 30_000
            var restored = false
            while (!restored && SystemClock.uptimeMillis() < completedDeadline) {
                instrumentation.runOnMainSync {
                    restored = lastReport.isFile && activity.window.decorView
                        .findViewWithTag<View>("diagnostics-scroll").visibility == View.VISIBLE
                }
                if (!restored) SystemClock.sleep(10)
            }
            assertTrue("actual retail request did not return and restore diagnostics; inspect its native attempt journal", restored)
            val report = JSONObject(lastReport.readText())
            instrumentation.runOnMainSync {
                val decor = activity.window.decorView
                val launch = decor.findViewWithTag<Button>("original-entry-run")
                val diagnostics = decor.findViewWithTag<View>("diagnostics-scroll")
                val controls = decor.findViewWithTag<View>("touch-control-overlay")
                val text = decor.findViewWithTag<TextView>("original-entry-status").text.toString()
                assertEquals(View.VISIBLE, diagnostics.visibility)
                assertEquals("controls still produce input after return", View.GONE, controls.visibility)
                assertEquals("retry does not reflect native cleanup", report.getBoolean("cleanupComplete"), launch.isEnabled)
                assertTrue("native result was not shown", text.contains(report.getString("status")))
                frontend.put("restoredMode", JSONObject()
                    .put("diagnosticsVisible", diagnostics.isShown)
                    .put("controlsVisible", controls.isShown)
                    .put("launchEnabled", launch.isEnabled)
                    .put("statusText", text))
            }
            File(activity.filesDir, "original-entry-frontend-instrumentation.json").writeText(frontend.toString(2))
            File(activity.filesDir, "original-entry-instrumentation.json").writeText(report.toString(2))
            assertFalse("an entry attempt cannot attest a playable game", report.getBoolean("gamePlayable"))
            assertEquals("NOT_OBSERVED", report.getString("originalFirstFrame"))
            val journalPath = report.getString("journal")
            assertTrue(journalPath.startsWith("game/original-attempts/attempt-"))
            val journal = File(activity.filesDir, journalPath).readLines().map(::JSONObject)
            assertEquals("preparation", journal.first().getString("event"))
            assertEquals("result", journal.last().getString("event"))
            assertEquals(report.getString("status"), journal.last().getString("status"))
            if (!report.getBoolean("modulesLoaded")) {
                assertEquals("BLOCKED", report.getString("status"))
                assertFalse(report.getBoolean("nnMainAttempted"))
                assertFalse(report.getBoolean("nnMainReturned"))
                assertTrue(report.getBoolean("cleanupComplete"))
                assertTrue(report.getString("error").isNotBlank())
                assertFalse("refused preparation must not reach an SDK call", journal.any { it.optString("event") == "bootstrap" })
            } else {
                // Returned native operations are auditable independently of the
                // test outcome. No original frame/menu assertion is fabricated.
                assertTrue(journal.any { it.optString("event") == "capsule_verified" })
                assertTrue(journal.any { it.optString("event") == "bootstrap" })
                assertTrue("original startup stopped: $report", report.getBoolean("nnMainReturned"))
                assertTrue("original runtime retained real resources: $report", report.getBoolean("cleanupComplete"))
            }
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
        }
    }

    private fun descendants(view: View): List<View> = listOf(view) +
        if (view is ViewGroup) (0 until view.childCount).flatMap { descendants(view.getChildAt(it)) } else emptyList()
}
