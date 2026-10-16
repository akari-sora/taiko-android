package org.d2rmobile.diagnostics

import android.content.Intent
import android.test.InstrumentationTestCase
import android.widget.Button
import android.widget.EditText
import android.widget.TextView

/** Exercises real setup controls without downloading copyrighted resources or altering user files. */
@Suppress("DEPRECATION")
class ResourceUiTest : InstrumentationTestCase() {
    fun testFolderPickerCancellationAndMissingReadGrantDoNotStartTransfer() {
        val activity = instrumentation.startActivitySync(
            Intent(instrumentation.targetContext, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        ) as MainActivity
        try {
            instrumentation.runOnMainSync {
                val setup = ResourceSetupUi(activity)
                try {
                    val status = setup.view.findViewWithTag<TextView>("resource-status")
                    val initial = status.text.toString()
                    assertTrue(setup.onActivityResult(ResourceSetupUi.TREE_REQUEST, android.app.Activity.RESULT_CANCELED, null))
                    assertEquals("Cancelling the picker must not report a permission error", initial, status.text.toString())
                    assertFalse(ResourceTransferService.current.running)
                    val writeOnly = Intent().setData(android.net.Uri.parse("content://example.invalid/tree/test"))
                        .addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
                    assertTrue(setup.onActivityResult(ResourceSetupUi.TREE_REQUEST, android.app.Activity.RESULT_OK, writeOnly))
                    assertTrue("Missing read access needs a visible read-permission explanation",
                        status.text.toString().contains("讀取") || status.text.toString().contains("read permission"))
                    assertFalse("A write-only picker result must not start an import", ResourceTransferService.current.running)
                } finally { setup.destroy() }
            }
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
        }
    }

    fun testSetupRejectsInsecureSourcesAndKeepsDiagnosticsAvailable() {
        val activity = instrumentation.startActivitySync(
            Intent(instrumentation.targetContext, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        ) as MainActivity
        try {
            val deadline = android.os.SystemClock.uptimeMillis() + 10000
            var available = false
            while (!available && android.os.SystemClock.uptimeMillis() < deadline) {
                instrumentation.runOnMainSync {
                    available = activity.window.decorView.findViewWithTag<Button>("resource-download")?.isEnabled == true
                }
                if (!available) android.os.SystemClock.sleep(25)
            }
            assertTrue("Setup must become available after the local inspection", available)
            instrumentation.runOnMainSync {
                val url = activity.window.decorView.findViewWithTag<EditText>("resource-source-url")
                assertNotNull("Resource setup URL field must exist", url)
                val download = activity.window.decorView.findViewWithTag<Button>("resource-download")
                assertNotNull("Resource setup download button must exist", download)
                url.setText("http://example.invalid/Update/RomFs/")
                download.performClick()
                val status = activity.window.decorView.findViewWithTag<TextView>("resource-status")
                assertTrue("Insecure sources must be rejected with a visible HTTPS explanation",
                    status.text.toString().contains("HTTPS"))
                assertFalse("A rejected URL must not start a transfer", ResourceTransferService.current.running)
                assertNotNull(activity.window.decorView.findViewWithTag<Button>("diagnostics-run"))
                assertNull("Setup must not advertise an unwired game launcher",
                    activity.window.decorView.findViewWithTag<Button>("resource-start-game"))
            }
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
        }
    }
}
