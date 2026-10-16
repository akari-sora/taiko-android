package org.d2rmobile.diagnostics

import android.app.AlertDialog
import android.content.Intent
import android.os.SystemClock
import android.test.InstrumentationTestCase
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.BaseInputConnection
import android.widget.EditText
import android.widget.TextView
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit

/** Authored owned-GuestStack caller through the real native broker, dialog and IME.
 * This does not launch an original guest or prove character creation. */
@Suppress("DEPRECATION")
class NativeKeyboardTest : InstrumentationTestCase() {
    private val executor = Executors.newSingleThreadExecutor()
    private var activity: MainActivity? = null
    private external fun sdkStringOnGuestStack(mode: Int): String?
    private external fun enterTextOnGuestStack(title: String, subtitle: String, guide: String,
        initial: String, minimum: Int, maximum: Int): String?
    private fun start(): MainActivity = (instrumentation.startActivitySync(
        Intent(instrumentation.targetContext, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
    ) as MainActivity).also {
        activity = it
        instrumentation.runOnMainSync { DiagnosticCoordinator.cancel(it) }
        DiagnosticCoordinator.awaitWorkerQuiescence(it)
        instrumentation.waitForIdleSync()
    }

    private fun request(minimum: Int = 2, maximum: Int = 8, initial: String = "初始Ab"): Future<String?> =
        executor.submit(Callable {
            enterTextOnGuestStack("Keyboard title", "Keyboard subtitle", "Keyboard guide", initial, minimum, maximum)
        })

    // Inspect the existing dialog without adding a test-only production entry.
    // All mutations still use the actual EditText / InputConnection / buttons.
    private fun shown(owner: MainActivity): AlertDialog? {
        val keyboardField = MainActivity::class.java.getDeclaredField("keyboard").apply { isAccessible = true }
        val coordinator = keyboardField.get(owner)
        val dialogField = KeyboardCoordinator::class.java.getDeclaredField("dialog").apply { isAccessible = true }
        return (dialogField.get(coordinator) as? AlertDialog)?.takeIf { it.isShowing }
    }
    private fun waitDialog(owner: MainActivity): AlertDialog {
        val deadline = SystemClock.uptimeMillis() + 10_000
        while (SystemClock.uptimeMillis() < deadline) {
            var dialog: AlertDialog? = null
            instrumentation.runOnMainSync { dialog = shown(owner) }
            if (dialog != null) return dialog!!
            SystemClock.sleep(10)
        }
        throw AssertionError("Keyboard dialog was not shown")
    }
    private fun waitDismissed(owner: MainActivity) {
        val deadline = SystemClock.uptimeMillis() + 10_000
        while (SystemClock.uptimeMillis() < deadline) {
            var visible = false
            instrumentation.runOnMainSync { visible = shown(owner) != null }
            if (!visible) return
            SystemClock.sleep(10)
        }
        throw AssertionError("Cancelled keyboard dialog was not dismissed")
    }
    private fun descendants(view: View): List<View> = listOf(view) + if (view is ViewGroup)
        (0 until view.childCount).flatMap { descendants(view.getChildAt(it)) } else emptyList()
    private fun input(dialog: AlertDialog): EditText =
        dialog.window!!.decorView.findViewWithTag("game-keyboard-input")

    fun testChineseEnglishEmojiRoundTripAndDialogMetadata() {
        val owner = start()
        val result = request()
        val dialog = waitDialog(owner)
        instrumentation.runOnMainSync {
            val labels = descendants(dialog.window!!.decorView).filterIsInstance<TextView>().map { it.text.toString() }
            assertTrue(labels.containsAll(listOf("Keyboard title", "Keyboard subtitle", "Keyboard guide")))
            assertEquals("初始Ab", input(dialog).text.toString())
            input(dialog).setText("中文AB😀")
            assertTrue(dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled)
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
        }
        assertEquals("中文AB😀", result.get(5, TimeUnit.SECONDS))
        // Calling the synchronous entry from the UI thread returns immediately.
        instrumentation.runOnMainSync(object : Runnable {
            override fun run() {
                assertNull(KeyboardCoordinator.enterText("", "", "", "", 0, 8))
            }
        })
    }

    fun testUtf16LimitsAndImeCompositionAreAppliedBeforeConfirm() {
        val owner = start()
        val result = request(minimum = 2, maximum = 3, initial = "A")
        val dialog = waitDialog(owner)
        instrumentation.runOnMainSync {
            val edit = input(dialog)
            assertEquals(0, edit.inputType and android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS)
            assertFalse(dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled)
            edit.setText("😀😀")
            assertFalse(dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled)
            assertEquals("😀😀", edit.text.toString()) // The IME text is not split/truncated.
            edit.setText("")
            val connection = edit.onCreateInputConnection(android.view.inputmethod.EditorInfo())!!
            connection.setComposingText("中文", 1)
            assertEquals("中文", edit.text.toString())
            assertTrue(BaseInputConnection.getComposingSpanStart(edit.text) >= 0)
            assertFalse(dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled)
            connection.finishComposingText()
            assertTrue(dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled)
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
            connection.closeConnection()
        }
        assertEquals("中文", result.get(5, TimeUnit.SECONDS))
    }

    fun testCancelAndBackgroundReleaseTheNativeWait() {
        val owner = start()
        val cancelled = request()
        val dialog = waitDialog(owner)
        instrumentation.runOnMainSync { dialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick() }
        assertNull(cancelled.get(5, TimeUnit.SECONDS))
        val background = request()
        waitDialog(owner)
        instrumentation.runOnMainSync { assertTrue(owner.moveTaskToBack(true)) }
        assertNull(background.get(5, TimeUnit.SECONDS))
    }

    fun testReplacementActivityCancelsOldRequestAndCanAcceptNewText() {
        val first = start()
        val retired = request()
        waitDialog(first)
        val second = start()
        assertNull(retired.get(5, TimeUnit.SECONDS))
        val current = request()
        val dialog = waitDialog(second)
        instrumentation.runOnMainSync {
            input(dialog).setText("新角色Ab")
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
        }
        assertEquals("新角色Ab", current.get(5, TimeUnit.SECONDS))
    }

    fun testShutdownDismissesOnlyCancelledDialogAndAllowsLaterInput() {
        val owner = start()
        val cancelled = request()
        waitDialog(owner)
        instrumentation.runOnMainSync(object : Runnable {
            override fun run() = KeyboardCoordinator.cancelPending()
        })
        assertNull(cancelled.get(5, TimeUnit.SECONDS))
        waitDismissed(owner)
        val current = request()
        val dialog = waitDialog(owner)
        instrumentation.runOnMainSync {
            input(dialog).setText("Ab")
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
        }
        assertEquals("Ab", current.get(5, TimeUnit.SECONDS))
    }

    fun testCommittedUnicodeNameAndQuantityRules() {
        assertNull(KeyboardRules.error("中文Ab", 0, 1002, 3006, characterName = true))
        assertNull(KeyboardRules.error("Ab-c", 0, 1002, 3006, characterName = true))
        for (invalid in listOf("", "A", "-Ab", "Ab-_c", "中文中文中文", "Ab😀"))
            assertNotNull(KeyboardRules.error(invalid, 0, 1002, 3006, characterName = true))
        assertNotNull(KeyboardRules.error("\uD800", 0, 1002, 3006))
        assertNotNull(KeyboardRules.error("\uDC00", 0, 1002, 3006))
        assertNull(KeyboardRules.error("123", 0, 1002, 3006, numericMax = 123))
        assertNotNull(KeyboardRules.error("124", 0, 1002, 3006, numericMax = 123))
        assertNotNull(KeyboardRules.error("999999999999999999999", 0, 1002, 3006, numericMax = 123))
    }

    private fun sdkRequest(mode: Int = 0): Future<String?> =
        executor.submit(Callable { sdkStringOnGuestStack(mode) })

    private fun sdkResult(result: Future<String?>, expected: Int, text: String? = null) {
        val report = org.json.JSONObject(result.get(15, TimeUnit.SECONDS)!!)
        assertEquals(report.toString(), true, report.getBoolean("invoked"))
        assertTrue(report.toString(), report.getBoolean("closed"))
        assertTrue(report.toString(), report.getBoolean("owned"))
        assertTrue(report.toString(), report.getBoolean("guards"))
        assertEquals(report.toString(), "", report.getString("error"))
        assertEquals(expected, report.getInt("sdkResult"))
        if (text == null) assertTrue(report.toString(), report.getBoolean("unchanged"))
        else assertEquals(text.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it.toInt() and 255) }, report.getString("utf8Hex"))
        val directory = java.io.File(instrumentation.targetContext.filesDir, "keyboard-sdk-output").apply { mkdirs() }
        java.io.File(directory, "mode-${report.getInt("mode")}-${SystemClock.uptimeMillis()}.json").writeText(report.toString())
    }

    fun testSdkStringChineseThroughRealInputConnectionUtf8AndUtf16() {
        val owner = start()
        for (mode in 0..1) {
            val result = sdkRequest(mode)
            val dialog = waitDialog(owner)
            instrumentation.runOnMainSync {
                assertEquals("初始Ab", input(dialog).text.toString())
                input(dialog).setText("")
                val connection = input(dialog).onCreateInputConnection(android.view.inputmethod.EditorInfo())!!
                connection.setComposingText("中文Ab😀", 1)
                assertFalse(dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled)
                connection.finishComposingText()
                assertTrue(dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled)
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
                connection.closeConnection()
            }
            sdkResult(result, 0, "中文Ab😀")
        }
    }

    fun testSdkStringCancelInvalidSpanAndStaleGenerationDoNotWrite() {
        val owner = start()
        val cancelled = sdkRequest()
        val dialog = waitDialog(owner)
        instrumentation.runOnMainSync { dialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick() }
        sdkResult(cancelled, 0x29f)
        for (mode in 2..3) sdkResult(sdkRequest(mode), 0x29f)
    }

    fun testSdkStringBackgroundCancelsBeforeOutputPublication() {
        val owner = start()
        val result = sdkRequest()
        waitDialog(owner)
        instrumentation.runOnMainSync { assertTrue(owner.moveTaskToBack(true)) }
        sdkResult(result, 0x29f)
    }

    override fun tearDown() {
        activity?.let { owner -> instrumentation.runOnMainSync { owner.finish() } }
        executor.shutdownNow()
        executor.awaitTermination(5, TimeUnit.SECONDS)
        super.tearDown()
    }
}
