package org.d2rmobile.diagnostics

import android.content.Intent
import android.os.SystemClock
import android.test.InstrumentationTestCase
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit

/** Actual rewritten guest -> original AudioOut -> focus -> AAudio -> kernel
 * event, using authored PCM. This does not claim original game audio. */
@Suppress("DEPRECATION")
class NativeAudioTest : InstrumentationTestCase() {
    private val executor = Executors.newSingleThreadExecutor()
    private val activities = mutableListOf<MainActivity>()
    private external fun nativePhase(): Int

    private fun start(): MainActivity {
        val gate = CountDownLatch(1)
        activities.lastOrNull()?.let { previous ->
            DiagnosticCoordinator.setBeforeOwnershipObserver(previous) { gate.await(10, TimeUnit.SECONDS) }
        }
        try {
            val owner = instrumentation.startActivitySync(
                Intent(instrumentation.targetContext, MainActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            ) as MainActivity
            activities.add(owner)
            instrumentation.runOnMainSync { DiagnosticCoordinator.cancel(owner) }
            gate.countDown()
            DiagnosticCoordinator.awaitWorkerQuiescence(owner)
            DiagnosticCoordinator.setBeforeOwnershipObserver(owner, null)
            instrumentation.waitForIdleSync()
            return owner
        } finally {
            gate.countDown()
        }
    }

    private fun awaitPhase(expected: Int, result: Future<String>) {
        val deadline = SystemClock.uptimeMillis() + 25_000
        while (SystemClock.uptimeMillis() < deadline) {
            if (nativePhase() == expected) return
            if (result.isDone) throw AssertionError("Audio probe ended before phase $expected: ${result.get()}")
            SystemClock.sleep(10)
        }
        throw AssertionError("Audio probe did not reach phase $expected; current=${nativePhase()}")
    }

    // Keep SAM/lambda helpers out of JUnit3's public test-name discovery.
    fun testRewrittenGuestAudioOutAndRealActivitySuspendResume() = runAudioScenario()

    private fun runAudioScenario() {
        val first = start()
        val result = executor.submit(Callable { first.runAudioDiagnostics() })
        awaitPhase(2, result)
        instrumentation.runOnMainSync { assertTrue(first.moveTaskToBack(true)) }
        awaitPhase(3, result)
        val replacement = start()
        val report = JSONObject(result.get(30, TimeUnit.SECONDS))
        File(replacement.filesDir, "audio-hle-report.json").writeText(report.toString(2))
        assertEquals("audio-hle", report.getString("phase"))
        assertTrue(report.getBoolean("syntheticOnly"))
        assertFalse(report.getBoolean("gamePlayable"))
        assertFalse(report.getBoolean("originalGameAudio"))
        val checks = report.getJSONArray("checks")
        assertEquals(6, checks.length())
        for (i in 0 until checks.length()) {
            val check = checks.getJSONObject(i)
            assertEquals(check.toString(), "PASS", check.getString("status"))
        }
        val audio = report.getJSONObject("audio")
        assertEquals(6, audio.getInt("channels"))
        assertEquals(48000, audio.getInt("sampleRate"))
        assertEquals(14, audio.getInt("importBindings"))
        assertEquals(2, audio.getInt("createEventSvcCalls"))
        assertTrue(audio.getBoolean("copiedGuestPcm"))
        assertTrue(audio.getLong("eventWaits") > 0)
        assertTrue(audio.getLong("playingNonzeroSamples") > 0)
        assertTrue(audio.getLong("playingPresentedFrames") > 0)
        assertTrue(audio.getLong("backgroundReleasedBuffers") > 0)
        assertTrue(audio.getLong("resumedCallbacks") > audio.getLong("backgroundCallbacks"))
        assertTrue(audio.getLong("resumedNonzeroSamples") > audio.getLong("playingNonzeroSamples"))
        assertTrue(audio.getLong("resumedPresentedFrames") > 0)
        assertTrue(audio.getBoolean("teardownComplete"))
    }

    override fun tearDown() {
        activities.forEach { owner -> instrumentation.runOnMainSync { if (!owner.isDestroyed) owner.finish() } }
        executor.shutdownNow()
        executor.awaitTermination(35, TimeUnit.SECONDS)
        super.tearDown()
    }
}
