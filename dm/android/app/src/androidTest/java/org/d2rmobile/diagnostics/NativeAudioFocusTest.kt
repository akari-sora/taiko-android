package org.d2rmobile.diagnostics

import android.content.Intent
import android.media.AudioAttributes
import android.media.AudioFocusRequest
import android.media.AudioManager
import android.os.SystemClock
import android.test.InstrumentationTestCase
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Authored playback lease client through the real AudioManager bridge.
 * Device PCM and HLE queue tests are separate; this does not claim game audio. */
@Suppress("DEPRECATION")
class NativeAudioFocusTest : InstrumentationTestCase() {
    private val executor = Executors.newSingleThreadExecutor()
    private val activities = mutableListOf<MainActivity>()
    private external fun nativeAcquire(): Int
    private external fun nativeRelease()
    private external fun nativeCancel()
    private external fun nativeHasFocus(): Boolean

    private fun start(): MainActivity {
        // A synthetic runtime's shutdown correctly cancels playback leases.
        // Keep automatic fixture batches out of this external focus client.
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

    private fun request(owner: MainActivity): AudioFocusRequest? {
        val field = MainActivity::class.java.getDeclaredField("audio").apply { isAccessible = true }
        val coordinator = field.get(owner)
        return AudioCoordinator::class.java.getDeclaredField("activeRequest")
            .apply { isAccessible = true }.get(coordinator) as? AudioFocusRequest
    }

    private fun waitRequest(owner: MainActivity, active: Boolean): AudioFocusRequest? {
        val deadline = SystemClock.uptimeMillis() + 10_000
        while (SystemClock.uptimeMillis() < deadline) {
            var current: AudioFocusRequest? = null
            instrumentation.runOnMainSync { current = request(owner) }
            if ((current != null) == active) return current
            SystemClock.sleep(10)
        }
        throw AssertionError("AudioManager request active=$active was not reached")
    }

    private fun acquire(): Int = executor.submit(Callable { nativeAcquire() }).get(10, TimeUnit.SECONDS)

    private fun waitFocus(granted: Boolean) {
        val deadline = SystemClock.uptimeMillis() + 10_000
        while (SystemClock.uptimeMillis() < deadline) {
            if (nativeHasFocus() == granted) return
            SystemClock.sleep(10)
        }
        throw AssertionError("Actual focus plus worker commit granted=$granted was not reached")
    }

    fun testActualGrantUiRefusalAndLastLeaseAbandon() {
        val owner = start()
        instrumentation.runOnMainSync {
            assertNull(request(owner)) // Idle diagnostics do not request focus.
            assertEquals(0, nativeAcquire())
        }
        assertEquals(1, acquire()) // Requires actual AUDIOFOCUS_REQUEST_GRANTED.
        val first = waitRequest(owner, true)
        assertEquals(1, acquire())
        nativeRelease()
        instrumentation.runOnMainSync { assertSame(first, request(owner)) }
        nativeRelease()
        waitRequest(owner, false)
        instrumentation.runOnMainSync { owner.finish() }
        instrumentation.waitForIdleSync()
        assertEquals(0, acquire())
    }

    fun testBackgroundAndReplacementUseCurrentActivityGrant() {
        val first = start()
        assertEquals(1, acquire())
        waitRequest(first, true)
        instrumentation.runOnMainSync { assertTrue(first.moveTaskToBack(true)) }
        waitRequest(first, false)
        assertEquals(0, acquire())
        val replacement = start()
        waitRequest(replacement, true) // A live playback lease requests on resume.
        assertEquals(1, acquire())
        nativeRelease()
        waitRequest(replacement, true)
        nativeRelease()
        waitRequest(replacement, false)
    }

    fun testActualExclusiveTransientLossAndGain() {
        val owner = start()
        assertEquals(1, acquire())
        val initial = waitRequest(owner, true)
        val manager = owner.getSystemService(AudioManager::class.java)!!
        val competing = AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN_TRANSIENT_EXCLUSIVE)
            .setAudioAttributes(AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_GAME)
                .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC).build())
            .setOnAudioFocusChangeListener { }.build()
        try {
            instrumentation.runOnMainSync {
                assertEquals(AudioManager.AUDIOFOCUS_REQUEST_GRANTED, manager.requestAudioFocus(competing))
            }
            // Exclusive transient focus interrupts even devices configured for
            // concurrent ordinary music focus. Both transitions are OS callbacks.
            waitFocus(false)
            manager.abandonAudioFocusRequest(competing)
            waitFocus(true)
            assertEquals(1, acquire())
            assertSame(initial, waitRequest(owner, true))
            nativeRelease()
            nativeRelease()
            waitRequest(owner, false)
        } finally {
            manager.abandonAudioFocusRequest(competing)
        }
    }

    override fun tearDown() {
        nativeCancel()
        activities.forEach { owner -> instrumentation.runOnMainSync { if (!owner.isDestroyed) owner.finish() } }
        executor.shutdownNow()
        executor.awaitTermination(5, TimeUnit.SECONDS)
        super.tearDown()
    }
}
