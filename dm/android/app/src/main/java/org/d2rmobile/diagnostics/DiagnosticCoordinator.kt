package org.d2rmobile.diagnostics

import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.content.pm.ApplicationInfo
import org.json.JSONObject
import java.lang.ref.WeakReference
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** An ownership refusal is deferred work, never a failed synthetic probe report. */
class DiagnosticOwnershipException(message: String) : IllegalStateException(message)

/** Native ownership covers preparation through restoration, including direct JNI calls. */
object NativeDiagnosticOwner {
    init { System.loadLibrary("d2r_diagnostics") }

    @JvmStatic external fun beginAutomaticBatch(): Long
    @JvmStatic external fun endAutomaticBatch(token: Long): Boolean
    @JvmStatic external fun sessionStatus(): String
}

/** One process queue: an Activity's destruction never releases an executing native owner. */
object DiagnosticCoordinator {
    private class Ticket(activity: MainActivity) {
        val activity = WeakReference(activity)
        @Volatile var cancelled = false
    }

    private data class Readiness(val generation: Long, val revision: Long)
    private val main = Handler(Looper.getMainLooper())
    private val worker = ScheduledThreadPoolExecutor(1)
    private val lock = Any()
    private var pending: Ticket? = null
    private var scheduled = false
    private var active: Ticket? = null
    // A failed native close retains ownership. Only an explicit successful owner
    // release may resume pending work; a timer must never hand off that state.
    private var cleanupRetained = false
    private var batchStarts = 0L
    private val beforeOwnershipObserver = AtomicReference<(() -> Unit)?>(null)

    /** Debug instrumentation seam; runs once outside every coordinator/native lock. */
    fun setBeforeOwnershipObserver(activity: MainActivity, observer: (() -> Unit)?) {
        check((activity.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            "Diagnostic scheduling observers require a debuggable application"
        }
        beforeOwnershipObserver.set(observer)
    }

    /** A main-queue drain alone cannot prove that delayed worker retries finished. */
    fun awaitWorkerQuiescence(activity: MainActivity, timeoutMs: Long = 10_000): Long {
        check((activity.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0)
        check(Looper.myLooper() != Looper.getMainLooper()) { "Do not wait on the UI thread" }
        require(timeoutMs in 1L..60_000L)
        val done = CountDownLatch(1)
        val cancelled = AtomicBoolean(false)
        val result = AtomicLong(-1)
        val deadline = SystemClock.uptimeMillis() + timeoutMs
        val observer = object : Runnable {
            override fun run() {
                if (cancelled.get()) return
                val count = synchronized(lock) {
                    if (pending == null && active == null && !scheduled && !cleanupRetained &&
                        worker.queue.isEmpty()) batchStarts else -1L
                }
                if (count >= 0) {
                    result.set(count)
                    done.countDown()
                } else if (SystemClock.uptimeMillis() < deadline) {
                    worker.schedule(this, 10, TimeUnit.MILLISECONDS)
                } else done.countDown()
            }
        }
        worker.execute(observer)
        try {
            check(done.await(timeoutMs, TimeUnit.MILLISECONDS) && result.get() >= 0) {
                "Diagnostic worker did not become quiescent"
            }
            return result.get()
        } finally {
            cancelled.set(true)
        }
    }

    fun request(activity: MainActivity) {
        synchronized(lock) {
            pending?.cancelled = true
            pending = Ticket(activity)
        }
        activity.diagnosticsDeferred("Waiting for native window and diagnostic ownership…")
        schedule()
    }

    fun cancel(activity: MainActivity) {
        synchronized(lock) {
            pending?.takeIf { it.activity.get() === activity }?.let {
                it.cancelled = true
                pending = null
            }
            // Marking an active ticket only suppresses stale UI delivery. Its
            // worker still finishes all cleanup before releasing the owner.
            active?.takeIf { it.activity.get() === activity }?.cancelled = true
        }
    }

    /** Called after an orderly persistent-session close, outside native locks. */
    fun ownerReleased() {
        synchronized(lock) { cleanupRetained = false }
        schedule()
    }

    fun readinessChanged() = schedule()

    private fun schedule(delayMs: Long = 0) {
        synchronized(lock) {
            if (scheduled || active != null || cleanupRetained || pending == null) return
            scheduled = true
        }
        worker.schedule({ attempt() }, delayMs, TimeUnit.MILLISECONDS)
    }

    private fun live(ticket: Ticket, activity: MainActivity): Boolean =
        !ticket.cancelled && !activity.isDestroyed && !activity.isFinishing

    private fun readiness(activity: MainActivity): Readiness? {
        val value = JSONObject(activity.runInputDiagnostics(false))
        val viewport = value.optJSONObject("viewport") ?: return null
        if (!value.optBoolean("available") || !value.optBoolean("resumed") ||
            !value.optBoolean("focused") || !value.optBoolean("hleResolved") ||
            !value.optBoolean("windowAvailable") ||
            value.optLong("nativeWidth") <= 0 || value.optLong("nativeHeight") <= 0 ||
            !(viewport.optDouble("width") > 0) || !(viewport.optDouble("height") > 0) ||
            !(viewport.optDouble("density") > 0)) return null
        val generation = value.optLong("generation")
        val revision = value.optLong("revision")
        return if (generation > 0 && revision > 0) Readiness(generation, revision) else null
    }

    private fun defer(ticket: Ticket, text: String) {
        main.post {
            val activity = ticket.activity.get()
            if (activity != null && live(ticket, activity)) activity.diagnosticsDeferred(text)
        }
    }

    private fun attempt() {
        val ticket = synchronized(lock) {
            scheduled = false
            if (cleanupRetained || active != null) return
            pending ?: return
        }
        val activity = ticket.activity.get()
        if (activity == null || !live(ticket, activity)) {
            synchronized(lock) { if (pending === ticket) pending = null }
            schedule()
            return
        }
        var token = 0L
        var closed = true
        var completion: (() -> Unit)? = null
        try {
            val before = readiness(activity)
            if (before == null) {
                defer(ticket, "Diagnostics deferred: waiting for a resumed, focused native window.")
                return
            }
            beforeOwnershipObserver.getAndSet(null)?.invoke()
            token = NativeDiagnosticOwner.beginAutomaticBatch()
            if (token == 0L) {
                defer(ticket, "Diagnostics deferred (BUSY): ${NativeDiagnosticOwner.sessionStatus()}")
                return
            }
            // A provider can retire while we acquire the lease. Revalidate the
            // exact snapshot before any global native preparation is permitted.
            if (!live(ticket, activity) || readiness(activity) != before) return
            val claimed = synchronized(lock) {
                if (pending !== ticket || ticket.cancelled) false else {
                    pending = null
                    active = ticket
                    batchStarts++
                    true
                }
            }
            if (!claimed) return
            completion = activity.executeDiagnosticBatch(token, before.generation, before.revision)
        } catch (error: Exception) {
            if (error is DiagnosticOwnershipException) {
                synchronized(lock) {
                    // Retain this request only if no newer Activity has queued
                    // work. A failed close below still prevents any retry.
                    if (pending == null && live(ticket, activity)) pending = ticket
                }
            }
            defer(ticket, "Diagnostics deferred: ${error.message ?: error.javaClass.simpleName}")
        } finally {
            if (token != 0L) {
                closed = try { NativeDiagnosticOwner.endAutomaticBatch(token) } catch (_: Exception) { false }
            }
            synchronized(lock) {
                if (active === ticket) active = null
                if (!closed) cleanupRetained = true
            }
            if (!closed) {
                defer(ticket, "Diagnostics paused: native cleanup retained ownership. ${runCatching { NativeDiagnosticOwner.sessionStatus() }.getOrDefault("")}")
                val waiting = synchronized(lock) { pending }
                if (waiting != null && waiting !== ticket) defer(waiting, "Diagnostics deferred: previous native cleanup still owns the process.")
            } else {
                // The enabled button is also a readiness receipt used by the
                // instrumentation suite. Publish completion only after release.
                if (live(ticket, activity)) completion?.invoke()
                // Also retries the latest live ticket after a readiness miss or
                // BUSY refusal. No Activity/UI thread waits for native ownership.
                schedule(100)
            }
        }
    }
}
