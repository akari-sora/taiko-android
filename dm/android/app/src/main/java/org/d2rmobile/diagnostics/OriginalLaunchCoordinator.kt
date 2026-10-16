package org.d2rmobile.diagnostics

import android.os.Handler
import android.os.Looper
import android.util.AtomicFile
import org.json.JSONObject
import java.io.File
import java.lang.ref.WeakReference
import java.util.concurrent.Executors

/** Keeps one user-requested retail attempt across Activity replacement.
 * This UI state does not grant native ownership or attest original execution. */
internal object OriginalLaunchCoordinator {
    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor { task -> Thread(task, "original-entry-owner") }
    private var receiver = WeakReference<MainActivity>(null)
    private var running = false
    private var report: JSONObject? = null
    private var failure: String? = null
    private var retryAllowed = true

    // State and receiver changes belong exclusively to the main queue. The
    // worker holds the requested Activity only for the unchanged JNI call.
    fun attach(activity: MainActivity): Boolean {
        checkMainThread()
        receiver = WeakReference(activity)
        render()
        return running || !retryAllowed
    }

    fun detach(activity: MainActivity) {
        checkMainThread()
        if (receiver.get() === activity) receiver.clear()
    }

    fun blocksDiagnostics(): Boolean {
        checkMainThread()
        return running || !retryAllowed
    }

    fun request(activity: MainActivity) {
        checkMainThread()
        if (running || !retryAllowed || activity.isDestroyed || activity.isFinishing) return
        receiver = WeakReference(activity)
        running = true
        report = null
        failure = null
        // Cancel only queued/stale diagnostic UI work; native DiagnosticCall
        // still independently refuses an owner that is already executing.
        DiagnosticCoordinator.cancel(activity)
        render()
        val requestedActivity = WeakReference(activity)
        val record = AtomicFile(File(activity.filesDir, "original-entry-last.json"))
        worker.execute {
            var result: JSONObject? = null
            var error: String? = null
            try {
                val owner = requestedActivity.get()
                    ?: throw IllegalStateException("The requested Activity no longer exists")
                result = JSONObject(NativeOriginal.run(owner))
                val stream = record.startWrite()
                try {
                    stream.write(result.toString(2).toByteArray(Charsets.UTF_8))
                    record.finishWrite(stream)
                } catch (failure: Exception) {
                    record.failWrite(stream)
                    throw failure
                }
            } catch (failure: Exception) {
                error = failure.message ?: failure.javaClass.simpleName
            }
            // Even a Java/reporting exception may follow a real native call.
            // Never infer cleanup merely because the background task returned.
            val nativeReleased = runCatching {
                val state = JSONObject(NativeDiagnosticOwner.sessionStatus())
                !state.getBoolean("retained") && !state.getBoolean("closing")
            }.getOrDefault(false)
            val canRetry = nativeReleased && (result == null || result.optBoolean("cleanupComplete", false))
            val completedReport = result
            val completedError = error
            main.post {
                running = false
                report = completedReport
                failure = completedError
                retryAllowed = canRetry
                render()
            }
        }
    }

    private fun render() {
        receiver.get()?.takeUnless { it.isDestroyed || it.isFinishing }
            ?.renderOriginalLaunch(running, report, failure, retryAllowed)
    }

    private fun checkMainThread() = check(Looper.myLooper() == Looper.getMainLooper())
}
