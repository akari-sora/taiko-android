package org.d2rmobile.diagnostics

import android.os.Build
import android.os.Bundle
import android.content.Intent
import android.util.AtomicFile
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.view.SurfaceView
import android.view.View
import android.view.ViewGroup
import android.view.ViewTreeObserver
import android.view.Choreographer
import android.view.WindowManager
import com.google.androidgamesdk.GameActivity
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Resource preparation, platform probes and the checked original-entry attempt. */
class MainActivity : GameActivity() {
    private lateinit var status: TextView
    private lateinit var output: TextView
    private lateinit var rerun: Button
    private lateinit var resourcesUi: ResourceSetupUi
    private lateinit var controllers: ControllerDevices
    private lateinit var keyboard: KeyboardCoordinator
    private lateinit var audio: AudioCoordinator
    private lateinit var originalStatus: TextView
    private lateinit var originalLaunch: Button
    private lateinit var diagnosticsScroll: ScrollView
    private lateinit var touchControls: TouchControlOverlay
    private var windowFocusCallbacks = 0L
    private var lastWindowFocus = false
    private var decorFocusCallbacks = 0L
    private var decorFocusReconciliations = 0L
    private var lastReconciledDecorFocus = false
    private var activityResumed = false
    private val displayFrameCallback = object : Choreographer.FrameCallback {
        override fun doFrame(frameTimeNanos: Long) {
            if (!activityResumed || isDestroyed || isFinishing) return
            // A real display tick paces NVN acquisition. It is not a posted
            // game frame or evidence that a buffer reached display scanout.
            nativeDisplayFrame(frameTimeNanos)
            Choreographer.getInstance().postFrameCallback(this)
        }
    }
    private var lastDecorFocus = false
    private var decorFocusAccepted = false
    private val decorFocusListener = ViewTreeObserver.OnWindowFocusChangeListener { hasFocus ->
        ++decorFocusCallbacks
        lastDecorFocus = hasFocus
        // The decor observer receives real window facts even when an OEM's
        // Window.Callback chain omits Activity.onWindowFocusChanged.
        decorFocusAccepted = nativeWindowFocusChanged(hasFocus)
        if (hasFocus && decorFocusAccepted) {
            if (::controllers.isInitialized) controllers.reconcile()
            DiagnosticCoordinator.readinessChanged()
        }
    }
    private external fun nativeWindowFocusChanged(hasFocus: Boolean): Boolean
    private external fun nativeDisplayFrame(frameTimeNanos: Long): Boolean

    private fun reconcileDecorFocus() {
        ++decorFocusReconciliations
        lastReconciledDecorFocus = window.decorView.hasWindowFocus()
        decorFocusAccepted = nativeWindowFocusChanged(lastReconciledDecorFocus)
        if (lastReconciledDecorFocus && decorFocusAccepted && ::controllers.isInitialized) controllers.reconcile()
        DiagnosticCoordinator.readinessChanged()
    }

    /** Read on the main thread to distinguish Android delivery from native routing. */
    internal fun windowFocusReceipt(): JSONObject = JSONObject()
        .put("windowFocusCallbacks", windowFocusCallbacks)
        .put("lastWindowFocusCallback", lastWindowFocus)
        .put("decorFocusCallbacks", decorFocusCallbacks)
        .put("decorFocusReconciliations", decorFocusReconciliations)
        .put("lastDecorFocusReconciliation", lastReconciledDecorFocus)
        .put("lastDecorFocusCallback", lastDecorFocus)
        .put("decorFocusAccepted", decorFocusAccepted)

    external fun runDiagnostics(sessionToken: Long = 0): String
    external fun runGuestDiagnostics(sessionToken: Long = 0): String
    external fun runModuleDiagnostics(sessionToken: Long = 0): String
    external fun runKernelDiagnostics(sessionToken: Long = 0): String
    external fun runServiceDiagnostics(sessionToken: Long = 0): String
    external fun runAudioDiagnostics(sessionToken: Long = 0): String
    external fun runObservationDiagnostics(sessionToken: Long = 0): String
    external fun runAppletDiagnostics(sessionToken: Long = 0): String
    external fun runControllerDiagnostics(sessionToken: Long = 0): String
    external fun runGraphicsDiagnostics(sessionToken: Long = 0): String
    external fun runGraphicsExtendedDiagnostics(sessionToken: Long = 0): String
    external fun runInputDiagnostics(readTouchState: Boolean = true, sessionToken: Long = 0): String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Loading and gameplay can have long periods without touch input. Keep
        // this visible game window awake even when USB is data-only; Android
        // releases the screen requirement when the Activity is backgrounded.
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        keyboard = KeyboardCoordinator(this)
        audio = AudioCoordinator(this)
        controllers = ControllerDevices(this)
        controllers.start()
        window.decorView.viewTreeObserver.addOnWindowFocusChangeListener(decorFocusListener)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 48, 24, 24)
            setBackgroundColor(0xfff5f5f5.toInt())
        }
        content.addView(TextView(this).apply {
            text = "D2R Android"
            textSize = 24f
        })
        resourcesUi = ResourceSetupUi(this)
        content.addView(resourcesUi.view, LinearLayout.LayoutParams(-1, -2))
        content.addView(TextView(this).apply {
            text = "Runtime diagnostics"
            textSize = 21f
            setPadding(0, 24, 0, 8)
        })
        content.addView(TextView(this).apply {
            text = "Synthetic ARM64, Vulkan, rewritten guest, module loader, kernel and host service fixtures. The original-entry button makes a separate checked retail attempt."
            textSize = 16f
        })
        originalStatus = TextView(this).apply {
            tag = "original-entry-status"
            text = getString(R.string.original_entry_intro)
            textSize = 16f
        }
        originalLaunch = Button(this).apply {
            tag = "original-entry-run"
            text = getString(R.string.original_entry_launch)
            setOnClickListener { OriginalLaunchCoordinator.request(this@MainActivity) }
        }
        content.addView(originalLaunch)
        content.addView(originalStatus)
        status = TextView(this).apply { textSize = 16f; tag = "diagnostics-status" }
        content.addView(status)
        rerun = Button(this).apply {
            tag = "diagnostics-run"
            text = "Run diagnostics"
            setOnClickListener { startDiagnostics() }
        }
        content.addView(rerun)
        output = TextView(this).apply {
            setTextIsSelectable(true)
            typeface = android.graphics.Typeface.MONOSPACE
            textSize = 12f
        }
        content.addView(output, LinearLayout.LayoutParams(-1, -2))
        // Both views sit above GameActivity's actual native surface. Launch mode
        // hides diagnostics; the overlay draws without collecting touch events.
        touchControls = TouchControlOverlay(this)
        addContentView(touchControls, ViewGroup.LayoutParams(-1, -1))
        diagnosticsScroll = ScrollView(this).apply {
            tag = "diagnostics-scroll"
            addView(content)
            isFillViewport = true
        }
        addContentView(diagnosticsScroll, ViewGroup.LayoutParams(-1, -1))
        content.setOnApplyWindowInsetsListener { view, insets ->
            @Suppress("DEPRECATION")
            view.setPadding(24 + insets.systemWindowInsetLeft, 24 + insets.systemWindowInsetTop,
                24 + insets.systemWindowInsetRight, 24 + insets.systemWindowInsetBottom)
            insets
        }
        content.requestApplyInsets()
        if (!OriginalLaunchCoordinator.attach(this)) startDiagnostics()
    }

    override fun onStart() {
        super.onStart()
        if (::resourcesUi.isInitialized) resourcesUi.onStart()
        DiagnosticCoordinator.readinessChanged()
    }

    override fun onResume() {
        super.onResume()
        // Recreated Activities may inherit an already focused decor window and
        // receive no new focus edge. Read the current window fact after native
        // resume, when this Activity's generation is bound; never infer focus
        // merely from the lifecycle state.
        activityResumed = true
        Choreographer.getInstance().removeFrameCallback(displayFrameCallback)
        Choreographer.getInstance().postFrameCallback(displayFrameCallback)
        reconcileDecorFocus()
        // ActivityThread can finish attaching/reusing the preserved ViewRoot
        // after onResume. Reconcile that actual decor fact once on its queue.
        window.decorView.post {
            if (activityResumed && !isDestroyed && !isFinishing && window.decorView.isAttachedToWindow) reconcileDecorFocus()
        }
        if (::audio.isInitialized) audio.resume()
        if (::keyboard.isInitialized) keyboard.resume()
        OriginalLaunchCoordinator.attach(this)
        DiagnosticCoordinator.readinessChanged()
    }

    override fun onPause() {
        activityResumed = false
        Choreographer.getInstance().removeFrameCallback(displayFrameCallback)
        if (::audio.isInitialized) audio.pause()
        if (::keyboard.isInitialized) keyboard.pause()
        super.onPause()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        ++windowFocusCallbacks
        lastWindowFocus = hasFocus
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) DiagnosticCoordinator.readinessChanged()
    }

    override fun onStop() {
        if (::resourcesUi.isInitialized) resourcesUi.onStop()
        super.onStop()
    }

    @Deprecated("Platform document picker result callback")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        resourcesUi.onActivityResult(requestCode, resultCode, data)
    }

    private fun startDiagnostics() {
        if (OriginalLaunchCoordinator.blocksDiagnostics()) return
        DiagnosticCoordinator.request(this)
    }

    /** Main-thread UI projection only; native reports remain execution authority. */
    internal fun renderOriginalLaunch(running: Boolean, report: JSONObject?, failure: String?, retryAllowed: Boolean) {
        diagnosticsScroll.visibility = if (running) View.INVISIBLE else View.VISIBLE
        touchControls.visibility = if (running) View.VISIBLE else View.GONE
        originalLaunch.isEnabled = !running && retryAllowed
        if (running) {
            originalStatus.text = getString(R.string.original_entry_preparing)
            rerun.isEnabled = false
            gameSurface(window.decorView)?.apply {
                isFocusable = true
                isFocusableInTouchMode = true
                requestFocus()
            }
        } else if (report != null || failure != null) {
            originalStatus.text = if (failure != null) {
                getString(R.string.original_entry_failed, failure)
            } else {
                val nativeStatus = report!!.optString("status")
                val label = when (nativeStatus) {
                    "BLOCKED" -> getString(R.string.original_entry_blocked)
                    "RETAINED_REQUIRE_PROCESS_RESTART" -> getString(R.string.original_entry_needs_restart)
                    "STOPPED", "NNMAIN_EXITED", "NNMAIN_RETURNED" -> getString(R.string.original_entry_stopped)
                    else -> nativeStatus
                }
                val displayedStatus = if (label == nativeStatus) nativeStatus else "$label（$nativeStatus）"
                getString(R.string.original_entry_result, displayedStatus, report.optString("error"),
                    report.optString("lastStep").ifBlank { getString(R.string.original_entry_not_started) })
            }
            rerun.isEnabled = retryAllowed
        }
    }

    private fun gameSurface(view: View): SurfaceView? {
        if (view is SurfaceView) return view
        if (view is ViewGroup) for (index in 0 until view.childCount) {
            gameSurface(view.getChildAt(index))?.let { return it }
        }
        return null
    }

    internal fun diagnosticsDeferred(message: String) {
        rerun.isEnabled = false
        status.text = message
    }

    /** Runs on the process worker while one native batch lease covers all five suites. */
    internal fun executeDiagnosticBatch(sessionToken: Long, activityGeneration: Long,
                                        readinessRevision: Long): () -> Unit {
        runOnUiThread { if (!isDestroyed) status.text = "Running native probes…" }
        val phase0 = try {
            withDeviceMetadata(JSONObject(runDiagnostics(sessionToken)).apply {
                put("gamePlayable", false)
                put("syntheticOnly", true)
            })
        } catch (error: Exception) {
            if (error is DiagnosticOwnershipException) throw error
            JSONObject().put("gamePlayable", false).put("syntheticOnly", true)
                .put("error", error.toString())
        }
        val phase1a = try {
            withDeviceMetadata(JSONObject(runGuestDiagnostics(sessionToken)))
        } catch (error: Exception) {
            if (error is DiagnosticOwnershipException) throw error
            JSONObject().put("schemaVersion", 2).put("phase", "1A")
                .put("gamePlayable", false).put("syntheticOnly", true)
                .put("error", error.toString())
        }
        val phase1b = try {
            withDeviceMetadata(JSONObject(runModuleDiagnostics(sessionToken)))
        } catch (error: Exception) {
            if (error is DiagnosticOwnershipException) throw error
            JSONObject().put("schemaVersion", 3).put("phase", "1B")
                .put("gamePlayable", false).put("syntheticOnly", true)
                .put("error", error.toString())
        }
        val phase2 = try {
            withDeviceMetadata(JSONObject(runKernelDiagnostics(sessionToken)))
        } catch (error: Exception) {
            if (error is DiagnosticOwnershipException) throw error
            JSONObject().put("schemaVersion", 4).put("phase", "2")
                .put("gamePlayable", false).put("syntheticOnly", true)
                .put("error", error.toString())
        }
        val phase3 = try {
            withDeviceMetadata(JSONObject(runServiceDiagnostics(sessionToken)))
        } catch (error: Exception) {
            if (error is DiagnosticOwnershipException) throw error
            JSONObject().put("schemaVersion", 5).put("phase", "3")
                .put("gamePlayable", false).put("syntheticOnly", true)
                .put("error", error.toString())
        }
        val reports = listOf("phase0-report.json" to phase0, "phase1a-report.json" to phase1a,
            "phase1b-report.json" to phase1b, "kernel-report.json" to phase2,
            "services-report.json" to phase3)
        reports.forEach { (_, report) ->
            report.put("diagnosticBatch", JSONObject().put("sessionToken", sessionToken)
                .put("activityGeneration", activityGeneration).put("readinessRevision", readinessRevision))
        }
        val saved = reports.map { (name, report) ->
            name to runCatching { persistReport(name, report.toString(2)) }
        }
        val text = "Phase 0\n${phase0.toString(2)}\n\nPhase 1A\n${phase1a.toString(2)}\n\nPhase 1B\n${phase1b.toString(2)}\n\nPhase 2 · Kernel\n${phase2.toString(2)}\n\nPhase 3 · Services\n${phase3.toString(2)}"
        return {
            runOnUiThread {
                if (!isDestroyed) {
                    output.text = text
                    status.text = saved.joinToString("\n") { (name, result) ->
                        if (result.isSuccess) "Report saved: $name"
                        else "Report could not be saved: $name: ${result.exceptionOrNull()?.message}"
                    }
                    rerun.isEnabled = true
                }
            }
        }
    }

    private fun withDeviceMetadata(report: JSONObject): JSONObject = report.apply {
        put("device", JSONObject().apply {
            put("manufacturer", Build.MANUFACTURER)
            put("model", Build.MODEL)
            put("apiLevel", Build.VERSION.SDK_INT)
            put("supportedAbis", JSONArray(Build.SUPPORTED_ABIS.toList()))
        })
    }

    private fun persistReport(name: String, text: String) {
        val file = AtomicFile(File(filesDir, name))
        val stream = file.startWrite()
        try {
            stream.write(text.toByteArray(Charsets.UTF_8))
            file.finishWrite(stream)
        } catch (error: Exception) {
            file.failWrite(stream)
            throw error
        }
    }

    override fun onDestroy() {
        activityResumed = false
        Choreographer.getInstance().removeFrameCallback(displayFrameCallback)
        if (::audio.isInitialized) audio.destroy()
        if (::keyboard.isInitialized) keyboard.destroy()
        // Attachment may migrate listeners to a new observer and kill the
        // pre-attachment one. Remove from the decor's current live observer.
        window.decorView.viewTreeObserver.takeIf { it.isAlive }
            ?.removeOnWindowFocusChangeListener(decorFocusListener)
        DiagnosticCoordinator.cancel(this)
        OriginalLaunchCoordinator.detach(this)
        if (::resourcesUi.isInitialized) resourcesUi.destroy()
        if (::controllers.isInitialized) controllers.stop()
        super.onDestroy()
    }

    companion object {
        init {
            System.loadLibrary("d2r_diagnostics")
            ControllerDevices.configureAxesOnce()
        }
    }
}
