package org.d2rmobile.diagnostics

import android.os.Build
import android.os.Bundle
import android.util.AtomicFile
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.google.androidgamesdk.GameActivity
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors

/** Synthetic feasibility probes only. No game files are loaded or executed. */
class MainActivity : GameActivity() {
    private val executor = Executors.newSingleThreadExecutor()
    private lateinit var status: TextView
    private lateinit var output: TextView
    private lateinit var rerun: Button

    external fun runDiagnostics(): String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 48, 24, 24)
            setBackgroundColor(0xfff5f5f5.toInt())
        }
        content.addView(TextView(this).apply {
            text = "D2R Android · Phase 0"
            textSize = 24f
        })
        content.addView(TextView(this).apply {
            text = "Synthetic ARM64 and Vulkan diagnostics. This application does not run the game."
            textSize = 16f
        })
        status = TextView(this).apply { textSize = 16f }
        content.addView(status)
        rerun = Button(this).apply {
            text = "Run diagnostics"
            setOnClickListener { startDiagnostics() }
        }
        content.addView(rerun)
        output = TextView(this).apply {
            setTextIsSelectable(true)
            typeface = android.graphics.Typeface.MONOSPACE
            textSize = 12f
        }
        content.addView(ScrollView(this).apply { addView(output) },
            LinearLayout.LayoutParams(-1, 0, 1f))
        // Keep GameActivity's native surface and lifecycle, with diagnostics above it.
        addContentView(content, android.view.ViewGroup.LayoutParams(-1, -1))
        content.setOnApplyWindowInsetsListener { view, insets ->
            @Suppress("DEPRECATION")
            view.setPadding(24 + insets.systemWindowInsetLeft, 24 + insets.systemWindowInsetTop,
                24 + insets.systemWindowInsetRight, 24 + insets.systemWindowInsetBottom)
            insets
        }
        content.requestApplyInsets()
        startDiagnostics()
    }

    private fun startDiagnostics() {
        rerun.isEnabled = false
        status.text = "Running native probes…"
        executor.execute {
            val report = try {
                JSONObject(runDiagnostics()).apply {
                    put("gamePlayable", false)
                    put("syntheticOnly", true)
                    put("device", JSONObject().apply {
                        put("manufacturer", Build.MANUFACTURER)
                        put("model", Build.MODEL)
                        put("apiLevel", Build.VERSION.SDK_INT)
                        put("supportedAbis", JSONArray(Build.SUPPORTED_ABIS.toList()))
                    })
                }
            } catch (error: Exception) {
                JSONObject().put("gamePlayable", false).put("syntheticOnly", true)
                    .put("error", error.toString())
            }
            val text = report.toString(2)
            val saved = runCatching { persistReport(text) }
            runOnUiThread {
                if (!isDestroyed) {
                    output.text = text
                    status.text = if (saved.isSuccess) "Report saved: phase0-report.json"
                        else "Report could not be saved: ${saved.exceptionOrNull()?.message}"
                    rerun.isEnabled = true
                }
            }
        }
    }

    private fun persistReport(text: String) {
        val file = AtomicFile(File(filesDir, "phase0-report.json"))
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
        executor.shutdown()
        super.onDestroy()
    }

    companion object {
        init { System.loadLibrary("d2r_diagnostics") }
    }
}
