package org.d2rmobile.diagnostics

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import java.lang.ref.WeakReference
import java.util.concurrent.CancellationException
import java.util.concurrent.Executors

/** Imports a complete PC-produced content tree. Hash verification grants no launch authority. */
internal class TaikoSetupUi(
    private val activity: Activity,
    private val context: Context = activity.applicationContext
) {
    private val worker = Executors.newSingleThreadExecutor()
    private val handler = Handler(Looper.getMainLooper())
    private var destroyed = false
    private var pickerPending = false
    private var busy = false
    private var importing = false
    private var token: CancellationToken? = null
    private var lastTree: Uri? = null
    private var pendingTree: Uri? = null
    private lateinit var status: TextView
    private lateinit var progress: ProgressBar
    private lateinit var choose: Button
    private lateinit var cancel: Button
    private lateinit var retry: Button

    val view = LinearLayout(activity).apply {
        orientation = LinearLayout.VERTICAL
        addView(TextView(activity).apply {
            text = activity.getString(R.string.taiko_content_title)
            textSize = 21f
        })
        addView(TextView(activity).apply {
            text = activity.getString(R.string.taiko_content_instructions)
            textSize = 14f
        })
        choose = button(R.string.taiko_content_import, "taiko-content-choose") { openTree() }
        addView(choose)
        progress = ProgressBar(activity, null, android.R.attr.progressBarStyleHorizontal).apply {
            tag = "taiko-content-progress"
            max = 1000
            visibility = View.GONE
            contentDescription = activity.getString(R.string.taiko_content_progress)
        }
        addView(progress)
        status = TextView(activity).apply {
            tag = "taiko-content-status"
            text = activity.getString(R.string.taiko_content_missing)
            textSize = 14f
            setTextIsSelectable(true)
            accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        }
        addView(status)
        cancel = button(R.string.taiko_content_cancel, "taiko-content-cancel") {
            token?.cancelAsync()
            cancel.isEnabled = false
            status.text = activity.getString(R.string.taiko_content_cancelling)
        }.apply { isEnabled = false }
        addView(cancel)
        retry = button(R.string.taiko_content_retry, "taiko-content-retry") { runOperation(lastTree) }
        addView(retry)
    }

    fun onStart() {
        if (!busy && !pickerPending) runOperation(null)
    }

    fun onStop() {
        token?.cancelAsync()
    }

    fun destroy() {
        destroyed = true
        onStop()
        worker.shutdownNow()
        handler.removeCallbacksAndMessages(null)
    }

    @Suppress("DEPRECATION")
    private fun openTree() {
        if (busy || destroyed) return
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or Intent.FLAG_GRANT_PREFIX_URI_PERMISSION)
        }
        pickerPending = true
        runCatching { activity.startActivityForResult(intent, TREE_REQUEST) }.onFailure {
            pickerPending = false
            showError(it)
        }
    }

    fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        if (requestCode != TREE_REQUEST) return false
        pickerPending = false
        if (resultCode != Activity.RESULT_OK || data?.data == null || destroyed) return true
        if (data.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION == 0) {
            status.text = activity.getString(R.string.taiko_content_read_permission)
            return true
        }
        val tree = data.data!!
        try {
            context.contentResolver.takePersistableUriPermission(tree, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            lastTree = tree
            if (busy) {
                // A recreated Activity may already be inspecting when the picker returns.
                // Cancel that work, then import the selected tree on the same serial worker.
                pendingTree = tree
                token?.cancelAsync()
            } else runOperation(tree)
        } catch (error: Exception) {
            showError(error)
        }
        return true
    }

    private fun runOperation(tree: Uri?) {
        if (busy || destroyed) return
        busy = true
        importing = tree != null
        val operation = CancellationToken()
        token = operation
        setButtons()
        progress.visibility = View.VISIBLE
        progress.isIndeterminate = true
        status.text = activity.getString(if (importing) R.string.taiko_content_importing else R.string.taiko_content_checking)
        val weak = WeakReference(this)
        val localContext = context
        val main = handler
        worker.execute {
            var lastProgress = 0L
            val result = runCatching {
                val store = TaikoContentStore(localContext)
                if (tree == null) store.inspect(operation)
                else store.importTree(tree, operation) { update ->
                    val now = SystemClock.uptimeMillis()
                    if (now - lastProgress >= 100 || update.done == update.total) {
                        lastProgress = now
                        main.post {
                            val ui = weak.get()
                            if (ui != null && !ui.destroyed && ui.token === operation && !operation.isCancelled) {
                                ui.showProgress(update)
                            }
                        }
                    }
                }
            }
            main.post {
                val ui = weak.get() ?: return@post
                if (ui.destroyed || ui.token !== operation) return@post
                ui.token = null
                ui.busy = false
                ui.importing = false
                ui.progress.visibility = View.GONE
                ui.setButtons()
                val pending = ui.pendingTree
                if (pending != null) {
                    ui.pendingTree = null
                    ui.runOperation(pending)
                    return@post
                }
                // A cancellation request may arrive after the store's atomic publication.
                // Honor the returned verification result if publication completed successfully.
                result.fold(ui::showResult) { error ->
                    if (operation.isCancelled || error is CancellationException) {
                        ui.status.text = ui.activity.getString(R.string.taiko_content_cancelled)
                    } else ui.showError(error)
                }
            }
        }
    }

    private fun showProgress(update: ResourceProgress) {
        progress.isIndeterminate = update.total <= 0
        if (update.total > 0) progress.progress =
            ((update.done.toDouble() / update.total) * 1000).toInt().coerceIn(0, 1000)
        status.text = activity.getString(R.string.taiko_content_progress_value,
            update.file, update.done, update.total)
    }

    private fun showResult(result: TaikoContentResult) {
        if (result.integrityVerified) lastTree = null
        val heading = if (result.integrityVerified && result.modulesVerified && result.contentReady)
            activity.getString(R.string.taiko_content_verified)
        else activity.getString(R.string.taiko_content_missing)
        status.text = if (result.integrityVerified) activity.getString(R.string.taiko_content_verified_details,
            heading, result.files, result.bytes, result.manifestSha256 ?: "")
        else "$heading\n${result.details}"
    }

    private fun showError(error: Throwable) {
        if (destroyed) return
        val detail = error.message ?: error.javaClass.simpleName
        val heading = when {
            error is SecurityException -> activity.getString(R.string.taiko_content_read_permission)
            detail.contains("schema", ignoreCase = true) || detail.contains("package version", ignoreCase = true) ->
                activity.getString(R.string.taiko_content_unsupported)
            else -> activity.getString(R.string.taiko_content_mismatch)
        }
        status.text = "$heading\n$detail"
    }

    private fun setButtons() {
        choose.isEnabled = !busy
        retry.isEnabled = !busy
        cancel.isEnabled = busy && importing && token?.isCancelled == false
    }

    private fun button(label: Int, value: String, action: () -> Unit) = Button(activity).apply {
        tag = value
        text = activity.getString(label)
        setOnClickListener { action() }
    }

    companion object { const val TREE_REQUEST = 4103 }
}
