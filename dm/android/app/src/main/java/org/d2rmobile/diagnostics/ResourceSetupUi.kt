package org.d2rmobile.diagnostics

import android.app.Activity
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import java.lang.ref.WeakReference
import java.net.URI
import java.util.Locale
import java.util.concurrent.Executors

/** Resource setup only. Archive validation does not establish game execution readiness. */
internal class ResourceSetupUi(private val activity: Activity) {
    private val chinese = activity.resources.configuration.locales[0].language == "zh"
    private val preferences = activity.getSharedPreferences("resource-setup", Activity.MODE_PRIVATE)
    private val inspector = Executors.newSingleThreadExecutor()
    private val handler = Handler(Looper.getMainLooper())
    private var destroyed = false
    private var inspecting = false
    private var attached = false
    private var inspectionToken: CancellationToken? = null
    private lateinit var source: EditText
    private lateinit var status: TextView
    private lateinit var progress: ProgressBar
    private lateinit var choose: Button
    private lateinit var download: Button
    private lateinit var resume: Button
    private lateinit var cancel: Button
    private lateinit var validate: Button
    private val listener: (TransferStatus) -> Unit = { render(it) }

    val view = LinearLayout(activity).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(12), dp(12), dp(12), dp(12))
        setBackgroundColor(0xffffffff.toInt())
        addView(label(words("遊戲資料", "Game resources"), 21f))
        addView(label(words(
            "匯入您持有的 Update/RomFs 資料夾，或從您提供的 HTTPS 位址下載。資料保留在本機；驗證通過仍不代表遊戲可啟動。",
            "Import your Update/RomFs folder or download from an HTTPS address you provide. Files stay on this device. Passing validation does not mean the game can run."
        ), 14f))
        source = EditText(activity).apply {
            tag = "resource-source-url"
            hint = "https://…/Update/RomFs/"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(true)
            setText(preferences.getString("source-url", ""))
            contentDescription = words("HTTPS 資料來源位址", "HTTPS resource source address")
        }
        addView(source, LinearLayout.LayoutParams(-1, -2))
        choose = button(words("選擇資料夾", "Choose folder"), "resource-choose") { openTree() }
        download = button(words("下載", "Download"), "resource-download") { startDownload() }
        addView(row(choose, download))
        resume = button(words("繼續上次傳輸", "Resume transfer"), "resource-resume") {
            runCatching { ResourceTransferService.resume(activity) }.onFailure { showError(it) }
        }
        cancel = button(words("取消傳輸", "Cancel transfer"), "resource-cancel") {
            runCatching { ResourceTransferService.cancel(activity) }.onFailure { showError(it) }
        }
        addView(row(resume, cancel))
        progress = ProgressBar(activity, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = 1000
            visibility = View.GONE
            contentDescription = words("資料傳輸進度", "Resource transfer progress")
        }
        addView(progress, LinearLayout.LayoutParams(-1, dp(8)))
        status = label(words("檢查本機資料…", "Checking local resources…"), 14f).apply {
            tag = "resource-status"
            setTextIsSelectable(true)
            accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        }
        addView(status)
        validate = button(words("重新驗證本機資料", "Validate local resources"), "resource-validate") { inspect() }
        addView(validate, LinearLayout.LayoutParams(-1, -2))
        addView(label(words(
            "遊戲啟動與渲染尚未接妥。目前可使用下方的核心診斷功能。",
            "Game launch and rendering are still being integrated. Runtime diagnostics are available below."
        ), 13f))
    }

    fun onStart() {
        attached = true
        ResourceTransferService.addListener(listener)
        val transfer = ResourceTransferService.current
        render(transfer)
        if (!transfer.running && transfer.result == null && transfer.error == null && !transfer.cancelled) inspect()
    }

    fun onStop() {
        attached = false
        ResourceTransferService.removeListener(listener)
        inspectionToken?.cancel()
    }

    fun destroy() {
        destroyed = true
        onStop()
        inspector.shutdownNow()
        handler.removeCallbacksAndMessages(null)
    }

    @Suppress("DEPRECATION")
    private fun openTree() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or Intent.FLAG_GRANT_PREFIX_URI_PERMISSION)
        }
        runCatching { activity.startActivityForResult(intent, TREE_REQUEST) }.onFailure { showError(it) }
    }

    fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        if (requestCode != TREE_REQUEST) return false
        if (resultCode != Activity.RESULT_OK || data?.data == null) return true
        val tree = data.data!!
        val readGrant = data.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION
        if (readGrant == 0) {
            showError(SecurityException(words("選取的資料夾未授予讀取權限，請重新選擇。",
                "The selected folder did not grant read permission. Choose it again.")))
            return true
        }
        try {
            // The service can reopen the selected source after the activity or process is recreated.
            activity.contentResolver.takePersistableUriPermission(tree, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            ResourceTransferService.startImport(activity, tree)
        } catch (error: Exception) {
            showError(error)
        }
        return true
    }

    private fun startDownload() {
        val address = source.text.toString().trim()
        val parsed = runCatching { URI(address) }.getOrNull()
        if (parsed?.scheme?.lowercase(Locale.ROOT) != "https" || parsed.host.isNullOrBlank() ||
            parsed.rawUserInfo != null || parsed.rawFragment != null) {
            status.text = words("請輸入有效的 HTTPS 資料夾位址，且不要包含帳號密碼或 # 片段。",
                "Enter a valid HTTPS folder address without embedded credentials or a # fragment.")
            return
        }
        preferences.edit().putString("source-url", address).apply()
        runCatching { ResourceTransferService.startDownload(activity, address) }.onFailure { showError(it) }
    }

    private fun inspect() {
        if (destroyed || inspecting || ResourceTransferService.current.running) return
        inspecting = true
        setButtons(false)
        status.text = words("檢查本機資料…", "Checking local resources…")
        val weak = WeakReference(this)
        val context = activity.applicationContext
        val mainHandler = handler
        val token = CancellationToken()
        inspectionToken = token
        inspector.execute {
            val result = runCatching { ResourceStore(context, NativeResources::validate).inspect(token) }
            mainHandler.post {
                val ui = weak.get() ?: return@post
                if (ui.destroyed) return@post
                ui.inspecting = false
                ui.inspectionToken = null
                if (token.isCancelled) {
                    if (ui.attached && !ResourceTransferService.current.running) ui.inspect()
                    return@post
                }
                if (ResourceTransferService.current.running) ui.render(ResourceTransferService.current)
                else if (ui.attached) result.fold({ ui.showResult(it) }, { ui.showError(it) })
            }
        }
    }

    private fun render(transfer: TransferStatus) {
        if (destroyed || !attached) return
        setButtons(!transfer.running && !inspecting)
        cancel.isEnabled = transfer.running
        progress.visibility = if (transfer.running) View.VISIBLE else View.GONE
        val update = transfer.progress
        if (transfer.running) {
            progress.isIndeterminate = update == null || update.total <= 0
            if (update != null) {
                if (update.total > 0) progress.progress =
                    ((update.done.toDouble() / update.total) * 1000).toInt().coerceIn(0, 1000)
                status.text = "${update.file}\n${size(update.done)} / ${if (update.total > 0) size(update.total) else "?"}\n${update.note}"
            } else status.text = words("準備傳輸…", "Preparing transfer…")
        } else when {
            transfer.error != null -> showError(IllegalStateException(transfer.error))
            transfer.cancelled -> status.text = words(
                "傳輸已取消。已完成的檔案及可續傳的部分保留在本機；按「繼續上次傳輸」可重試。",
                "Transfer cancelled. Completed files and resumable partial files remain on this device. Use Resume transfer to retry."
            )
            transfer.result != null -> showResult(transfer.result)
        }
    }

    private fun showResult(result: ResourceResult) {
        setButtons(true)
        progress.visibility = View.GONE
        val heading = if (result.validation.ready) words("資料結構驗證通過", "Resource structure validated")
            else words("資料尚未完整", "Resources are incomplete")
        val digest = if (result.shaVerified) words("SHA-256 清單驗證通過", "SHA-256 manifest verified")
            else words("未驗證 SHA-256 清單", "SHA-256 manifest not verified")
        status.text = "$heading · ${result.files} ${words("個檔案", "files")} · ${size(result.bytes)}\n$digest\n${result.validation.details}"
    }

    private fun showError(error: Throwable) {
        if (destroyed) return
        setButtons(!ResourceTransferService.current.running && !inspecting)
        status.text = "${words("作業未完成", "Operation did not finish")}: ${error.message ?: error.javaClass.simpleName}"
    }

    private fun setButtons(idle: Boolean) {
        source.isEnabled = idle
        choose.isEnabled = idle
        download.isEnabled = idle
        resume.isEnabled = idle
        validate.isEnabled = idle
        cancel.isEnabled = ResourceTransferService.current.running
    }

    private fun label(value: String, size: Float) = TextView(activity).apply {
        text = value
        textSize = size
        setTextColor(0xff20252b.toInt())
        setPadding(0, dp(4), 0, dp(6))
    }

    private fun button(value: String, identifier: String, action: () -> Unit) = Button(activity).apply {
        text = value
        tag = identifier
        isAllCaps = false
        setOnClickListener { action() }
    }

    private fun row(first: View, second: View) = LinearLayout(activity).apply {
        orientation = LinearLayout.HORIZONTAL
        addView(first, LinearLayout.LayoutParams(0, -2, 1f))
        addView(second, LinearLayout.LayoutParams(0, -2, 1f))
    }

    private fun dp(value: Int) = (value * activity.resources.displayMetrics.density).toInt()
    private fun words(zh: String, en: String) = if (chinese) zh else en
    private fun size(bytes: Long) = String.format(Locale.ROOT, "%.1f MiB", bytes / 1048576.0)

    companion object { const val TREE_REQUEST = 401 }
}
