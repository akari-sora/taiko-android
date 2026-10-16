package org.d2rmobile.diagnostics

import android.app.Activity
import android.app.AlertDialog
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.InputType
import android.text.NoCopySpan
import android.text.Spannable
import android.text.Spanned
import android.text.SpanWatcher
import android.text.TextWatcher
import android.view.WindowManager
import android.view.inputmethod.BaseInputConnection
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/** One Activity owns the dialog; the native guest waits on its own thread. */
internal class KeyboardCoordinator(private val activity: Activity) {
    private val handler = Handler(Looper.getMainLooper())
    private var resumed = false
    private var dialog: AlertDialog? = null
    private var requestId = 0L
    private var finished = true
    private var generation = nativeAttach(this)

    fun resume() {
        check(Looper.myLooper() == Looper.getMainLooper())
        resumed = true
        nativeActive(generation, true)
    }

    fun pause() {
        check(Looper.myLooper() == Looper.getMainLooper())
        resumed = false
        // Wake the guest before dismiss callbacks; those callbacks cannot
        // complete the cancelled request a second time.
        nativeActive(generation, false)
        dialog?.dismiss()
        dialog = null
    }

    fun destroy() {
        pause()
        nativeDetach(generation)
        generation = 0
    }

    @Suppress("unused")
    fun dismissRequest(owner: Long, id: Long) {
        handler.post {
            if (owner == generation && requestId == id) {
                finish(owner, id, false, "")
            }
        }
    }

    // Called by JNI on the guest thread. Posting does not wait for the UI.
    @Suppress("unused")
    fun postRequest(owner: Long, id: Long, title: String, subtitle: String, guide: String,
                    initial: String, minimum: Int, maximum: Int, maxBytes: Int,
                    numericMax: Int, characterName: Boolean): Boolean = handler.post {
        if (owner != generation || !resumed || activity.isFinishing || activity.isDestroyed ||
            !nativePending(owner, id)) return@post
        if (dialog != null) {
            nativeComplete(owner, id, false, "")
            return@post
        }
        val content = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            val padding = (24 * resources.displayMetrics.density).toInt()
            setPadding(padding, 0, padding, 0)
        }
        if (subtitle.isNotEmpty()) content.addView(TextView(activity).apply { text = subtitle })
        if (guide.isNotEmpty()) content.addView(TextView(activity).apply { text = guide })
        if (characterName) content.addView(TextView(activity).apply {
            text = "Use 2–15 English letters or 1–5 Chinese characters (may be mixed). One - or _ is allowed inside the name."
        })
        val input = EditText(activity).apply {
            tag = "game-keyboard-input"
            setSingleLine(true)
            hint = guide
            // Keep IME conversion candidates available for Chinese input.
            inputType = if (numericMax >= 0) InputType.TYPE_CLASS_NUMBER else InputType.TYPE_CLASS_TEXT
            imeOptions = EditorInfo.IME_ACTION_DONE or EditorInfo.IME_FLAG_NO_EXTRACT_UI
            setText(initial)
            setSelection(text.length)
        }
        content.addView(input, LinearLayout.LayoutParams(-1, -2))
        val alert = AlertDialog.Builder(activity)
            .setTitle(title.ifEmpty { if (numericMax >= 0) "Quantity" else "Enter text" })
            .setView(content)
            .setPositiveButton(android.R.string.ok, null)
            .setNegativeButton(android.R.string.cancel) { _, _ -> finish(owner, id, false, "") }
            .create()
        dialog = alert
        requestId = id
        finished = false
        fun error(): String? {
            val editable = input.text
            if (BaseInputConnection.getComposingSpanStart(editable) >= 0 ||
                BaseInputConnection.getComposingSpanEnd(editable) >= 0) return "Choose an input candidate first."
            return KeyboardRules.error(editable.toString(), minimum, maximum, maxBytes, numericMax, characterName)
        }
        fun refresh() {
            val reason = error()
            input.error = reason
            alert.getButton(AlertDialog.BUTTON_POSITIVE)?.isEnabled = reason == null
        }
        fun confirm() {
            val reason = error()
            if (reason != null) { input.error = reason; return }
            finish(owner, id, true, input.text.toString())
        }
        // Some IMEs finish a candidate by removing only composing spans, with
        // no text mutation. Observe that change so OK becomes usable then too.
        val compositionWatcher = object : SpanWatcher, NoCopySpan {
            override fun onSpanAdded(text: Spannable, what: Any, start: Int, end: Int) {
                if (what !== this) refresh()
            }
            override fun onSpanRemoved(text: Spannable, what: Any, start: Int, end: Int) {
                if (what !== this) refresh()
            }
            override fun onSpanChanged(text: Spannable, what: Any, oldStart: Int, oldEnd: Int, newStart: Int, newEnd: Int) {
                if (what !== this) refresh()
            }
        }
        input.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
            override fun afterTextChanged(s: Editable?) {
                s?.setSpan(compositionWatcher, 0, s.length, Spanned.SPAN_INCLUSIVE_INCLUSIVE)
                refresh()
            }
        })
        input.setOnEditorActionListener { _, action, _ ->
            if (action == EditorInfo.IME_ACTION_DONE) { confirm(); true } else false
        }
        alert.setOnCancelListener { finish(owner, id, false, "") }
        alert.setOnDismissListener {
            finish(owner, id, false, "")
            if (dialog === alert) dialog = null
        }
        alert.setOnShowListener {
            alert.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener { confirm() }
            refresh()
            input.text.setSpan(compositionWatcher, 0, input.text.length, Spanned.SPAN_INCLUSIVE_INCLUSIVE)
            input.requestFocus()
            alert.window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE)
        }
        try {
            alert.show()
        } catch (_: WindowManager.BadTokenException) {
            finish(owner, id, false, "")
            if (dialog === alert) dialog = null
        }
    }

    private fun finish(owner: Long, id: Long, confirmed: Boolean, value: String): Boolean {
        if (generation != owner || requestId != id || finished) return false
        // Retire the UI before waking the guest: it may immediately request a
        // second keyboard before Android delivers the old dismiss callback.
        finished = true
        val ending = dialog
        dialog = null
        ending?.dismiss()
        val accepted = nativeComplete(owner, id, confirmed, value)
        // A native validation refusal is not a completed request. Cancel it
        // before dismissing so a UI/native policy mismatch cannot strand a wait.
        if (confirmed && !accepted) nativeComplete(owner, id, false, "")
        return accepted
    }

    companion object {
        @JvmStatic private external fun nativeAttach(coordinator: KeyboardCoordinator): Long
        @JvmStatic private external fun nativeActive(generation: Long, active: Boolean)
        @JvmStatic private external fun nativeDetach(generation: Long)
        @JvmStatic private external fun nativePending(generation: Long, request: Long): Boolean
        @JvmStatic private external fun nativeComplete(generation: Long, request: Long,
                                                      confirmed: Boolean, value: String): Boolean
        /** Generic frontend entry. Call from a worker, never the Android UI thread. */
        @JvmStatic external fun enterText(title: String, subtitle: String, guide: String,
                                         initial: String, minimum: Int, maximum: Int): String?
        /** Product shutdown can wake a guest before waiting for its thread. */
        @JvmStatic external fun cancelPending()
    }
}

internal object KeyboardRules {
    fun error(text: String, minimum: Int, maximum: Int, maxBytes: Int,
              numericMax: Int = -1, characterName: Boolean = false): String? {
        var index = 0
        while (index < text.length) {
            val c = text[index++]
            if (c == '\u0000' || Character.isLowSurrogate(c)) return "Enter valid text."
            if (Character.isHighSurrogate(c) && (index == text.length ||
                        !Character.isLowSurrogate(text[index++]))) return "Enter valid text."
        }
        if (text.length < minimum) return "Enter at least $minimum characters."
        if (text.length > maximum) return "Use at most $maximum characters."
        val bytes = text.toByteArray(Charsets.UTF_8).size
        if (bytes > maxBytes) return "The text is too long."
        if (characterName) {
            if (bytes < 2 || bytes > 15) return "Use 2–15 English letters or 1–5 Chinese characters."
            if (text.first() in "-_" || text.last() in "-_") return "Start and end the name with a letter."
            if (text.count { it == '-' || it == '_' } > 1 || text.any {
                    !(it in 'A'..'Z' || it in 'a'..'z' || it in '\u3400'..'\u4dbf' ||
                        it in '\u4e00'..'\u9fff' || it == '-' || it == '_')
                }) return "Use English letters or Chinese characters and at most one - or _."
        }
        if (numericMax >= 0 && (text.isEmpty() || text.any { it !in '0'..'9' } ||
                    text.toLongOrNull()?.let { it > numericMax } != false)) return "Enter a number from 0 to $numericMax."
        return null
    }
}
