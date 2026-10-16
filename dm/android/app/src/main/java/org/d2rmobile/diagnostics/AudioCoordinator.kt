package org.d2rmobile.diagnostics

import android.app.Activity
import android.media.AudioAttributes
import android.media.AudioFocusRequest
import android.media.AudioManager
import android.os.Handler
import android.os.Looper

/** AudioManager ownership follows the current Activity and real playback Starts. */
internal class AudioCoordinator(private val activity: Activity) {
    private val handler = Handler(Looper.getMainLooper())
    private val audioManager = activity.getSystemService(AudioManager::class.java)
    private var resumed = false
    private var activeRequest: AudioFocusRequest? = null
    private var generation = nativeAttach(this)

    fun resume() {
        check(Looper.myLooper() == Looper.getMainLooper())
        resumed = true
        nativeActivity(generation, true)
    }

    fun pause() {
        check(Looper.myLooper() == Looper.getMainLooper())
        resumed = false
        nativeActivity(generation, false)
        abandonCurrent()
    }

    fun destroy() {
        pause()
        nativeDetach(generation)
        generation = 0
    }

    // JNI callers post work; they never wait for Android's main thread.
    @Suppress("unused")
    fun postRequestFocus(owner: Long, id: Long): Boolean = handler.post {
        if (owner != generation || !resumed || activity.isFinishing || activity.isDestroyed ||
            !nativePending(owner, id)) {
            nativeFocusResult(owner, id, false)
            return@post
        }
        abandonCurrent()
        val manager = audioManager
        if (manager == null) {
            nativeFocusResult(owner, id, false)
            return@post
        }
        lateinit var request: AudioFocusRequest
        val listener = AudioManager.OnAudioFocusChangeListener { change ->
            // A callback already queued for an abandoned/replaced request has
            // no authority over the current playback lease.
            if (owner == generation && resumed && activeRequest === request) {
                when (change) {
                    AudioManager.AUDIOFOCUS_GAIN -> nativeFocusChanged(owner, true)
                    AudioManager.AUDIOFOCUS_LOSS,
                    AudioManager.AUDIOFOCUS_LOSS_TRANSIENT,
                    AudioManager.AUDIOFOCUS_LOSS_TRANSIENT_CAN_DUCK -> {
                        nativeFocusChanged(owner, false)
                        if (change == AudioManager.AUDIOFOCUS_LOSS) abandonCurrent()
                    }
                }
            }
        }
        request = AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN)
            .setAudioAttributes(AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_GAME)
                .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC).build())
            .setAcceptsDelayedFocusGain(false)
            .setWillPauseWhenDucked(true)
            .setOnAudioFocusChangeListener(listener, handler)
            .build()
        activeRequest = request
        val result = try {
            manager.requestAudioFocus(request)
        } catch (_: RuntimeException) {
            AudioManager.AUDIOFOCUS_REQUEST_FAILED
        }
        val granted = result == AudioManager.AUDIOFOCUS_REQUEST_GRANTED &&
            owner == generation && resumed && !activity.isFinishing && !activity.isDestroyed &&
            nativePending(owner, id)
        if (!granted) abandonCurrent()
        nativeFocusResult(owner, id, granted)
    }

    @Suppress("unused")
    fun postAbandonFocus(owner: Long) {
        handler.post {
            // A newer Start can overtake an old caller before this post reaches
            // main. Its pending/current lease must not be abandoned by that post.
            if (owner == generation && nativeShouldAbandon(owner)) abandonCurrent()
        }
    }

    private fun abandonCurrent() {
        val request = activeRequest ?: return
        activeRequest = null
        try {
            audioManager?.abandonAudioFocusRequest(request)
        } catch (_: RuntimeException) {
            // Native state already cancelled this request; late callbacks are
            // ignored and cannot publish focus or restart playback.
        }
    }

    companion object {
        @JvmStatic private external fun nativeAttach(coordinator: AudioCoordinator): Long
        @JvmStatic private external fun nativeActivity(generation: Long, resumed: Boolean)
        @JvmStatic private external fun nativeDetach(generation: Long)
        @JvmStatic private external fun nativeFocusResult(generation: Long, request: Long, granted: Boolean)
        @JvmStatic private external fun nativeFocusChanged(generation: Long, hasFocus: Boolean)
        @JvmStatic private external fun nativePending(generation: Long, request: Long): Boolean
        @JvmStatic private external fun nativeShouldAbandon(generation: Long): Boolean
    }
}
