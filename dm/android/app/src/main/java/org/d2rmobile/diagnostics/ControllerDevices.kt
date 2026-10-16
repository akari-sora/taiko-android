package org.d2rmobile.diagnostics

import android.app.Activity
import android.hardware.input.InputManager
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.InputDevice
import java.util.concurrent.atomic.AtomicLong

/** Framework discovery only: no direct Bluetooth/USB access or permissions. */
internal class ControllerDevices(private val activity: Activity) : InputManager.InputDeviceListener {
    private val manager = activity.getSystemService(InputManager::class.java)
    private val handler = Handler(Looper.getMainLooper())
    private val known = mutableSetOf<Int>()
    private var started = false
    private var attachmentDeadlineMs = 0L
    private val attachmentRetry = object : Runnable {
        override fun run() {
            if (!started) return
            if (nativeGeneration(activity) != 0L) reconcile()
            else if (SystemClock.uptimeMillis() < attachmentDeadlineMs) handler.postDelayed(this, 250)
        }
    }

    fun start() {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (!started) {
            manager.registerInputDeviceListener(this, handler)
            started = true
            attachmentDeadlineMs = SystemClock.uptimeMillis() + 30_000
        }
        reconcile()
    }

    /** Also call after native Activity attachment/focus readiness. */
    fun reconcile() {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (!started) return
        if (nativeGeneration(activity) == 0L) {
            handler.removeCallbacks(attachmentRetry)
            if (SystemClock.uptimeMillis() < attachmentDeadlineMs) handler.postDelayed(attachmentRetry, 250)
            return
        }
        handler.removeCallbacks(attachmentRetry)
        val ids = manager.inputDeviceIds.toSet()
        (known - ids).forEach { retire(it) }
        ids.forEach { publish(it) }
    }

    fun stop() {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (started) manager.unregisterInputDeviceListener(this)
        started = false
        handler.removeCallbacks(attachmentRetry)
        known.toList().forEach { retire(it) }
    }

    override fun onInputDeviceAdded(deviceId: Int) = publish(deviceId)
    override fun onInputDeviceChanged(deviceId: Int) = publish(deviceId)
    override fun onInputDeviceRemoved(deviceId: Int) = retire(deviceId)

    private fun retire(id: Int) {
        known.remove(id)
        nativeRemove(activity, id, nextNotification.incrementAndGet(), System.nanoTime())
    }

    private fun publish(id: Int) {
        if (!started) return
        val fence = System.nanoTime()
        // Refetch changed devices; descriptor is descriptive, never an owner key.
        val device = manager.getInputDevice(id)
        if (device == null || (!device.supportsSource(InputDevice.SOURCE_GAMEPAD) &&
                !device.supportsSource(InputDevice.SOURCE_JOYSTICK))) {
            if (id in known) retire(id)
            return
        }
        val ranges = device.motionRanges
        val axes = IntArray(ranges.size)
        val sources = IntArray(ranges.size)
        val calibration = FloatArray(ranges.size * 4)
        ranges.forEachIndexed { index, range ->
            axes[index] = range.axis
            sources[index] = range.source
            calibration[index * 4] = range.min
            calibration[index * 4 + 1] = range.max
            calibration[index * 4 + 2] = range.flat
            calibration[index * 4 + 3] = range.fuzz
        }
        if (nativeDevice(activity, id, device.sources, device.vendorId, device.productId,
                device.name, device.descriptor, nextNotification.incrementAndGet(), fence,
                axes, sources, calibration)) known.add(id)
    }

    companion object {
        private val nextNotification = AtomicLong()
        @JvmStatic external fun configureAxesOnce()
        @JvmStatic private external fun nativeGeneration(activity: Activity): Long
        @JvmStatic private external fun nativeDevice(activity: Activity, id: Int, sources: Int,
            vendor: Int, product: Int, name: String, descriptor: String, notification: Long,
            fenceNs: Long, axes: IntArray, rangeSources: IntArray, calibration: FloatArray): Boolean
        @JvmStatic private external fun nativeRemove(activity: Activity, id: Int,
            notification: Long, fenceNs: Long): Boolean
        @JvmStatic external fun receipt(): String
        // Explicit debug-only OS injection seam. This cannot claim discovery of
        // physical hardware or grant the complete production input capability.
        @JvmStatic external fun registerDiagnosticVirtual(activity: Activity, id: Int,
            sources: Int, sessionToken: Long = 0): Boolean
        @JvmStatic external fun removeDiagnosticVirtual(activity: Activity, id: Int,
            sessionToken: Long = 0): Boolean
    }
}
