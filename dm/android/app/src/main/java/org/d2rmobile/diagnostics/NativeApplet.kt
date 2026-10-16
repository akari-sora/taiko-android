package org.d2rmobile.diagnostics

/** Persistent synthetic OE runtime; the token retains native process ownership. */
object NativeApplet {
    init { System.loadLibrary("d2r_diagnostics") }

    @JvmStatic external fun begin(): Long
    @JvmStatic external fun poll(token: Long): String
    @JvmStatic external fun armLoadBarrier(): Long
    @JvmStatic external fun loaderSnapshot(): String
    @JvmStatic external fun releaseLoadBarrier(id: Long): Boolean
    @JvmStatic private external fun nativeEnd(token: Long): Boolean

    fun end(token: Long): Boolean {
        val closed = nativeEnd(token)
        if (closed) DiagnosticCoordinator.ownerReleased()
        return closed
    }
}
