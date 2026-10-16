package org.d2rmobile.diagnostics

/** Owns the public synthetic controller guest while OS input is delivered. */
object NativeController {
    init { System.loadLibrary("d2r_diagnostics") }

    @JvmStatic external fun begin(): Long
    @JvmStatic external fun poll(token: Long): String
    @JvmStatic private external fun nativeEnd(token: Long): Boolean

    fun end(token: Long): Boolean {
        val closed = nativeEnd(token)
        if (closed) DiagnosticCoordinator.ownerReleased()
        return closed
    }
}
