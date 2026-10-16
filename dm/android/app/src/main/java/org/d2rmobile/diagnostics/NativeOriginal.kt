package org.d2rmobile.diagnostics

/** Runs the checked retail bootstrap on the calling background owner thread.
 * User launch requests are serialized by OriginalLaunchCoordinator; this JNI
 * entry still independently acquires the actual native DiagnosticCall owner.
 * An attempted call is distinct from returned original code and a game frame. */
object NativeOriginal {
    init { System.loadLibrary("d2r_diagnostics") }

    @JvmStatic external fun run(activity: MainActivity): String
}
