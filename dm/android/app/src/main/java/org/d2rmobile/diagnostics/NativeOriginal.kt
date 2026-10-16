package org.d2rmobile.diagnostics

/** Runs the checked retail bootstrap on the calling background owner thread.
 * User launch requests are serialized by OriginalLaunchCoordinator; this JNI
 * entry still independently acquires the actual native DiagnosticCall owner.
 * An attempted call is distinct from returned original code and a game frame. */
object NativeOriginal {
    init { System.loadLibrary("d2r_diagnostics") }

    @JvmStatic fun run(activity: MainActivity): String =
        TaikoContentStore(activity).withNativeContent { runNative(activity) }

    @JvmStatic private external fun runNative(activity: MainActivity): String

    /** Actual native runtime state, including a retained guest after a call returns. */
    @JvmStatic external fun contentInUse(): Boolean
    @JvmStatic external fun hasCompiledBuild(): Boolean
}
