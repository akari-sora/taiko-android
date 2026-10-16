package org.d2rmobile.diagnostics

/** Retains the public NVN guest and its actual GPU work through clean retirement. */
object NativeGraphics {
    init { System.loadLibrary("d2r_diagnostics") }

    @JvmStatic external fun begin(): Long
    @JvmStatic external fun poll(token: Long): String
    @JvmStatic external fun waitForCompletion(token: Long, timeoutNs: Long): String
    @JvmStatic private external fun nativeEnd(token: Long): Boolean
    // Debug test controls retain only generation-bound barrier metadata. They
    // remain callable while waitForCompletion owns the ordinary guest borrower.
    @JvmStatic external fun armPublicationBarrier(): Long
    @JvmStatic external fun publicationBarrierSnapshot(id: Long): String
    @JvmStatic external fun releasePublicationBarrier(id: Long): Boolean
    @JvmStatic external fun retentionSnapshot(id: Long): String
    @JvmStatic external fun runComputeDiagnostics(sessionToken: Long = 0): String
    @JvmStatic external fun runViDiagnostics(sessionToken: Long = 0): String
    @JvmStatic external fun runWindowDiagnostics(sessionToken: Long = 0): String
    @JvmStatic external fun runSampledDiagnostics(sessionToken: Long = 0): String
    @JvmStatic external fun sampledFrameSnapshot(): String
    @JvmStatic external fun acknowledgeSampledFrame(id: Long, frame: Int): Boolean
    @JvmStatic external fun runDrawDiagnostics(activity: MainActivity, present: Boolean,
                                               sessionToken: Long = 0): String
    @JvmStatic external fun surfaceSnapshot(activity: MainActivity): String

    fun end(token: Long): Boolean {
        val closed = nativeEnd(token)
        if (closed) DiagnosticCoordinator.ownerReleased()
        return closed
    }
}
