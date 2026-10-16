package org.d2rmobile.diagnostics

import org.json.JSONObject

/** Checks archive sizes/extents; it never establishes game execution. */
object NativeResources {
    init { System.loadLibrary("d2r_diagnostics") }
    external fun validateRomFs(path: String): String

    fun validate(path: String): ResourceValidation {
        val report = JSONObject(validateRomFs(path))
        return ResourceValidation(report.getBoolean("ready"), report.getString("details"))
    }
}
