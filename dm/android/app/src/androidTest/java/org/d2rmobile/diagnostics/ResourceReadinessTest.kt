package org.d2rmobile.diagnostics

import android.test.InstrumentationTestCase
import org.json.JSONObject
import java.io.File

/** Self-authored all-zero extents test the inventory, not real game contents. */
@Suppress("DEPRECATION")
class ResourceReadinessTest : InstrumentationTestCase() {
    fun testNativeInventoryAndMalformedExtentsNeverPromoteGameReadiness() {
        val root = File.createTempFile("resource-readiness-", "", instrumentation.targetContext.cacheDir)
        assertTrue(root.delete()); assertTrue(root.mkdir())
        val archives = linkedMapOf(
            "00-00000001.data" to 1073741824L, "00-00000002.data" to 1073741821L,
            "00-00000003.data" to 1026342790L, "00-00000004.data" to 3664822L,
            "00-00000005.data" to 391990840L, "00-00000006.data" to 3794407L,
            "01-00000001.data" to 344377972L, "01-00000002.data" to 37189352L,
            "02-00000001.data" to 368762692L, "02-00000002.data" to 23206186L,
            "03-00000001.data" to 251620752L, "03-00000002.data" to 55071917L,
            "04-00000001.data" to 118831405L, "04-00000002.data" to 8915855L,
            "05-00000001.data" to 478931036L, "05-00000002.data" to 92048235L,
            "17-00000001.data" to 204495617L, "17-00000002.data" to 4496514L
        )
        fun report() = JSONObject(NativeResources.validateRomFs(root.absolutePath)).also {
            assertFalse(it.getBoolean("gamePlayable"))
            assertEquals("sizes-and-extents", it.getString("integrity"))
        }
        try {
            assertFalse(report().getBoolean("ready"))
            for ((name, size) in archives) {
                File(root, name).writeBytes(byteArrayOf())
                File(root, "$name.holes").writeText("size $size\n0 $size\n")
            }
            assertTrue(report().getBoolean("ready"))
            val extraLink = File(root, "unexpected-link")
            android.system.Os.symlink("missing-target", extraLink.absolutePath)
            assertFalse("Readiness must include the strict tree validation", report().getBoolean("ready"))
            assertTrue(extraLink.delete())
            var nested = root
            repeat(65) { nested = File(nested, "depth"); assertTrue(nested.mkdir()) }
            assertFalse("Excessive tree depth must fail the actual JNI validator", report().getBoolean("ready"))
            assertTrue(File(root, "depth").deleteRecursively())
            assertTrue(report().getBoolean("ready"))
            for ((name, size) in archives) {
                val sidecar = File(root, "$name.holes")
                sidecar.appendText("malformed trailing metadata\n")
                assertFalse("Malformed extent table must fail: $name", report().getBoolean("ready"))
                sidecar.writeText("size $size\n0 $size\n")
                val archive = File(root, name)
                assertTrue(archive.delete())
                assertFalse("Every original archive is required: $name", report().getBoolean("ready"))
                archive.writeBytes(byteArrayOf())
            }
            assertTrue(report().getBoolean("ready"))
        } finally { assertTrue(root.deleteRecursively()) }
    }
}
