package org.d2rmobile.diagnostics

import android.content.Context
import android.content.ContextWrapper
import android.content.pm.ProviderInfo
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.DocumentsProvider
import android.system.Os
import android.system.OsConstants
import android.test.InstrumentationTestCase
import android.test.mock.MockContentResolver
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CancellationException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Self-authored package/resource bytes test transport integrity, never native authority. */
@Suppress("DEPRECATION")
class TaikoContentStoreTest : InstrumentationTestCase() {
    private lateinit var scratch: File
    private lateinit var localContext: Context

    override fun setUp() {
        super.setUp()
        scratch = File(instrumentation.targetContext.cacheDir, "taiko-content-test-${UUID.randomUUID()}")
        assertTrue(scratch.mkdirs())
        localContext = object : ContextWrapper(instrumentation.targetContext) {
            override fun getFilesDir() = File(scratch, "private").apply { mkdirs() }
        }
    }

    override fun tearDown() { scratch.deleteRecursively(); super.tearDown() }

    fun testImportPreservesNestedPathsAndRehashesInstalledFiles() {
        val input = fixture("first")
        val store = TaikoContentStore(localContext)
        val result = store.importDirectory(input)
        assertTrue(result.integrityVerified)
        assertTrue(result.modulesVerified)
        assertTrue(result.contentReady)
        assertFalse(result.nativeStartupAdmitted)
        assertEquals(6, result.files)
        assertEquals(hash(File(input, MANIFEST).readBytes()), result.manifestSha256)
        assertEquals("song-first", File(store.romfsDirectory, "Data/StreamingAssets/song/song.bin").readText())
        assertEquals("shared-first", File(store.romfsDirectory, "Data/shared.bin").readText())
        assertTrue(File(store.moduleDirectory, "subsdk0.dmag").isFile)
        File(store.romfsDirectory, "Data/shared.bin").writeText("tampered")
        assertFalse(store.inspect().integrityVerified)
    }

    fun testInvalidIdentityCannotReplaceInstalledContent() {
        val store = TaikoContentStore(localContext)
        store.importDirectory(fixture("old"))
        val mutations: List<(JSONObject) -> Unit> = listOf(
            { it.put("schema", 2) }, { it.put("schema", "1") },
            { it.put("target", "d2r-android") }, { it.put("program_id", "01002460135A4800") },
            { it.put("selected_exefs_display_version", "1.1.1") },
            { it.put("module_order", JSONArray(listOf("main", "sdk", "subsdk0"))) },
            { it.getJSONArray("sources").getJSONObject(0).put("sha256", "0".repeat(64)) },
            { it.getJSONArray("sources").getJSONObject(1).put("bytes", 1) },
            { it.getJSONArray("sources").getJSONObject(2).put("build_id", "0".repeat(64)) },
            { it.getJSONArray("sources").remove(4) },
            { it.getJSONArray("packages").getJSONObject(0).put("source_sha256", "0".repeat(64)) },
            { it.getJSONArray("packages").getJSONObject(0).put("path", "modules/sdk.dmag") },
            { it.remove("import_receipt") },
            { it.getJSONObject("import_receipt").put("path", "RomFS/import.json") },
            { it.put("total_bytes", 1) }
        )
        mutations.forEachIndexed { index, mutate ->
            val input = fixture("bad-$index")
            edit(input, mutate)
            expectFailure { store.importDirectory(input) }
            assertEquals("shared-old", File(store.romfsDirectory, "Data/shared.bin").readText())
        }
    }

    fun testUnsafeDuplicateAndCaseCollidingPathsAreRejected() {
        val paths = listOf("../outside", "/RomFS/a", "RomFS/../a", "RomFS//a", "RomFS/a\\b",
            "RomFS/a/./b", "RomFS/C:/a", "RomFS/a\u0000b", "modules/main.dmag", "RomFS/")
        paths.forEachIndexed { index, path ->
            val input = fixture("path-$index")
            edit(input) { it.getJSONArray("files").getJSONObject(0).put("path", path) }
            val error = expectFailure { TaikoContentStore(localContext).importDirectory(input) }
            assertTrue(error.message.orEmpty().contains("path", ignoreCase = true))
        }
        for (path in listOf("RomFS/Data/shared.bin", "RomFS/data/SHARED.bin", "RomFS/Data/shared.bin/child")) {
            val input = fixture("collision-${UUID.randomUUID()}")
            edit(input) { json ->
                json.getJSONArray("files").put(entry(path, byteArrayOf(1)))
                json.remove("total_bytes")
            }
            val error = expectFailure { TaikoContentStore(localContext).importDirectory(input) }
            assertTrue("Collision must fail during manifest admission: $error",
                error.message.orEmpty().contains("colli", ignoreCase = true) || error.message.orEmpty().contains("Duplicate"))
        }
    }

    fun testBadSizesHashesAndMissingOrUnlistedFilesFailClosed() {
        val mutations: List<(File) -> Unit> = listOf(
            { edit(it) { j -> j.getJSONArray("files").getJSONObject(0).put("bytes", -1) } },
            { edit(it) { j -> j.getJSONArray("files").getJSONObject(0).put("bytes", 1.5) } },
            { edit(it) { j -> j.getJSONArray("files").getJSONObject(0).put("bytes", "1") } },
            { edit(it) { j -> j.getJSONArray("files").getJSONObject(0).put("sha256", "z".repeat(64)) } },
            { File(it, "RomFS/Data/shared.bin").delete() },
            { File(it, "RomFS/Data/shared.bin").writeText("bad") },
            { File(it, "RomFS/Data/unlisted.bin").writeText("extra") },
            { File(it, "modules/sdk.dmag").appendText("trailing") },
            { File(it, MANIFEST).appendText("{}") }
        )
        mutations.forEachIndexed { index, mutate ->
            val input = fixture("bad-data-$index")
            mutate(input)
            expectFailure { TaikoContentStore(localContext).importDirectory(input) }
        }
    }

    fun testCancellationAndFailedCopyPreserveContentAndSave() {
        val store = TaikoContentStore(localContext)
        store.importDirectory(fixture("before"))
        File(store.saveDirectory, "progress.bin").writeText("saved")
        val token = CancellationToken()
        try {
            store.importDirectory(fixture("after"), token) { token.cancel() }
            fail("Expected cancellation")
        } catch (_: CancellationException) { }
        assertTrue(store.inspect().integrityVerified)
        assertEquals("shared-before", File(store.romfsDirectory, "Data/shared.bin").readText())
        assertEquals("saved", File(store.saveDirectory, "progress.bin").readText())
        val corrupt = fixture("corrupt")
        File(corrupt, "modules/subsdk0.dmag").writeText("corrupt")
        expectFailure { store.importDirectory(corrupt) }
        assertEquals("shared-before", File(store.romfsDirectory, "Data/shared.bin").readText())
    }

    fun testSymlinkSourceAndInstalledExtraFilesAreRejected() {
        val input = fixture("symlink")
        val path = File(input, "RomFS/Data/shared.bin")
        val outside = File(scratch, "outside").apply { writeBytes(path.readBytes()) }
        assertTrue(path.delete())
        Os.symlink(outside.absolutePath, path.absolutePath)
        val store = TaikoContentStore(localContext)
        expectFailure { store.importDirectory(input) }
        store.importDirectory(fixture("clean"))
        File(store.romfsDirectory, "unlisted.bin").writeText("extra")
        assertFalse(store.inspect().integrityVerified)
    }

    fun testInterruptedPublicationRecoversPreviousContent() {
        val store = TaikoContentStore(localContext)
        store.importDirectory(fixture("recovery"))
        Os.rename(store.contentDirectory.absolutePath, File(store.rootDirectory, "content.previous").absolutePath)
        assertTrue(store.inspect().integrityVerified)
        assertEquals("shared-recovery", File(store.romfsDirectory, "Data/shared.bin").readText())
        assertFalse(File(store.rootDirectory, "content.previous").exists())
    }

    fun testAbandonedStagesAreRecoveredWithoutRemovingUnrelatedOrLinkedEntries() {
        val store = TaikoContentStore(localContext)
        store.importDirectory(fixture("installed"))
        val stale = File(store.tempDirectory, "content-${UUID.randomUUID()}").apply { mkdirs() }
        File(stale, "modules/main.dmag").apply { parentFile!!.mkdirs(); writeText("interrupted module bytes") }
        val unrelated = File(store.tempDirectory, "unrelated-cache").apply { mkdirs() }
        File(unrelated, "keep.bin").writeText("keep")
        val partialName = File(store.tempDirectory, "content-not-a-uuid").apply { mkdirs() }
        File(partialName, "keep.bin").writeText("keep")
        val outside = File(scratch, "outside-stage").apply { mkdirs() }
        File(outside, "keep.bin").writeText("outside")
        val linked = File(store.tempDirectory, "content-${UUID.randomUUID()}")
        Os.symlink(outside.absolutePath, linked.absolutePath)
        val nestedLink = File(store.tempDirectory, "content-${UUID.randomUUID()}").apply { mkdirs() }
        Os.symlink(outside.absolutePath, File(nestedLink, "linked").absolutePath)
        File(store.saveDirectory, "progress.bin").writeText("save")

        // Recovery runs before admission/free-space checks, even if the new transfer fails.
        val invalid = fixture("invalid-retry")
        edit(invalid) { it.put("target", "wrong-target") }
        expectFailure { store.importDirectory(invalid) }
        assertFalse("Abandoned own stage must be removed before evaluating a retry", stale.exists())
        assertEquals("keep", File(unrelated, "keep.bin").readText())
        assertEquals("keep", File(partialName, "keep.bin").readText())
        assertTrue(OsConstants.S_ISLNK(Os.lstat(linked.absolutePath).st_mode))
        assertTrue(OsConstants.S_ISLNK(Os.lstat(File(nestedLink, "linked").absolutePath).st_mode))
        assertEquals("outside", File(outside, "keep.bin").readText())
        assertEquals("save", File(store.saveDirectory, "progress.bin").readText())
        assertTrue(store.inspect().integrityVerified)
    }

    fun testNativeContentLeaseBlocksCancellableImportAndPreservesSave() {
        val store = TaikoContentStore(localContext)
        store.importDirectory(fixture("before-lease"))
        File(store.saveDirectory, "progress.bin").writeText("saved-before-lease")
        val input = fixture("after-lease")
        val leaseEntered = CountDownLatch(1)
        val releaseLease = CountDownLatch(1)
        val leaseDone = CountDownLatch(1)
        val leaseResult = AtomicReference<String?>()
        val leaseFailure = AtomicReference<Throwable?>()
        val lease = Thread {
            try {
                leaseResult.set(store.withNativeContent {
                    leaseEntered.countDown()
                    if (!releaseLease.await(5, TimeUnit.SECONDS)) throw IOException("Lease test was not released")
                    "lease-completed"
                })
            } catch (error: Throwable) { leaseFailure.set(error) }
            finally { leaseDone.countDown() }
        }.apply { start() }
        val cancellation = CancellationToken()
        val importStarted = CountDownLatch(1)
        val importDone = CountDownLatch(1)
        val importFailure = AtomicReference<Throwable?>()
        var importer: Thread? = null
        try {
            assertTrue("Content lease must be held before starting import", leaseEntered.await(2, TimeUnit.SECONDS))
            // A distinct Store instance must use the same process-wide content lock.
            importer = Thread {
                importStarted.countDown()
                try { TaikoContentStore(localContext).importDirectory(input, cancellation) }
                catch (error: Throwable) { importFailure.set(error) }
                finally { importDone.countDown() }
            }.apply { start() }
            assertTrue(importStarted.await(2, TimeUnit.SECONDS))
            assertFalse("Import cannot finish while native content lease is held", importDone.await(150, TimeUnit.MILLISECONDS))
            cancellation.cancel()
            assertTrue("Waiting import must remain cancellable", importDone.await(2, TimeUnit.SECONDS))
            assertTrue("Cancelled waiter must report cancellation: ${importFailure.get()}", importFailure.get() is CancellationException)
            assertEquals("shared-before-lease", File(store.romfsDirectory, "Data/shared.bin").readText())
            assertEquals("saved-before-lease", File(store.saveDirectory, "progress.bin").readText())
        } finally {
            cancellation.cancel()
            releaseLease.countDown()
            importer?.join(2_000)
            lease.join(2_000)
        }
        assertTrue(leaseDone.await(1, TimeUnit.SECONDS))
        assertNull("Content lease failed: ${leaseFailure.get()}", leaseFailure.get())
        assertEquals("lease-completed", leaseResult.get())
        assertTrue(store.importDirectory(input).integrityVerified)
        assertEquals("shared-after-lease", File(store.romfsDirectory, "Data/shared.bin").readText())
        assertEquals("saved-before-lease", File(store.saveDirectory, "progress.bin").readText())
    }

    fun testNativeContentLeaseRefusesNestedStoreOperations() {
        val store = TaikoContentStore(localContext)
        assertEquals("nested-refused", store.withNativeContent {
            val error = expectFailure { store.inspect() }
            assertTrue(error.message.orEmpty().contains("already running"))
            "nested-refused"
        })
    }

    fun testSafImportPreservesNestedTreeAndRejectsUnsafeProviderNames() {
        val input = fixture("saf")
        val provider = FixtureProvider(input)
        val mock = MockContentResolver(localContext)
        provider.attachInfo(localContext, ProviderInfo().apply {
            authority = AUTHORITY; exported = true; grantUriPermissions = true
            readPermission = "android.permission.MANAGE_DOCUMENTS"
            writePermission = "android.permission.MANAGE_DOCUMENTS"
        })
        mock.addProvider(AUTHORITY, provider)
        val wrapped = object : ContextWrapper(localContext) { override fun getContentResolver() = mock }
        val store = TaikoContentStore(wrapped)
        assertTrue(store.importTree(provider.tree).integrityVerified)
        assertEquals("song-saf", File(store.romfsDirectory, "Data/StreamingAssets/song/song.bin").readText())
        provider.unsafeName = true
        expectFailure { store.importTree(provider.tree) }
        assertTrue(store.inspect().integrityVerified)
    }

    private fun fixture(label: String): File {
        val directory = File(scratch, "input-$label").apply { mkdirs() }
        val payloads = linkedMapOf(
            "import.json" to "self-authored-import-receipt-$label".toByteArray(),
            "modules/main.dmag" to "self-authored-main-$label".toByteArray(),
            "modules/subsdk0.dmag" to "self-authored-subsdk0-$label".toByteArray(),
            "modules/sdk.dmag" to "self-authored-sdk-$label".toByteArray(),
            "RomFS/Data/shared.bin" to "shared-$label".toByteArray(),
            "RomFS/Data/StreamingAssets/song/song.bin" to "song-$label".toByteArray())
        payloads.forEach { (path, bytes) -> File(directory, path).apply { parentFile!!.mkdirs(); writeBytes(bytes) } }
        val sources = JSONArray()
        PINS.forEach { pin ->
            sources.put(JSONObject().put("name", pin[0]).put("bytes", pin[1].toLong()).put("sha256", pin[2]).apply {
                if (pin.size == 4) put("build_id", pin[3])
            })
        }
        val packages = JSONArray()
        MODULES.forEach { name ->
            packages.put(entry("modules/$name.dmag", payloads.getValue("modules/$name.dmag"))
                .put("name", name).put("source_sha256", PINS.first { it[0] == name }[2]))
        }
        val files = JSONArray()
        payloads.filterKeys { it.startsWith("RomFS/") }.forEach { (path, bytes) -> files.put(entry(path, bytes)) }
        File(directory, MANIFEST).writeText(JSONObject().put("schema", 1).put("target", "taiko-android")
            .put("program_id", "01002460135A4000").put("selected_exefs_display_version", JSONObject.NULL)
            .put("module_order", JSONArray(MODULES)).put("sources", sources).put("packages", packages)
            .put("import_receipt", entry("import.json", payloads.getValue("import.json")))
            .put("files", files).put("total_bytes", payloads.values.sumOf { it.size.toLong() }).toString())
        return directory
    }

    private fun edit(directory: File, mutation: (JSONObject) -> Unit) {
        val file = File(directory, MANIFEST)
        val json = JSONObject(file.readText()); mutation(json); file.writeText(json.toString())
    }

    private fun expectFailure(action: () -> Unit): IOException {
        try { action() } catch (error: IOException) { return error }
        throw AssertionError("Expected Taiko content rejection")
    }

    private class FixtureProvider(private val root: File) : DocumentsProvider() {
        var unsafeName = false
        val tree: Uri = DocumentsContract.buildTreeDocumentUri(AUTHORITY, "root")
        override fun onCreate() = true
        private fun file(id: String) = if (id == "root") root else File(root, id.removePrefix("root/"))
        override fun isChildDocument(parentDocumentId: String, documentId: String) =
            documentId == parentDocumentId || documentId.startsWith("$parentDocumentId/")
        override fun queryRoots(projection: Array<out String>?): Cursor = MatrixCursor(arrayOf(DocumentsContract.Root.COLUMN_ROOT_ID))
        override fun queryDocument(documentId: String, projection: Array<out String>?): Cursor = cursor(projection).apply {
            add(this, documentId, file(documentId))
        }
        override fun queryChildDocuments(parentDocumentId: String, projection: Array<out String>?, sortOrder: String?): Cursor = cursor(projection).apply {
            file(parentDocumentId).listFiles()!!.forEach { add(this, "$parentDocumentId/${it.name}", it) }
        }
        override fun openDocument(documentId: String, mode: String, signal: CancellationSignal?): ParcelFileDescriptor {
            check(mode == "r"); signal?.throwIfCanceled()
            return ParcelFileDescriptor.open(file(documentId), ParcelFileDescriptor.MODE_READ_ONLY)
        }
        private fun cursor(projection: Array<out String>?) = MatrixCursor(projection ?: arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE, DocumentsContract.Document.COLUMN_SIZE))
        private fun add(cursor: MatrixCursor, id: String, file: File) {
            cursor.addRow(cursor.columnNames.map<String, Any?> { column -> when (column) {
                DocumentsContract.Document.COLUMN_DOCUMENT_ID -> id
                DocumentsContract.Document.COLUMN_DISPLAY_NAME -> if (unsafeName && file.name == MANIFEST) "../$MANIFEST" else file.name
                DocumentsContract.Document.COLUMN_MIME_TYPE -> if (file.isDirectory) DocumentsContract.Document.MIME_TYPE_DIR else "application/octet-stream"
                DocumentsContract.Document.COLUMN_SIZE -> if (file.isDirectory) null else file.length()
                else -> null
            } }.toTypedArray())
        }
    }

    companion object {
        private const val MANIFEST = "taiko-content.json"
        private const val AUTHORITY = "org.taikocompat.test.content"
        private val MODULES = listOf("main", "subsdk0", "sdk")
        private val PINS = listOf(
            listOf("rtld", "7132", "8e08c8cf2e4d6b39d69643af10ce765d39c06860878224c68f8cafc45a2636aa", "567cdd4c5251494c5cd70822e3ccc740c190c2b2000000000000000000000000"),
            listOf("main", "38127530", "f1313fe0d6cd4a024e53d8a283434448bacea453b02f37b75b18bfe281d0fcff", "4541b79257635ce79105b3ba59e4808500000000000000000000000000000000"),
            listOf("subsdk0", "3385425", "f38d30e8241ee208cbf3090f44613e328af517ad199eb5985619416bb2cbcb55", "a8cb97803f7f442a3b6cce1c7cd4ee4a78b7def3000000000000000000000000"),
            listOf("sdk", "5989236", "2a89fa1c0e677710e89ed29b578162affef530a0c9b8c93cda15d50a57a20d28", "357efc198e728cb5d55265aff304f03cfc9cc0e3000000000000000000000000"),
            listOf("main.npdm", "1572", "afd3aade95cbcc607759eb677b67082193719a701a5b0cc8ed78ac33b5c65150"))
        private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        private fun entry(path: String, bytes: ByteArray) = JSONObject().put("path", path).put("bytes", bytes.size).put("sha256", hash(bytes))
    }
}
