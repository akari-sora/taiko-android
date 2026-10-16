package org.d2rmobile.diagnostics

import android.test.InstrumentationTestCase
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
import android.test.mock.MockContentResolver
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CancellationException

/** Self-authored resource bytes only; these tests cannot establish game readiness. */
@Suppress("DEPRECATION")
class ResourceStoreTest : InstrumentationTestCase() {
    private lateinit var scratch: File
    private val context: Context get() = instrumentation.targetContext

    override fun setUp() {
        super.setUp()
        scratch = File(context.cacheDir, "resource-test-${UUID.randomUUID()}")
        assertTrue(scratch.mkdirs())
    }

    override fun tearDown() {
        scratch.deleteRecursively()
        super.tearDown()
    }

    fun testStrictManifestRejectsAmbiguousOrUnboundedInputs() {
        val good = fileEntry("one.data", byteArrayOf(1))
        assertEquals(1, ResourceStore.parseManifest(manifest(good)).files.size)
        val ignored = fileEntry("extractor.json", byteArrayOf(2))
        assertEquals(1, ResourceStore.parseManifest(manifest(good, ignored)).files.size)
        val bad = listOf(
            manifest(good, good),
            manifest(JSONObject(good.toString()).put("name", "../one.data")),
            manifest(JSONObject(good.toString()).put("name", "dir\\one.data")),
            manifest(JSONObject(good.toString()).put("name", ".hidden.data")),
            manifest(JSONObject(good.toString()).put("name", "one%2f.data")),
            manifest(JSONObject(good.toString()).put("size", -1)),
            manifest(JSONObject(good.toString()).put("size", Long.MAX_VALUE)),
            manifest(JSONObject(good.toString()).put("size", 1.5)),
            manifest(JSONObject(good.toString()).put("size", "1")),
            manifest(JSONObject(good.toString()).put("sha256", "z".repeat(64))),
            manifest(ignored), "{\"files\":[]}", "{}"
        )
        bad.forEach { expectFailure { ResourceStore.parseManifest(it) } }
    }

    fun testRangedDownloadHashesBeforePublishingAndUsesNativeReadiness() {
        val bytes = "self-authored-resource-0123456789".toByteArray()
        val server = FixtureTransport(mapOf("one.data" to bytes))
        var validations = 0
        val store = store(server) { path ->
            validations++
            assertEquals(storePath().absolutePath, path)
            ResourceValidation(false, "Original game archives are absent")
        }
        val result = store.download(BASE)
        assertTrue(result.shaVerified)
        assertFalse("Self-authored fixtures must not grant native game readiness", result.validation.ready)
        assertEquals(1, validations)
        assertEquals(bytes.size.toLong(), result.bytes)
        assertTrue(File(store.dataDirectory, "one.data").readBytes().contentEquals(bytes))
        assertFalse(File(store.dataDirectory, "one.data.part").exists())
        assertTrue(server.ranges.size > 1)
        assertEquals(0L, server.ranges.first().first)
        val calls = server.ranges.size
        store.download(BASE)
        assertEquals("Existing files are hash checked and then reused", calls, server.ranges.size)
        File(store.dataDirectory, "one.data").writeBytes(ByteArray(bytes.size))
        assertFalse(store.inspect().shaVerified)
        store.download(BASE)
        assertTrue(server.ranges.size > calls)
    }

    fun testWrongRangesTruncationAndCorruptionNeverPublish() {
        val bytes = "abcdefgh".toByteArray()
        for (mode in listOf("status", "range", "total", "length", "short", "long", "hash", "encoding")) {
            val server = FixtureTransport(mapOf("one.data" to bytes), mode)
            val directory = File(scratch, mode)
            val store = store(server, directory)
            expectFailure { store.download(BASE) }
            assertFalse("$mode must not publish", File(store.dataDirectory, "one.data").exists())
            assertFalse("Range staging must be cleaned", File(store.tempDirectory, "resource-range.tmp").exists())
            if (mode == "hash") assertEquals("Whole file retries are bounded at three", 6, server.ranges.size)
            else assertEquals("Protocol errors do not retry endlessly", 1, server.ranges.size)
        }
    }

    fun testCancellationPersistsOnlyCompletedRangesAndRestartResumes() {
        val bytes = "abcdefghijkl".toByteArray()
        val server = FixtureTransport(mapOf("one.data" to bytes))
        val token = CancellationToken()
        server.beforeRange = { offset -> if (offset == 4L) token.cancel() }
        val store = store(server)
        try { store.download(BASE, token); fail("Expected cancellation") }
        catch (_: CancellationException) { }
        assertEquals(4L, File(store.dataDirectory, "one.data.part").length())
        assertFalse(File(store.dataDirectory, "one.data").exists())
        val resumed = FixtureTransport(mapOf("one.data" to bytes))
        assertTrue(store(resumed).download(BASE).shaVerified)
        assertEquals(4L, resumed.ranges.first().first)
    }

    fun testStorageAdmissionFailurePreservesCompletedArchives() {
        val good = "already-complete".toByteArray()
        val server = FixtureTransport(linkedMapOf("good.data" to good, "next.data" to byteArrayOf(9)))
        val store = ResourceStore(context, { ResourceValidation(false, "Fixture only") }, server, { 0L }, 4, scratch)
        File(store.dataDirectory, "good.data").writeBytes(good)
        expectFailure { store.download(BASE) }
        assertTrue(File(store.dataDirectory, "good.data").readBytes().contentEquals(good))
        assertFalse(File(store.dataDirectory, "next.data").exists())
        assertEquals(0, server.ranges.size)
    }

    fun testBadOrIncompleteManifestCannotOverrideValidationGate() {
        // This callback only tests the conjunction of two independent gates, not native/game
        // compatibility. NativeResources has separate tests using its actual archive inventory.
        val server = FixtureTransport(mapOf("one.data" to byteArrayOf(1, 2, 3, 4)))
        val store = store(server) { ResourceValidation(true, "Synthetic gate accepted") }
        assertTrue(store.download(BASE).validation.ready)
        File(store.dataDirectory, "one.data").writeBytes(byteArrayOf(4, 3, 2, 1))
        assertFalse("Equal byte count cannot satisfy a supplied bad hash", store.inspect().validation.ready)
        store.download(BASE)
        File(store.dataDirectory, "unlisted.data").writeBytes(byteArrayOf(9))
        val incomplete = store.inspect()
        assertFalse("An incomplete manifest cannot attest unlisted archive bytes", incomplete.shaVerified)
        assertFalse(incomplete.validation.ready)
    }

    fun testHttpsBaseCannotBeDowngradedOrContainCredentials() {
        val server = FixtureTransport(mapOf("one.data" to byteArrayOf(1)))
        val store = store(server)
        listOf("http://example.test", "https://user:secret@example.test", "https://example.test/?key=x",
            "https://example.test/#fragment", "https://example.test/%2f", "https://example.test/../outside")
            .forEach { value -> expectFailure { store.download(value) } }
        assertEquals(0, server.requests)
    }

    fun testActualHttpURLConnectionRangesEncodingRedirectAndCancellation() {
        val bytes = "actual-loopback-network-fixture".toByteArray()
        ResourceTestHttpServer(bytes).use { server ->
            val store = store(ResourceStore.loopbackTransportForTests(server.port), File(scratch, "http"))
            assertTrue(store.download(BASE).shaVerified)
            assertEquals("bytes=0-3", server.ranges.first())
        }
        for (mode in listOf("encoded", "redirect")) {
            ResourceTestHttpServer(bytes, mode).use { server ->
                val store = store(ResourceStore.loopbackTransportForTests(server.port), File(scratch, mode))
                expectFailure { store.download(BASE) }
                assertFalse(File(store.dataDirectory, "one.data").exists())
                assertEquals(1, server.ranges.size)
            }
        }
        ResourceTestHttpServer(bytes, "blocked").use { server ->
            val store = store(ResourceStore.loopbackTransportForTests(server.port), File(scratch, "blocked"))
            val token = CancellationToken()
            val stopped = java.util.concurrent.CountDownLatch(1)
            val failure = java.util.concurrent.atomic.AtomicReference<Throwable>()
            val thread = Thread {
                try { store.download(BASE, token); failure.set(AssertionError("Expected cancellation")) }
                catch (_: CancellationException) { }
                catch (error: Throwable) { failure.set(error) }
                finally { stopped.countDown() }
            }
            thread.start()
            assertTrue(server.rangeStarted.await(5, java.util.concurrent.TimeUnit.SECONDS))
            token.cancel()
            assertTrue("Cancellation disconnects a blocked socket", stopped.await(5, java.util.concurrent.TimeUnit.SECONDS))
            assertNull(failure.get())
            assertFalse(File(store.dataDirectory, "one.data").exists())
        }
    }

    fun testSafTreeImportTraversesOuterFolderAndChecksManifest() {
        val archive = "local-SAF-fixture".toByteArray()
        val provider = FixtureDocumentsProvider(File(scratch, "provider"))
        provider.folder("root", "outer", "Resources")
        provider.folder("outer", "data", "data")
        provider.file("outer", "manifest", "manifest.json", manifest(fileEntry("one.data", archive)).toByteArray())
        provider.file("data", "archive", "one.data", archive)
        val store = providerStore(provider)
        val result = store.importTree(provider.tree)
        assertTrue(result.shaVerified)
        assertFalse(result.validation.ready)
        assertTrue(File(store.dataDirectory, "one.data").readBytes().contentEquals(archive))
    }

    fun testSafWithoutManifestTracksSizeOnlyAndRejectsDuplicateNames() {
        val provider = FixtureDocumentsProvider(File(scratch, "provider"))
        provider.file("root", "one", "one.data", byteArrayOf(1, 2, 3))
        val store = providerStore(provider)
        assertFalse(store.importTree(provider.tree).shaVerified)
        assertFalse(store.inspect().shaVerified)
        provider.folder("root", "nested", "another-copy")
        provider.file("nested", "duplicate", "one.data", byteArrayOf(4))
        expectFailure { store.importTree(provider.tree) }
        assertTrue(File(store.dataDirectory, "one.data").readBytes().contentEquals(byteArrayOf(1, 2, 3)))
    }

    fun testSafBadHashOrUnknownSizeCannotPublish() {
        val provider = FixtureDocumentsProvider(File(scratch, "provider"))
        provider.file("root", "manifest", "manifest.json", manifest(fileEntry("one.data", byteArrayOf(1))).toByteArray())
        provider.file("root", "archive", "one.data", byteArrayOf(2))
        val store = providerStore(provider)
        expectFailure { store.importTree(provider.tree) }
        assertFalse(File(store.dataDirectory, "one.data").exists())
        provider.nodes.remove("manifest")
        provider.nodes.getValue("archive").reportedSize = null
        expectFailure { store.importTree(provider.tree) }
    }

    fun testSafProviderOpeningCancellationReleasesOperationLock() {
        val provider = FixtureDocumentsProvider(File(scratch, "provider"))
        provider.file("root", "archive", "one.data", byteArrayOf(1, 2, 3))
        provider.blockOpen = true
        val store = providerStore(provider)
        val token = CancellationToken()
        val stopped = java.util.concurrent.CountDownLatch(1)
        val failure = java.util.concurrent.atomic.AtomicReference<Throwable>()
        Thread {
            try { store.importTree(provider.tree, token); failure.set(AssertionError("Expected SAF cancellation")) }
            catch (_: CancellationException) { }
            catch (error: Throwable) { failure.set(error) }
            finally { stopped.countDown() }
        }.start()
        assertTrue(provider.openStarted.await(5, java.util.concurrent.TimeUnit.SECONDS))
        token.cancel()
        assertTrue("Provider receives cancellation while opening", stopped.await(5, java.util.concurrent.TimeUnit.SECONDS))
        assertNull(failure.get())
        provider.blockOpen = false
        assertFalse(store.importTree(provider.tree).shaVerified)
    }

    fun testInspectionCancellationAndReentrantOperationsAreRejected() {
        val server = FixtureTransport(mapOf("one.data" to byteArrayOf(1, 2, 3, 4, 5)))
        val store = store(server)
        var sawReentryRejection = false
        store.download(BASE, onProgress = {
            try { store.inspect() } catch (_: IOException) { sawReentryRejection = true }
        })
        assertTrue(sawReentryRejection)
        val token = CancellationToken().apply { cancel() }
        try { store.inspect(token); fail("Expected cancelled inspection") } catch (_: CancellationException) { }
    }

    fun testTransferWaitsForInspectionHandoffAndWaitingCanBeCancelled() {
        val inspecting = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val inspectionDone = java.util.concurrent.CountDownLatch(1)
        val inspector = store(FixtureTransport(emptyMap()), File(scratch, "inspection")) {
            inspecting.countDown()
            release.await(10, java.util.concurrent.TimeUnit.SECONDS)
            ResourceValidation(false, "Fixture only")
        }
        Thread { try { inspector.inspect() } finally { inspectionDone.countDown() } }.start()
        assertTrue(inspecting.await(5, java.util.concurrent.TimeUnit.SECONDS))
        val server = FixtureTransport(mapOf("one.data" to byteArrayOf(1, 2, 3)))
        val transfer = store(server)
        val cancelled = java.util.concurrent.CountDownLatch(1)
        val token = CancellationToken()
        val failure = java.util.concurrent.atomic.AtomicReference<Throwable>()
        try {
            Thread {
                try { transfer.download(BASE, token); failure.set(AssertionError("Expected waiting cancellation")) }
                catch (_: CancellationException) { }
                catch (error: Throwable) { failure.set(error) }
                finally { cancelled.countDown() }
            }.start()
            token.cancel()
            assertTrue(cancelled.await(5, java.util.concurrent.TimeUnit.SECONDS))
            assertNull(failure.get())
            assertEquals("Waiting transfer must not touch the network", 0, server.requests)
            val completed = java.util.concurrent.CountDownLatch(1)
            Thread {
                try { transfer.download(BASE) }
                catch (error: Throwable) { failure.set(error) }
                finally { completed.countDown() }
            }.start()
            assertFalse("No transfer can overlap an inspection", completed.await(100, java.util.concurrent.TimeUnit.MILLISECONDS))
            release.countDown()
            assertTrue(completed.await(5, java.util.concurrent.TimeUnit.SECONDS))
            assertNull(failure.get())
            assertTrue(File(transfer.dataDirectory, "one.data").exists())
        } finally {
            release.countDown()
            assertTrue(inspectionDone.await(5, java.util.concurrent.TimeUnit.SECONDS))
        }
    }

    private fun storePath() = File(scratch, "romfs/data")
    private fun store(
        transport: ResourceStore.Transport, root: File = scratch,
        validation: (String) -> ResourceValidation = { ResourceValidation(false, "Self-authored fixture, original game absent") }
    ) = ResourceStore(context, validation, transport, { Long.MAX_VALUE }, 4, root)

    private fun providerStore(provider: FixtureDocumentsProvider): ResourceStore {
        val mock = MockContentResolver(context)
        val info = ProviderInfo().apply {
            authority = AUTHORITY
            exported = true
            grantUriPermissions = true
            readPermission = "android.permission.MANAGE_DOCUMENTS"
            writePermission = "android.permission.MANAGE_DOCUMENTS"
        }
        provider.attachInfo(context, info)
        mock.addProvider(AUTHORITY, provider)
        val wrapped = object : ContextWrapper(context) { override fun getContentResolver() = mock }
        return ResourceStore(wrapped, { ResourceValidation(false, "Self-authored SAF fixture") },
            FixtureTransport(emptyMap()), { Long.MAX_VALUE }, 4, File(scratch, "store"))
    }

    private fun expectFailure(action: () -> Unit) {
        try { action(); fail("Expected resource rejection") } catch (_: IOException) { }
    }

    private class FixtureTransport(val files: Map<String, ByteArray>, val mode: String = "") : ResourceStore.Transport {
        val ranges = mutableListOf<Pair<Long, Long>>()
        var requests = 0
        var beforeRange: (Long) -> Unit = {}
        override fun open(url: String, start: Long?, end: Long?, token: CancellationToken?): ResourceStore.Response {
            requests++
            if (url.endsWith("/manifest.json")) {
                val bytes = manifest(*files.map { fileEntry(it.key, it.value) }.toTypedArray()).toByteArray()
                return ResourceStore.Response(200, null, bytes.size.toLong(), ByteArrayInputStream(bytes))
            }
            val first = start ?: throw IOException("Missing range start")
            val last = end ?: throw IOException("Missing range end")
            ranges.add(first to last)
            beforeRange(first)
            val source = files[url.substringAfterLast('/')] ?: throw IOException("Missing fixture")
            var bytes = source.copyOfRange(first.toInt(), last.toInt() + 1)
            if (mode == "short") bytes = bytes.copyOf(bytes.size - 1)
            if (mode == "long") bytes += byteArrayOf(9)
            if (mode == "hash") bytes[0] = (bytes[0].toInt() xor 1).toByte()
            return ResourceStore.Response(if (mode == "status") 200 else 206,
                if (mode == "range") "bytes 1-$last/${source.size}" else "bytes $first-$last/${source.size + if (mode == "total") 1 else 0}",
                last - first + if (mode == "length") 2 else 1, ByteArrayInputStream(bytes),
                if (mode == "encoding") "gzip" else null)
        }
    }

    /** Exercises DocumentsContract query/open routing with a real DocumentsProvider implementation. */
    private class FixtureDocumentsProvider(private val directory: File) : DocumentsProvider() {
        data class Node(val parent: String, val name: String, val file: File?, var reportedSize: Long?)
        val nodes = linkedMapOf("root" to Node("", "Selected", null, null))
        var blockOpen = false
        val openStarted = java.util.concurrent.CountDownLatch(1)
        val tree: Uri = DocumentsContract.buildTreeDocumentUri(AUTHORITY, "root")
        init { directory.mkdirs() }
        fun folder(parent: String, id: String, name: String) { nodes[id] = Node(parent, name, null, null) }
        fun file(parent: String, id: String, name: String, bytes: ByteArray) {
            val file = File(directory, id).apply { writeBytes(bytes) }
            nodes[id] = Node(parent, name, file, bytes.size.toLong())
        }
        override fun onCreate() = true
        override fun isChildDocument(parentDocumentId: String, documentId: String): Boolean {
            var current = documentId
            val seen = mutableSetOf<String>()
            while (seen.add(current)) {
                if (current == parentDocumentId) return true
                current = nodes[current]?.parent ?: return false
            }
            return false
        }
        override fun queryRoots(projection: Array<out String>?): Cursor = MatrixCursor(arrayOf(DocumentsContract.Root.COLUMN_ROOT_ID))
        override fun queryDocument(documentId: String, projection: Array<out String>?): Cursor = cursor(projection).apply {
            row(this, documentId, nodes.getValue(documentId))
        }
        override fun queryChildDocuments(parentDocumentId: String, projection: Array<out String>?, sortOrder: String?): Cursor = cursor(projection).apply {
            nodes.filter { it.value.parent == parentDocumentId }.forEach { (id, node) -> row(this, id, node) }
        }
        override fun openDocument(documentId: String, mode: String, signal: CancellationSignal?): ParcelFileDescriptor {
            require(mode == "r")
            if (blockOpen) {
                val cancellation = java.util.concurrent.CountDownLatch(1)
                signal?.setOnCancelListener { cancellation.countDown() }
                openStarted.countDown()
                cancellation.await(10, java.util.concurrent.TimeUnit.SECONDS)
                signal?.throwIfCanceled()
                throw IOException("Fixture provider did not receive cancellation")
            }
            return ParcelFileDescriptor.open(nodes.getValue(documentId).file, ParcelFileDescriptor.MODE_READ_ONLY)
        }
        private fun cursor(projection: Array<out String>?) = MatrixCursor(projection ?: arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE, DocumentsContract.Document.COLUMN_SIZE))
        private fun row(cursor: MatrixCursor, id: String, node: Node) {
            cursor.addRow(cursor.columnNames.map<String, Any?> { name -> when (name) {
                DocumentsContract.Document.COLUMN_DOCUMENT_ID -> id
                DocumentsContract.Document.COLUMN_DISPLAY_NAME -> node.name
                DocumentsContract.Document.COLUMN_MIME_TYPE -> if (node.file == null) DocumentsContract.Document.MIME_TYPE_DIR else "application/octet-stream"
                DocumentsContract.Document.COLUMN_SIZE -> node.reportedSize
                else -> null
            } }.toTypedArray())
        }
    }

    companion object {
        private const val BASE = "https://fixture.invalid/resources"
        private const val AUTHORITY = "org.d2rmobile.test.resources"
        private fun fileEntry(name: String, bytes: ByteArray): JSONObject = JSONObject().put("name", name)
            .put("size", bytes.size).put("sha256", MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it.toInt() and 255) })
        private fun manifest(vararg files: JSONObject) = JSONObject().put("files", JSONArray(files.toList())).toString()
    }
}
