package org.d2rmobile.diagnostics

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.os.StatFs
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.system.Os
import android.system.OsConstants
import org.json.JSONObject
import java.io.Closeable
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.RandomAccessFile
import java.net.HttpURLConnection
import java.net.URI
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.CancellationException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock

data class ResourceValidation(val ready: Boolean, val details: String)
data class ResourceResult(val validation: ResourceValidation, val shaVerified: Boolean, val files: Int, val bytes: Long)
data class ResourceProgress(val done: Long, val total: Long, val file: String, val note: String)

class CancellationToken {
    private val cancelled = AtomicBoolean(false)
    private val callbacks = java.util.concurrent.CopyOnWriteArraySet<() -> Unit>()
    val isCancelled: Boolean get() = cancelled.get()
    fun cancel() { cancelCallbacks(asynchronous = false) }
    internal fun cancelAsync() { cancelCallbacks(asynchronous = true) }
    private fun cancelCallbacks(asynchronous: Boolean) {
        if (!cancelled.compareAndSet(false, true)) return
        callbacks.forEach { callback ->
            val close = Runnable { try { callback() } catch (_: Exception) { } }
            if (asynchronous) cancellationExecutor.execute(close) else close.run()
        }
    }
    internal fun check() { if (isCancelled) throw CancellationException("Transfer paused; resume to continue") }
    internal fun onCancel(callback: () -> Unit): Closeable {
        callbacks.add(callback)
        if (isCancelled) callback()
        return Closeable { callbacks.remove(callback) }
    }

    companion object {
        // A provider's cancellation Binder call may block. Never execute these callbacks on
        // the foreground service's main thread or before its timeout stop can be delivered.
        private val cancellationExecutor = java.util.concurrent.Executors.newCachedThreadPool { task ->
            Thread(task, "resource-cancel").apply { isDaemon = true }
        }
    }
}

/**
 * Disk-backed resource preparation, shared by the foreground service and setup UI.
 * Final names are published only after a complete SHA-256 check (when a manifest exists).
 * Resource readiness always comes from the original native RomFS validator.
 */
class ResourceStore internal constructor(
    context: Context,
    private val validate: (String) -> ResourceValidation,
    private val transport: Transport,
    private val availableSpace: (File) -> Long,
    private val chunkBytes: Long,
    private val rootOverride: File?
) {
    constructor(context: Context, validate: (String) -> ResourceValidation) : this(
        context.applicationContext, validate, UrlConnectionTransport(),
        { StatFs(it.absolutePath).availableBytes }, CHUNK_BYTES, null
    )

    private val resolver: ContentResolver = context.contentResolver
    private val root = rootOverride ?: File(context.filesDir, "game")
    val dataDirectory = File(root, "romfs/data")
    val saveDirectory = File(root, "save")
    val tempDirectory = File(root, "temp")
    private val manifestFile = File(dataDirectory.parentFile, "manifest.json")

    init {
        require(chunkBytes in 1..CHUNK_BYTES)
        listOf(dataDirectory, saveDirectory, tempDirectory).forEach {
            if (!it.isDirectory && !it.mkdirs() && !it.isDirectory) throw IOException("Cannot create ${it.name} directory")
        }
    }

    internal data class Entry(val name: String, val size: Long, val sha256: String)
    internal data class Manifest(val files: List<Entry>, val total: Long, val json: String)
    internal interface Transport {
        fun open(url: String, start: Long? = null, end: Long? = null, token: CancellationToken? = null): Response
    }
    internal class Response(
        val status: Int, val contentRange: String?, val length: Long,
        val input: InputStream, val contentEncoding: String? = null, private val release: () -> Unit = {}
    ) : Closeable {
        override fun close() { try { input.close() } finally { release() } }
    }

    /** This method hashes disk contents again; an old completion marker cannot grant readiness. */
    fun inspect(token: CancellationToken = CancellationToken()): ResourceResult = exclusive {
        inspectLocked(token, {})
    }

    fun download(
        baseUrl: String, token: CancellationToken = CancellationToken(),
        onProgress: (ResourceProgress) -> Unit = {}
    ): ResourceResult = exclusive(token, wait = true) {
        val base = safeBase(baseUrl)
        token.check()
        val text = try {
            transport.open("$base/manifest.json", token = token).use { response ->
                if (response.status != 200) throw IOException("Manifest server returned HTTP ${response.status}")
                readBounded(response.input, MAX_MANIFEST_BYTES, token).toString(Charsets.UTF_8)
            }
        } catch (error: Exception) { token.check(); throw error }
        val manifest = parseManifest(text)
        // Preserve the manifest used for this transfer before touching any archive bytes.
        atomicWrite(manifestFile, manifest.json.toByteArray(Charsets.UTF_8))
        var completed = 0L
        for (entry in manifest.files) {
            token.check()
            val final = archiveFile(entry.name)
            if (matches(final, entry, token)) { completed = Math.addExact(completed, entry.size); continue }
            val part = File(dataDirectory, "${entry.name}.part")
            if (part.exists() && (!part.isFile || part.length() > entry.size)) {
                if (!part.delete()) throw IOException("Cannot reset partial file ${entry.name}")
            }
            var corruptions = 0
            while (true) {
                token.check()
                var offset = if (part.isFile) part.length() else 0L
                checkSpace(entry.size - offset)
                while (offset < entry.size) {
                    token.check()
                    val end = offset + minOf(chunkBytes, entry.size - offset) - 1
                    var failures = 0
                    while (true) {
                        try {
                            receiveRange("$base/data/${entry.name}", entry, part, offset, end, token) { received ->
                                onProgress(ResourceProgress(completed + received, manifest.total, entry.name, "Downloading"))
                            }
                            break
                        } catch (error: RetryableNetworkException) {
                            if (++failures > MAX_NETWORK_ATTEMPTS) throw error
                            val delay = minOf(30_000L, 2_000L shl (failures - 1))
                            onProgress(ResourceProgress(completed + offset, manifest.total, entry.name,
                                "Network interrupted; retrying in ${delay / 1000} seconds"))
                            cancellableDelay(delay, token)
                        }
                    }
                    offset = part.length()
                }
                if (!part.exists()) FileOutputStream(part).use { it.fd.sync() }
                onProgress(ResourceProgress(completed + entry.size, manifest.total, entry.name, "Verifying SHA-256"))
                if (matches(part, entry, token)) { publish(part, final); break }
                if (!part.delete()) throw IOException("Cannot discard corrupt partial ${entry.name}")
                if (++corruptions >= MAX_HASH_ATTEMPTS) throw IOException("SHA-256 mismatch for ${entry.name} after $corruptions attempts")
            }
            completed = Math.addExact(completed, entry.size)
        }
        inspectLocked(token, onProgress)
    }

    /** Import a selected data directory or an enclosing resource tree, at most four folders deep. */
    fun importTree(
        tree: Uri, token: CancellationToken = CancellationToken(),
        onProgress: (ResourceProgress) -> Unit = {}
    ): ResourceResult = exclusive(token, wait = true) {
        val documents = discover(tree, token)
        val manifests = documents.filter { it.name == "manifest.json" }
        if (manifests.size > 1) throw IOException("More than one manifest found; select one resource folder")
        val manifest = manifests.singleOrNull()?.let { document ->
            withDocumentInput(document.uri, token) {
                parseManifest(readBounded(it, MAX_MANIFEST_BYTES, token).toString(Charsets.UTF_8))
            }
        }
        val archives = documents.filter { isArchive(it.name) }
        if (archives.isEmpty()) throw IOException("No .data or .data.holes archives found")
        val byName = archives.associateBy { it.name }
        if (byName.size != archives.size) throw IOException("Duplicate archive names in selected folders; select one resource folder")
        val entries = manifest?.files ?: archives.map {
            if (it.size == null || it.size !in 0..MAX_FILE_BYTES) throw IOException("Provider must report a bounded size for ${it.name}")
            Entry(it.name, it.size, "")
        }
        var total = 0L
        for (entry in entries) {
            total = checkedTotal(total, entry.size)
            if (byName[entry.name] == null) throw IOException("Missing selected archive ${entry.name}")
        }
        // A manifest-less import must not inherit a prior download's SHA provenance.
        if (manifest != null) atomicWrite(manifestFile, manifest.json.toByteArray(Charsets.UTF_8))
        else if (manifestFile.exists()) {
            if (!manifestFile.delete()) throw IOException("Cannot clear previous manifest")
            syncDirectory(manifestFile.parentFile!!)
        }
        var completed = 0L
        for (entry in entries) {
            token.check()
            val final = archiveFile(entry.name)
            if (manifest != null && matches(final, entry, token)) {
                completed += entry.size
                continue
            }
            checkSpace(entry.size)
            // SAF providers need not support seeking. A cancelled local copy restarts this file;
            // already published files stay intact, including when a provider disappears.
            val part = File(dataDirectory, "${entry.name}.import.part")
            try {
                val document = byName.getValue(entry.name)
                withDocumentInput(document.uri, token) { input ->
                    FileOutputStream(part, false).use { output ->
                        copyExact(input, output, entry.size, token) { count ->
                            onProgress(ResourceProgress(completed + count, total, entry.name, "Importing"))
                        }
                        output.fd.sync()
                    }
                }
                if (manifest != null && !matches(part, entry, token)) throw IOException("SHA-256 mismatch for imported ${entry.name}")
                token.check()
                publish(part, final)
            } catch (error: Exception) {
                part.delete()
                throw error
            }
            completed += entry.size
        }
        inspectLocked(token, onProgress)
    }

    private fun inspectLocked(token: CancellationToken, progress: (ResourceProgress) -> Unit): ResourceResult {
        token.check()
        val manifest = if (manifestFile.isFile) {
            FileInputStream(manifestFile).use { parseManifest(readBounded(it, MAX_MANIFEST_BYTES, token).toString(Charsets.UTF_8)) }
        } else null
        var count = 0
        var total = 0L
        var verified = manifest != null
        val archives = dataDirectory.listFiles()?.filter { it.isFile && isArchive(it.name) } ?: emptyList()
        if (archives.size > MAX_ENTRIES) throw IOException("Resource directory contains too many archives")
        for (file in archives) { total = checkedTotal(total, file.length()); count++ }
        if (manifest != null && archives.any { file -> manifest.files.none { it.name == file.name } }) verified = false
        manifest?.files?.forEach { entry ->
            token.check()
            progress(ResourceProgress(0, manifest.total, entry.name, "Verifying SHA-256"))
            if (!matches(archiveFile(entry.name), entry, token)) verified = false
        }
        val validation = validate(dataDirectory.absolutePath)
        // Native size/extent validation is necessary, but cannot override a supplied bad hash.
        val result = if (manifest != null && !verified) ResourceValidation(false,
            "Manifest archive SHA-256 verification incomplete or failed. ${validation.details}") else validation
        return ResourceResult(result, verified, count, total)
    }

    private fun receiveRange(
        url: String, entry: Entry, part: File, offset: Long, end: Long,
        token: CancellationToken, progress: (Long) -> Unit
    ) {
        checkSpace(end - offset + 1)
        // Stage each response independently. A wrong/truncated range never advances .part.
        val chunk = File(tempDirectory, "resource-range.tmp")
        try {
            try {
                val opened = try { transport.open(url, offset, end, token) }
                    catch (error: IOException) {
                        token.check()
                        if (error is ResourceProtocolException) throw error
                        throw RetryableNetworkException(error)
                    }
                opened.use { response ->
                    val expected = end - offset + 1
                    if (response.status != 206 || response.contentRange != "bytes $offset-$end/${entry.size}" ||
                        response.length != expected || (response.contentEncoding != null &&
                        !response.contentEncoding.equals("identity", ignoreCase = true))) {
                        throw IOException("Server returned an invalid or encoded byte range for ${entry.name}")
                    }
                    FileOutputStream(chunk, false).use { output ->
                        val networkInput = object : java.io.FilterInputStream(response.input) {
                            override fun read(): Int = try { super.read() } catch (error: IOException) { throw RetryableNetworkException(error) }
                            override fun read(buffer: ByteArray, offset: Int, length: Int): Int =
                                try { super.read(buffer, offset, length) } catch (error: IOException) { throw RetryableNetworkException(error) }
                        }
                        copyExact(networkInput, output, expected, token) { progress(offset + it) }
                        output.fd.sync()
                    }
                }
            } catch (error: CancellationException) { throw error }
            catch (error: IOException) { token.check(); throw error }
            token.check()
            RandomAccessFile(part, "rw").use { output ->
                if (output.length() != offset) throw IOException("Partial file changed during transfer")
                try {
                    output.seek(offset)
                    FileInputStream(chunk).use { input ->
                        val buffer = ByteArray(BUFFER_BYTES)
                        while (true) {
                            token.check()
                            val n = input.read(buffer)
                            if (n < 0) break
                            output.write(buffer, 0, n)
                        }
                    }
                    output.fd.sync()
                } catch (error: Exception) {
                    output.setLength(offset)
                    output.fd.sync()
                    throw error
                }
            }
        } finally { chunk.delete() }
    }

    private data class Document(val uri: Uri, val name: String, val size: Long?)
    private fun discover(tree: Uri, token: CancellationToken): List<Document> {
        if (!DocumentsContract.isTreeUri(tree)) throw IOException("Select a folder using the Android document picker")
        val result = mutableListOf<Document>()
        val pending = ArrayDeque<Pair<String, Int>>()
        pending.add(DocumentsContract.getTreeDocumentId(tree) to 0)
        val seen = mutableSetOf<String>()
        var visited = 0
        while (pending.isNotEmpty()) {
            token.check()
            val (id, depth) = pending.removeFirst()
            if (!seen.add(id)) throw IOException("Document provider returned a folder cycle")
            val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, id)
            val projection = arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME, DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_SIZE)
            val signal = CancellationSignal()
            try {
                token.onCancel { signal.cancel() }.use {
                    val cursor = resolver.query(children, projection, null, null, null, signal)
                        ?: throw IOException("Cannot read selected resource folder")
                    token.onCancel { cursor.close() }.use {
                        cursor.use {
                            while (cursor.moveToNext()) {
                                token.check()
                                if (++visited > MAX_DOCUMENTS) throw IOException("Selected resource tree contains too many documents")
                                val childId = cursor.getString(0) ?: throw IOException("Provider omitted document ID")
                                val name = cursor.getString(1) ?: throw IOException("Provider omitted document name")
                                if (cursor.getString(2) == DocumentsContract.Document.MIME_TYPE_DIR) {
                                    if (depth < MAX_DEPTH) pending.add(childId to depth + 1)
                                } else if (name == "manifest.json" || isArchive(name)) {
                                    if (name != "manifest.json") requireName(name)
                                    result.add(Document(DocumentsContract.buildDocumentUriUsingTree(tree, childId), name,
                                        if (cursor.isNull(3)) null else cursor.getLong(3)))
                                }
                            }
                        }
                    }
                }
            } catch (error: Exception) { token.check(); throw error }
        }
        return result
    }

    private fun <T> withDocumentInput(uri: Uri, token: CancellationToken, action: (InputStream) -> T): T {
        token.check()
        val signal = CancellationSignal()
        try {
            token.onCancel { signal.cancel() }.use {
                // ContentResolver's read-only asset path requests */*. DocumentsProvider's
                // typed fallback drops the CancellationSignal when it calls openAssetFile(r).
                // Whole archive documents use the direct cancellable openFile transport.
                val client = resolver.acquireUnstableContentProviderClient(uri)
                    ?: throw IOException("Cannot connect to selected document provider")
                client.use {
                    val descriptor = client.openFile(uri, "r", signal)
                        ?: throw IOException("Cannot open selected resource document")
                    descriptor.use {
                        val input = ParcelFileDescriptor.AutoCloseInputStream(descriptor)
                        token.onCancel { input.close() }.use {
                            input.use { return action(it) }
                        }
                    }
                }
            }
        } catch (error: Exception) { token.check(); throw error }
    }

    private fun archiveFile(name: String): File {
        requireName(name)
        val file = File(dataDirectory, name)
        if (file.canonicalFile.parentFile != dataDirectory.canonicalFile) throw IOException("Archive escapes resource directory")
        return file
    }

    private fun checkSpace(bytes: Long) {
        if (bytes < 0 || bytes > MAX_TOTAL_BYTES) throw IOException("Invalid transfer size")
        // The range staging file coexists with .part. The reserve also leaves room for app state.
        val needed = Math.addExact(bytes, SPACE_RESERVE)
        if (availableSpace(dataDirectory) < needed) throw IOException("Not enough storage: need $needed additional bytes")
    }

    private fun matches(file: File, entry: Entry, token: CancellationToken): Boolean {
        if (!file.isFile || file.length() != entry.size) return false
        val digest = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).use { input ->
            val buffer = ByteArray(BUFFER_BYTES)
            while (true) {
                token.check()
                val size = input.read(buffer)
                if (size < 0) break
                digest.update(buffer, 0, size)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) } == entry.sha256
    }

    private fun publish(part: File, final: File) {
        // POSIX rename atomically replaces an earlier invalid final without a deletion gap.
        Os.rename(part.absolutePath, final.absolutePath)
        syncDirectory(final.parentFile!!)
    }

    private fun atomicWrite(file: File, bytes: ByteArray) {
        val part = File(file.parentFile, "${file.name}.new")
        FileOutputStream(part, false).use { it.write(bytes); it.fd.sync() }
        publish(part, file)
    }

    private fun <T> exclusive(token: CancellationToken? = null, wait: Boolean = false, action: () -> T): T {
        if (operation.isHeldByCurrentThread) throw IOException("Another resource operation is already running")
        if (wait) {
            // A UI inspection may still be unwinding after cancellation. Transfers wait without
            // overlapping its filesystem I/O; a paused waiting transfer remains cancellable.
            while (!operation.tryLock(100, java.util.concurrent.TimeUnit.MILLISECONDS)) token?.check()
        } else if (!operation.tryLock()) throw IOException("Another resource operation is already running")
        try { token?.check(); return action() } finally { operation.unlock() }
    }

    private class RetryableNetworkException(cause: IOException) : IOException("Network request failed", cause)
    private class ResourceProtocolException(message: String) : IOException(message)

    companion object {
        internal const val CHUNK_BYTES = 16L * 1024 * 1024
        private const val BUFFER_BYTES = 256 * 1024
        private const val MAX_MANIFEST_BYTES = 1024 * 1024
        private const val MAX_ENTRIES = 4096
        private const val MAX_DOCUMENTS = 8192
        private const val MAX_DEPTH = 4
        private const val MAX_FILE_BYTES = 512L * 1024 * 1024 * 1024
        private const val MAX_TOTAL_BYTES = 2L * 1024 * 1024 * 1024 * 1024
        private const val SPACE_RESERVE = 32L * 1024 * 1024
        private const val MAX_NETWORK_ATTEMPTS = 5
        private const val MAX_HASH_ATTEMPTS = 3
        private val operation = ReentrantLock()
        private val fileName = Regex("[A-Za-z0-9][A-Za-z0-9_.-]{0,199}")
        private val sha256 = Regex("[0-9a-fA-F]{64}")

        internal fun parseManifest(text: String): Manifest {
            if (text.toByteArray(Charsets.UTF_8).size > MAX_MANIFEST_BYTES) throw IOException("Manifest is too large")
            try {
                val root = JSONObject(text)
                val files = root.getJSONArray("files")
                if (files.length() !in 1..MAX_ENTRIES) throw IOException("Invalid manifest file count")
                val names = mutableSetOf<String>()
                val entries = mutableListOf<Entry>()
                var total = 0L
                for (index in 0 until files.length()) {
                    val item = files.getJSONObject(index)
                    val name = item.get("name") as? String ?: throw IOException("Invalid archive name")
                    requireName(name)
                    if (!names.add(name.lowercase(Locale.ROOT))) throw IOException("Duplicate manifest archive $name")
                    val number = item.get("size")
                    if (number !is Int && number !is Long) throw IOException("Archive size must be an integer")
                    val size = (number as Number).toLong()
                    if (size !in 0..MAX_FILE_BYTES) throw IOException("Archive size out of bounds")
                    val hash = item.get("sha256") as? String ?: throw IOException("Missing archive SHA-256")
                    if (!sha256.matches(hash)) throw IOException("Invalid archive SHA-256")
                    if (isArchive(name)) {
                        total = checkedTotal(total, size)
                        entries.add(Entry(name, size, hash.lowercase(Locale.ROOT)))
                    }
                }
                if (entries.isEmpty()) throw IOException("Manifest contains no .data or .data.holes archives")
                return Manifest(entries, total, text)
            } catch (error: IOException) { throw error }
            catch (error: Exception) { throw IOException("Invalid resource manifest", error) }
        }

        private fun checkedTotal(total: Long, size: Long): Long {
            if (size !in 0..MAX_FILE_BYTES || total > MAX_TOTAL_BYTES - size) throw IOException("Resource size exceeds supported limit")
            return total + size
        }

        private fun requireName(name: String) {
            if (!fileName.matches(name) || name.contains("..")) throw IOException("Unsafe archive name")
        }

        private fun isArchive(name: String) = name.endsWith(".data") || name.endsWith(".data.holes")

        private fun safeBase(value: String): String {
            val uri = try { URI(value.trim().trimEnd('/')) } catch (error: Exception) { throw IOException("Invalid resource server URL", error) }
            if (uri.scheme != "https" || uri.host.isNullOrEmpty() || uri.rawUserInfo != null || uri.rawQuery != null ||
                uri.rawFragment != null || uri.port !in -1..65535 || uri.rawPath?.contains('%') == true || uri.path.split('/').any { it == ".." }) {
                throw IOException("Resource server must be an HTTPS URL without credentials, query or fragment")
            }
            return uri.toASCIIString()
        }

        private fun readBounded(input: InputStream, limit: Int, token: CancellationToken): ByteArray {
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                token.check()
                val n = input.read(buffer)
                if (n < 0) break
                if (n > limit - output.size()) throw IOException("Resource metadata is too large")
                output.write(buffer, 0, n)
            }
            return output.toByteArray()
        }

        private fun copyExact(input: InputStream, output: FileOutputStream, size: Long, token: CancellationToken, progress: (Long) -> Unit) {
            val buffer = ByteArray(BUFFER_BYTES)
            var copied = 0L
            while (copied < size) {
                token.check()
                val n = input.read(buffer, 0, minOf(buffer.size.toLong(), size - copied).toInt())
                if (n < 0) throw IOException("Resource stream ended before its declared size")
                if (n == 0) continue
                output.write(buffer, 0, n)
                copied += n
                progress(copied)
            }
            token.check()
            if (input.read() != -1) throw IOException("Resource stream exceeds its declared size")
        }

        private fun syncDirectory(directory: File) {
            val fd = Os.open(directory.absolutePath, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC, 0)
            try {
                if (!OsConstants.S_ISDIR(Os.fstat(fd).st_mode)) throw IOException("Resource parent is not a directory")
                Os.fsync(fd)
            } finally { Os.close(fd) }
        }

        private fun cancellableDelay(milliseconds: Long, token: CancellationToken) {
            var remain = milliseconds
            while (remain > 0) {
                token.check()
                val step = minOf(remain, 100L)
                Thread.sleep(step)
                remain -= step
            }
        }

        /** Explicit instrumentation seam. User input still goes through HTTPS-only safeBase. */
        internal fun loopbackTransportForTests(port: Int): Transport {
            require(port in 1..65535)
            return UrlConnectionTransport(port)
        }

        private class UrlConnectionTransport(private val loopbackTestPort: Int? = null) : Transport {
            override fun open(url: String, start: Long?, end: Long?, token: CancellationToken?): Response {
                var current = if (loopbackTestPort != null) {
                    val requested = URI(url)
                    if (requested.scheme != "https" || requested.host != "fixture.invalid") throw IOException("Invalid loopback test URL")
                    "http://127.0.0.1:$loopbackTestPort${requested.rawPath}"
                } else url
                repeat(5) {
                    val uri = URI(current)
                    val loopback = loopbackTestPort != null && uri.scheme == "http" && uri.host == "127.0.0.1" && uri.port == loopbackTestPort
                    if ((uri.scheme != "https" && !loopback) || uri.host.isNullOrEmpty() || uri.rawUserInfo != null) throw ResourceProtocolException("Insecure resource redirect refused")
                    val connection = uri.toURL().openConnection() as HttpURLConnection
                    val cancellation = token?.onCancel { connection.disconnect() }
                    connection.instanceFollowRedirects = false
                    connection.connectTimeout = 15_000
                    connection.readTimeout = 30_000
                    connection.useCaches = false
                    connection.setRequestProperty("Accept-Encoding", "identity")
                    if (start != null && end != null) connection.setRequestProperty("Range", "bytes=$start-$end")
                    try {
                        token?.check()
                        val status = connection.responseCode
                        if (status in listOf(301, 302, 303, 307, 308)) {
                            val location = connection.getHeaderField("Location") ?: throw ResourceProtocolException("Resource redirect omitted destination")
                            current = uri.resolve(location).toASCIIString()
                            cancellation?.close()
                            connection.disconnect()
                        } else {
                            val input = if (status in 200..299) connection.inputStream else connection.errorStream ?: java.io.ByteArrayInputStream(byteArrayOf())
                            return Response(status, connection.getHeaderField("Content-Range"), connection.contentLengthLong,
                                input, connection.getHeaderField("Content-Encoding")) { cancellation?.close(); connection.disconnect() }
                        }
                    } catch (error: Exception) { cancellation?.close(); connection.disconnect(); token?.check(); throw error }
                }
                throw ResourceProtocolException("Too many resource redirects")
            }
        }
    }
}
