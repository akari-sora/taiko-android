package org.d2rmobile.diagnostics

import android.content.Context
import android.net.Uri
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.os.StatFs
import android.provider.DocumentsContract
import android.system.Os
import android.system.OsConstants
import org.json.JSONObject
import org.json.JSONTokener
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID
import java.util.concurrent.locks.ReentrantLock

/** Transfer integrity is separate from the compiled native loader's execution authority. */
data class TaikoContentResult(
    val integrityVerified: Boolean,
    val modulesVerified: Boolean,
    val files: Int,
    val bytes: Long,
    val manifestSha256: String?,
    val details: String
) {
    val contentReady: Boolean get() = integrityVerified
    val nativeStartupAdmitted: Boolean get() = false
}

/** A complete, locally supplied Taiko content tree; save data never participates in replacement. */
class TaikoContentStore(context: Context) {
    private val resolver = context.contentResolver
    val rootDirectory = File(context.filesDir, "taiko")
    val contentDirectory = File(rootDirectory, "content")
    val moduleDirectory = File(contentDirectory, "modules")
    val romfsDirectory = File(contentDirectory, "RomFS")
    val saveDirectory = File(rootDirectory, "save")
    val tempDirectory = File(rootDirectory, "temp")
    private val previousDirectory = File(rootDirectory, "content.previous")

    init { listOf(rootDirectory, saveDirectory, tempDirectory).forEach(::ensureDirectory) }

    fun inspect(token: CancellationToken = CancellationToken()): TaikoContentResult = exclusive(token) {
        recoverPublication(token)
        if (!contentDirectory.exists()) return@exclusive unavailable("No Taiko content has been imported")
        try {
            val sources = directorySources(contentDirectory, token)
            val raw = readManifest(sources, token)
            val manifest = parseManifest(raw)
            requireInventory(sources, manifest)
            var total = 0L
            for (entry in manifest.entries) {
                token.check()
                readEntry(sources.getValue(entry.path), entry, token, null) { }
                total += entry.bytes
            }
            TaikoContentResult(true, true, manifest.entries.size, total, sha256(raw),
                "Taiko content hashes verified. Native startup has not been admitted or run.")
        } catch (error: IOException) {
            unavailable(error.message ?: "Taiko content verification failed")
        }
    }

    /** Import the selected tree itself. The manifest must be at its root. */
    fun importTree(
        tree: Uri, token: CancellationToken = CancellationToken(),
        onProgress: (ResourceProgress) -> Unit = {}
    ): TaikoContentResult = exclusive(token) {
        install(documentSources(tree, token), token, onProgress)
    }

    /** Also supports app-private CLI staging without bypassing any manifest or hash check. */
    fun importDirectory(
        directory: File, token: CancellationToken = CancellationToken(),
        onProgress: (ResourceProgress) -> Unit = {}
    ): TaikoContentResult = exclusive(token) {
        install(directorySources(directory, token), token, onProgress)
    }

    /** Pins the installed tree through native verification and the entire guest call.
     * The native entry independently validates compiled pins while this lock is held. */
    internal fun withNativeContent(action: () -> String): String = exclusive(CancellationToken(), action)

    private data class Entry(val path: String, val bytes: Long, val sha256: String)
    private data class Manifest(val entries: List<Entry>, val total: Long)
    private interface Source {
        val bytes: Long?
        fun <T> read(token: CancellationToken, action: (InputStream) -> T): T
    }

    private fun install(sources: Map<String, Source>, token: CancellationToken, progress: (ResourceProgress) -> Unit): TaikoContentResult {
        recoverPublication(token)
        val raw = readManifest(sources, token)
        val manifest = parseManifest(raw)
        requireInventory(sources, manifest)
        val reserve = 32L * 1024 * 1024
        if (StatFs(rootDirectory.absolutePath).availableBytes < manifest.total + raw.size + reserve)
            throw IOException("Not enough storage for a complete Taiko content replacement")
        val staging = File(tempDirectory, "content-${UUID.randomUUID()}")
        ensureDirectory(staging)
        var completed = 0L
        try {
            for (entry in manifest.entries) {
                token.check()
                val target = File(staging, entry.path)
                ensureParents(staging, target.parentFile!!)
                FileOutputStream(target).use { output ->
                    readEntry(sources.getValue(entry.path), entry, token, output) { count ->
                        progress(ResourceProgress(completed + count, manifest.total, entry.path, "Importing and verifying Taiko content"))
                    }
                    output.fd.sync()
                }
                completed += entry.bytes
            }
            FileOutputStream(File(staging, MANIFEST)).use { it.write(raw); it.fd.sync() }
            syncTreeDirectories(staging)
            token.check()
            // Cancellation before this point leaves the installed tree untouched. Publication
            // is a short, non-cancellable rename transaction with rollback on an I/O failure.
            if (contentDirectory.exists()) Os.rename(contentDirectory.absolutePath, previousDirectory.absolutePath)
            try {
                Os.rename(staging.absolutePath, contentDirectory.absolutePath)
                syncDirectory(rootDirectory)
            } catch (error: Exception) {
                try {
                    if (contentDirectory.exists()) Os.rename(contentDirectory.absolutePath, staging.absolutePath)
                    if (previousDirectory.exists()) Os.rename(previousDirectory.absolutePath, contentDirectory.absolutePath)
                    syncDirectory(rootDirectory)
                } catch (rollback: Exception) { error.addSuppressed(rollback) }
                throw IOException("Cannot publish verified Taiko content", error)
            }
            // A retained backup is recoverable housekeeping, never a failed content import.
            try { if (previousDirectory.exists()) removeTree(previousDirectory); syncDirectory(rootDirectory) } catch (_: IOException) { }
            return TaikoContentResult(true, true, manifest.entries.size, completed, sha256(raw),
                "Taiko content hashes verified. Native startup has not been admitted or run.")
        } catch (error: android.system.ErrnoException) {
            throw IOException("Taiko content filesystem operation failed", error)
        } finally {
            if (staging.exists()) removeTree(staging)
        }
    }

    private fun readManifest(sources: Map<String, Source>, token: CancellationToken): ByteArray {
        val source = sources[MANIFEST] ?: throw IOException("Select the folder containing $MANIFEST")
        if (source.bytes != null && source.bytes!! > MAX_MANIFEST_BYTES) throw IOException("Taiko manifest is too large")
        return try { source.read(token) { input ->
            val result = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(BUFFER_BYTES)
            while (true) {
                token.check()
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) throw IOException("Manifest provider made no progress")
                if (count > MAX_MANIFEST_BYTES - result.size()) throw IOException("Taiko manifest is too large")
                result.write(buffer, 0, count)
            }
            result.toByteArray()
        } } catch (error: IOException) { token.check(); throw error }
    }

    private fun parseManifest(raw: ByteArray): Manifest {
        try {
            val decoder = Charsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
            val parser = JSONTokener(decoder.decode(java.nio.ByteBuffer.wrap(raw)).toString())
            val json = parser.nextValue() as? JSONObject ?: throw IOException("Taiko manifest must be a JSON object")
            if (parser.nextClean() != '\u0000') throw IOException("Trailing data after Taiko manifest")
            if (integer(json, "schema") != 1L || string(json, "target") != "taiko-android" ||
                string(json, "program_id") != "01002460135A4000" ||
                json.has("selected_exefs_display_version") && !json.isNull("selected_exefs_display_version"))
                throw IOException("Manifest does not identify the supported Taiko source")
            val order = json.getJSONArray("module_order")
            if (order.length() != MODULES.size || MODULES.indices.any { order.get(it) != MODULES[it] })
                throw IOException("Taiko module order must be main, subsdk0, sdk")
            val sources = json.getJSONArray("sources")
            if (sources.length() != SOURCE_PINS.size) throw IOException("Missing exact Taiko source identities")
            val seen = mutableSetOf<String>()
            for (index in 0 until sources.length()) {
                val item = sources.getJSONObject(index)
                val name = string(item, "name")
                val pin = SOURCE_PINS[name] ?: throw IOException("Unsupported Taiko source $name")
                if (!seen.add(name) || integer(item, "bytes") != pin.bytes || string(item, "sha256") != pin.sha256 ||
                    if (pin.buildId == null) item.has("build_id") && !item.isNull("build_id") else string(item, "build_id") != pin.buildId)
                    throw IOException("Taiko source identity mismatch for $name")
            }
            val entries = mutableListOf<Entry>()
            val paths = mutableSetOf<String>()
            val prefixes = mutableMapOf<String, String>()
            var total = 0L
            fun add(item: JSONObject, expectedPath: String? = null): Entry {
                val path = string(item, "path")
                safePath(path)
                if (expectedPath != null && path != expectedPath) throw IOException("Unexpected Taiko package or receipt path")
                val folded = foldPath(path)
                if (!paths.add(folded) || prefixes.containsKey(folded)) throw IOException("Duplicate or colliding Taiko content path")
                var prefix = ""
                path.split('/').dropLast(1).forEach { component ->
                    prefix = if (prefix.isEmpty()) component else "$prefix/$component"
                    val key = foldPath(prefix)
                    if (paths.contains(key)) throw IOException("File/directory collision in Taiko manifest")
                    if (prefixes.putIfAbsent(key, prefix)?.let { it != prefix } == true)
                        throw IOException("Directory case collision in Taiko manifest")
                }
                val bytes = integer(item, "bytes")
                val hash = string(item, "sha256")
                if (bytes !in 0..MAX_FILE_BYTES || !HASH.matches(hash) || total > MAX_TOTAL_BYTES - bytes)
                    throw IOException("Invalid Taiko content size or SHA-256")
                total += bytes
                return Entry(path, bytes, hash.lowercase(Locale.ROOT)).also { entries.add(it) }
            }
            val packages = json.getJSONArray("packages")
            if (packages.length() != MODULES.size) throw IOException("Three Taiko module packages are required")
            MODULES.forEachIndexed { index, name ->
                val item = packages.getJSONObject(index)
                if (string(item, "name") != name || string(item, "source_sha256") != SOURCE_PINS.getValue(name).sha256)
                    throw IOException("Taiko package source or order mismatch")
                if (add(item, "modules/$name.dmag").bytes == 0L) throw IOException("Empty Taiko module package")
            }
            if (add(json.getJSONObject("import_receipt"), "import.json").bytes == 0L) throw IOException("Empty Taiko import receipt")
            val files = json.getJSONArray("files")
            if (files.length() !in 1..MAX_FILES) throw IOException("Invalid Taiko resource file count")
            for (index in 0 until files.length()) {
                val item = files.getJSONObject(index)
                if (!string(item, "path").startsWith("RomFS/")) throw IOException("Resource path must be inside RomFS")
                add(item)
            }
            if (json.has("total_bytes") && integer(json, "total_bytes") != total) throw IOException("Taiko total byte count mismatch")
            return Manifest(entries, total)
        } catch (error: IOException) { throw error }
        catch (error: Exception) { throw IOException("Invalid Taiko content manifest", error) }
    }

    private fun requireInventory(sources: Map<String, Source>, manifest: Manifest) {
        if (sources.keys != (manifest.entries.map { it.path } + MANIFEST).toSet())
            throw IOException("Taiko tree contains missing, extra, or differently cased files")
        manifest.entries.forEach { entry ->
            val size = sources.getValue(entry.path).bytes
            if (size != null && size != entry.bytes) throw IOException("Size mismatch for ${entry.path}")
        }
    }

    private fun readEntry(source: Source, entry: Entry, token: CancellationToken, output: FileOutputStream?, progress: (Long) -> Unit) {
        val digest = MessageDigest.getInstance("SHA-256")
        try { source.read(token) { input ->
            val buffer = ByteArray(BUFFER_BYTES)
            var copied = 0L
            while (copied < entry.bytes) {
                token.check()
                val count = input.read(buffer, 0, minOf(buffer.size.toLong(), entry.bytes - copied).toInt())
                if (count <= 0) throw IOException("Truncated or stalled Taiko file ${entry.path}")
                digest.update(buffer, 0, count)
                output?.write(buffer, 0, count)
                copied += count
                progress(copied)
            }
            token.check()
            if (input.read() != -1) throw IOException("Taiko file exceeds declared size: ${entry.path}")
        } } catch (error: IOException) { token.check(); throw error }
        if (hex(digest.digest()) != entry.sha256) throw IOException("SHA-256 mismatch for ${entry.path}")
    }

    private fun directorySources(directory: File, token: CancellationToken): Map<String, Source> {
        requireRegularDirectory(directory)
        val root = directory.canonicalFile
        val found = linkedMapOf<String, Source>()
        val paths = mutableSetOf<String>()
        var documents = 0
        fun visit(folder: File, prefix: String, depth: Int) {
            token.check()
            if (depth > MAX_DEPTH) throw IOException("Taiko tree exceeds directory depth limit")
            val children = folder.listFiles() ?: throw IOException("Cannot read Taiko content directory")
            for (file in children) {
                token.check()
                if (++documents > MAX_DOCUMENTS) throw IOException("Taiko tree contains too many entries")
                val path = if (prefix.isEmpty()) file.name else "$prefix/${file.name}"
                safePath(path)
                if (!paths.add(foldPath(path))) throw IOException("Case-colliding Taiko source paths")
                if (!file.canonicalPath.startsWith(root.path + File.separator)) throw IOException("Taiko source escapes selected directory")
                val st = try { Os.lstat(file.absolutePath) } catch (error: Exception) { throw IOException("Cannot inspect Taiko source", error) }
                if (OsConstants.S_ISDIR(st.st_mode)) visit(file, path, depth + 1)
                else if (OsConstants.S_ISREG(st.st_mode)) {
                    found[path] = object : Source {
                        override val bytes = st.st_size
                        override fun <T> read(token: CancellationToken, action: (InputStream) -> T): T {
                            token.check()
                            FileInputStream(file).use { input -> token.onCancel { input.close() }.use { return action(input) } }
                        }
                    }
                } else throw IOException("Taiko source contains a symlink or unsupported file")
            }
        }
        visit(directory, "", 0)
        return found
    }

    private fun documentSources(tree: Uri, token: CancellationToken): Map<String, Source> {
        if (!DocumentsContract.isTreeUri(tree)) throw IOException("Select a Taiko content folder")
        val found = linkedMapOf<String, Source>()
        val seen = mutableSetOf<String>()
        val paths = mutableSetOf<String>()
        var documents = 0
        val projection = arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE, DocumentsContract.Document.COLUMN_SIZE)
        fun visit(id: String, prefix: String, depth: Int) {
            token.check()
            if (depth > MAX_DEPTH || !seen.add(id)) throw IOException("Taiko document tree contains a cycle or exceeds depth limit")
            val signal = CancellationSignal()
            try {
                token.onCancel { signal.cancel() }.use {
                    val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, id)
                    val cursor = resolver.query(children, projection, null, null, null, signal)
                        ?: throw IOException("Cannot read selected Taiko folder")
                    cursor.use {
                        token.onCancel { cursor.close() }.use {
                            while (cursor.moveToNext()) {
                                token.check()
                                if (++documents > MAX_DOCUMENTS) throw IOException("Taiko document tree contains too many entries")
                                val child = cursor.getString(0) ?: throw IOException("Provider omitted document ID")
                                val name = cursor.getString(1) ?: throw IOException("Provider omitted file name")
                                safeSegment(name)
                                val path = if (prefix.isEmpty()) name else "$prefix/$name"
                                safePath(path)
                                if (!paths.add(foldPath(path))) throw IOException("Duplicate Taiko provider path")
                                if (cursor.getString(2) == DocumentsContract.Document.MIME_TYPE_DIR) visit(child, path, depth + 1)
                                else {
                                    if (!seen.add(child)) throw IOException("Provider returned duplicate Taiko document ID")
                                    val length = if (cursor.isNull(3)) null else cursor.getLong(3)
                                    if (length != null && length !in 0..MAX_FILE_BYTES) throw IOException("Invalid provider file size")
                                    val uri = DocumentsContract.buildDocumentUriUsingTree(tree, child)
                                    found[path] = documentSource(uri, length)
                                }
                            }
                        }
                    }
                }
            } catch (error: Exception) { token.check(); if (error is IOException) throw error; throw IOException("Cannot read Taiko document tree", error) }
        }
        visit(DocumentsContract.getTreeDocumentId(tree), "", 0)
        return found
    }

    private fun documentSource(uri: Uri, length: Long?) = object : Source {
        override val bytes = length
        override fun <T> read(token: CancellationToken, action: (InputStream) -> T): T {
            token.check()
            val signal = CancellationSignal()
            try {
                token.onCancel { signal.cancel() }.use {
                    val client = resolver.acquireUnstableContentProviderClient(uri) ?: throw IOException("Cannot connect to Taiko document provider")
                    client.use {
                        val descriptor = client.openFile(uri, "r", signal) ?: throw IOException("Cannot open Taiko content file")
                        descriptor.use {
                            ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { input ->
                                token.onCancel { input.close() }.use { return action(input) }
                            }
                        }
                    }
                }
            } catch (error: Exception) { token.check(); if (error is IOException) throw error; throw IOException("Cannot read Taiko document", error) }
        }
    }

    private fun recoverPublication(token: CancellationToken) {
        try {
            if (previousDirectory.exists()) {
                requireRegularDirectory(previousDirectory)
                if (!contentDirectory.exists()) {
                    Os.rename(previousDirectory.absolutePath, contentDirectory.absolutePath)
                    syncDirectory(rootDirectory)
                } else removeTree(previousDirectory)
            }
            if (contentDirectory.exists()) requireRegularDirectory(contentDirectory)
            recoverAbandonedStages(token)
        } catch (error: android.system.ErrnoException) { throw IOException("Cannot recover Taiko content publication", error) }
    }

    private fun recoverAbandonedStages(token: CancellationToken) {
        requireRegularDirectory(tempDirectory)
        val candidates = tempDirectory.listFiles() ?: throw IOException("Cannot inspect Taiko temporary directory")
        for (candidate in candidates) {
            token.check()
            if (!STAGING_NAME.matches(candidate.name)) continue
            var visited = 0
            fun safeTree(file: File, depth: Int): Boolean {
                token.check()
                if (++visited > MAX_DOCUMENTS || depth > MAX_DEPTH + 1) return false
                val stat = try { Os.lstat(file.absolutePath) } catch (_: android.system.ErrnoException) { return false }
                if (OsConstants.S_ISREG(stat.st_mode)) return true
                if (!OsConstants.S_ISDIR(stat.st_mode) || depth > MAX_DEPTH) return false
                val children = file.listFiles() ?: return false
                return children.all { safeTree(it, depth + 1) }
            }
            // Only the store's canonical UUIDv4 directory names are ours to recover.
            // Validate the entire candidate before deleting anything; unknown entries,
            // links and special files preserve their containing candidate untouched.
            val stat = try { Os.lstat(candidate.absolutePath) } catch (_: android.system.ErrnoException) { continue }
            if (!OsConstants.S_ISDIR(stat.st_mode) || !safeTree(candidate, 0)) continue
            removeTree(candidate)
        }
        syncDirectory(tempDirectory)
    }

    private fun <T> exclusive(token: CancellationToken, action: () -> T): T {
        if (operation.isHeldByCurrentThread) throw IOException("A Taiko content operation is already running")
        token.check()
        requireNativeContentReleased()
        while (!operation.tryLock(100, java.util.concurrent.TimeUnit.MILLISECONDS)) {
            token.check()
            requireNativeContentReleased()
        }
        try {
            token.check()
            requireNativeContentReleased()
            return action()
        } finally { operation.unlock() }
    }

    private fun requireNativeContentReleased() {
        if (NativeOriginal.contentInUse()) throw IOException("Native runtime is using Taiko content; wait for complete cleanup before importing or inspecting")
    }

    private fun unavailable(details: String) = TaikoContentResult(false, false, 0, 0, null, details)

    companion object {
        private const val MANIFEST = "taiko-content.json"
        private const val MAX_MANIFEST_BYTES = 64 * 1024 * 1024
        private const val BUFFER_BYTES = 256 * 1024
        private const val MAX_FILES = 200_000
        private const val MAX_DOCUMENTS = 400_000
        private const val MAX_DEPTH = 64
        private const val MAX_FILE_BYTES = 512L * 1024 * 1024 * 1024
        private const val MAX_TOTAL_BYTES = 2L * 1024 * 1024 * 1024 * 1024
        private val MODULES = listOf("main", "subsdk0", "sdk")
        private val HASH = Regex("[0-9a-fA-F]{64}")
        private val STAGING_NAME = Regex("content-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
        private val operation = ReentrantLock()
        private data class SourcePin(val bytes: Long, val sha256: String, val buildId: String? = null)
        private val SOURCE_PINS = mapOf(
            "rtld" to SourcePin(7132, "8e08c8cf2e4d6b39d69643af10ce765d39c06860878224c68f8cafc45a2636aa", "567cdd4c5251494c5cd70822e3ccc740c190c2b2000000000000000000000000"),
            "main" to SourcePin(38127530, "f1313fe0d6cd4a024e53d8a283434448bacea453b02f37b75b18bfe281d0fcff", "4541b79257635ce79105b3ba59e4808500000000000000000000000000000000"),
            "subsdk0" to SourcePin(3385425, "f38d30e8241ee208cbf3090f44613e328af517ad199eb5985619416bb2cbcb55", "a8cb97803f7f442a3b6cce1c7cd4ee4a78b7def3000000000000000000000000"),
            "sdk" to SourcePin(5989236, "2a89fa1c0e677710e89ed29b578162affef530a0c9b8c93cda15d50a57a20d28", "357efc198e728cb5d55265aff304f03cfc9cc0e3000000000000000000000000"),
            "main.npdm" to SourcePin(1572, "afd3aade95cbcc607759eb677b67082193719a701a5b0cc8ed78ac33b5c65150"))

        private fun string(json: JSONObject, key: String) = json.get(key) as? String ?: throw IOException("Invalid manifest string: $key")
        private fun integer(json: JSONObject, key: String): Long {
            val value = json.get(key)
            if (value !is Int && value !is Long) throw IOException("Manifest $key must be an integer")
            return (value as Number).toLong()
        }
        private fun safeSegment(name: String) {
            if (name.isEmpty() || name == "." || name == ".." || name.toByteArray(Charsets.UTF_8).size > 255 ||
                name.any { it == '/' || it == '\\' || it == ':' || it.code < 32 || it.code == 127 })
                throw IOException("Unsafe Taiko content path component")
        }
        private fun safePath(path: String) {
            if (path.toByteArray(Charsets.UTF_8).size > 4096) throw IOException("Taiko content path is too long")
            path.split('/').forEach(::safeSegment)
        }
        // Expanding case changes (for example sharp-s and ligatures) also collide.
        private fun foldPath(path: String) = path.uppercase(Locale.ROOT).lowercase(Locale.ROOT)
        private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
        private fun sha256(bytes: ByteArray) = hex(MessageDigest.getInstance("SHA-256").digest(bytes))
        private fun requireRegularDirectory(directory: File) {
            val st = try { Os.lstat(directory.absolutePath) } catch (error: Exception) { throw IOException("Cannot inspect Taiko directory", error) }
            if (!OsConstants.S_ISDIR(st.st_mode)) throw IOException("Taiko directory is a symlink or unsupported entry")
        }
        private fun ensureDirectory(directory: File) {
            if (!directory.exists() && !directory.mkdirs() && !directory.isDirectory) throw IOException("Cannot create Taiko directory")
            requireRegularDirectory(directory)
        }
        private fun ensureParents(root: File, directory: File) {
            if (directory == root) return
            ensureParents(root, directory.parentFile ?: throw IOException("Invalid destination parent"))
            ensureDirectory(directory)
        }
        private fun syncDirectory(directory: File) {
            try {
                val fd = Os.open(directory.absolutePath, OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW, 0)
                try {
                    if (!OsConstants.S_ISDIR(Os.fstat(fd).st_mode)) throw IOException("Taiko fsync target is not a directory")
                    Os.fsync(fd)
                } finally { Os.close(fd) }
            } catch (error: android.system.ErrnoException) { throw IOException("Cannot sync Taiko directory", error) }
        }
        private fun syncTreeDirectories(directory: File) {
            directory.listFiles()?.filter { it.isDirectory }?.forEach(::syncTreeDirectories)
            syncDirectory(directory)
        }
        private fun removeTree(file: File) {
            val st = try { Os.lstat(file.absolutePath) } catch (error: Exception) { throw IOException("Cannot inspect temporary Taiko entry", error) }
            if (OsConstants.S_ISDIR(st.st_mode)) {
                val children = file.listFiles() ?: throw IOException("Cannot read temporary Taiko directory")
                children.forEach(::removeTree)
            }
            if (!file.delete()) throw IOException("Cannot remove temporary Taiko entry")
        }
    }
}
