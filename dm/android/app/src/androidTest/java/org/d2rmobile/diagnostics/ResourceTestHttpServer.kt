package org.d2rmobile.diagnostics

import org.json.JSONArray
import org.json.JSONObject
import java.io.Closeable
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Local HTTP only through the explicit injected transport; never a resource server default. */
internal class ResourceTestHttpServer(val bytes: ByteArray, val mode: String = "") : Closeable {
    private val server = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
    private val executor = Executors.newCachedThreadPool()
    private val closed = AtomicBoolean(false)
    private val clients = CopyOnWriteArrayList<Socket>()
    val ranges = CopyOnWriteArrayList<String>()
    val rangeStarted = CountDownLatch(1)
    val releaseRange = CountDownLatch(1)
    val port: Int get() = server.localPort
    val manifest: ByteArray = JSONObject().put("files", JSONArray().put(JSONObject()
        .put("name", "one.data").put("size", bytes.size).put("sha256", MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 255) }))).toString().toByteArray()

    init {
        executor.execute {
            while (!closed.get()) {
                try {
                    val client = server.accept()
                    clients.add(client)
                    executor.execute { handle(client) }
                } catch (_: Exception) { if (!closed.get()) throw AssertionError("Fixture server stopped unexpectedly") }
            }
        }
    }

    private fun handle(socket: Socket) {
        try {
            socket.use {
                socket.soTimeout = 10_000
                val reader = socket.getInputStream().bufferedReader(Charsets.US_ASCII)
                val request = reader.readLine() ?: return
                val headers = mutableMapOf<String, String>()
                while (true) {
                    val line = reader.readLine() ?: return
                    if (line.isEmpty()) break
                    headers[line.substringBefore(':').lowercase()] = line.substringAfter(':').trim()
                }
                val path = request.split(' ')[1]
                val output = socket.getOutputStream()
                if (path.endsWith("manifest.json")) {
                    output.write("HTTP/1.1 200 OK\r\nContent-Length: ${manifest.size}\r\nConnection: close\r\n\r\n".toByteArray())
                    output.write(manifest)
                } else {
                    val range = headers["range"] ?: throw AssertionError("Range missing")
                    ranges.add(range)
                    val positions = range.removePrefix("bytes=").split('-').map { it.toInt() }
                    val start = positions[0]
                    val end = positions[1]
                    val body = bytes.copyOfRange(start, end + 1)
                    val response = when (mode) {
                        "redirect" -> "HTTP/1.1 302 Found\r\nLocation: http://example.invalid/unsafe\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        else -> "HTTP/1.1 206 Partial Content\r\nContent-Length: ${body.size}\r\nContent-Range: bytes $start-$end/${bytes.size}\r\n${if (mode == "encoded") "Content-Encoding: gzip\r\n" else ""}Connection: close\r\n\r\n"
                    }
                    output.write(response.toByteArray())
                    output.flush()
                    rangeStarted.countDown()
                    if (mode == "blocked") releaseRange.await(15, TimeUnit.SECONDS)
                    if (mode != "redirect") output.write(body)
                }
                output.flush()
            }
        } catch (_: Exception) { /* Client cancellation deliberately closes its socket. */ }
        finally { clients.remove(socket) }
    }

    override fun close() {
        closed.set(true)
        releaseRange.countDown()
        server.close()
        clients.forEach { try { it.close() } catch (_: Exception) { } }
        executor.shutdownNow()
    }
}
