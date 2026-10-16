package org.d2rmobile.diagnostics

import android.content.Intent
import android.content.pm.ServiceInfo
import android.test.InstrumentationTestCase
import org.json.JSONObject
import org.json.JSONArray
import java.io.ByteArrayInputStream
import java.io.Closeable
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Starts the declared Android service, including framework onCreate/start/onDestroy calls. */
@Suppress("DEPRECATION")
class ResourceTransferServiceTest : InstrumentationTestCase() {
    private lateinit var scratch: File
    private lateinit var activity: MainActivity
    private var journalBackup: ByteArray? = null
    private val context get() = instrumentation.targetContext
    private val journal get() = File(context.filesDir, "resource-transfer.json")

    override fun setUp() {
        super.setUp()
        assertFalse("Tests must not interrupt an existing resource transfer", ResourceTransferService.current.running)
        journalBackup = if (journal.exists()) journal.readBytes() else null
        scratch = File(context.cacheDir, "service-test-${UUID.randomUUID()}").apply { mkdirs() }
        activity = instrumentation.startActivitySync(Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)) as MainActivity
        instrumentation.waitForIdleSync()
    }

    override fun tearDown() {
        instrumentation.runOnMainSync {
            context.stopService(Intent(context, ResourceTransferService::class.java))
        }
        ResourceTransferService.storeFactoryForTests = null
        ResourceTransferService.lifecycleObserverForTests = null
        journalBackup?.let { journal.writeBytes(it) } ?: journal.delete()
        scratch.deleteRecursively()
        instrumentation.runOnMainSync { activity.finish() }
        instrumentation.waitForIdleSync()
        super.tearDown()
    }

    fun testPauseAfterAdditionalStartStopsServiceAndJournalResumes() {
        BlockingTransport("foreground-service-download".toByteArray()).use { server ->
            installStore(server)
            val lifecycle = observe()
            instrumentation.runOnMainSync { ResourceTransferService.startDownload(context, BASE) }
            assertTrue(lifecycle.created.await(5, TimeUnit.SECONDS))
            assertTrue(server.rangeStarted.await(5, TimeUnit.SECONDS))
            instrumentation.runOnMainSync {
                // This new startId must not cause stopSelf(firstStartId) to leave a zombie.
                ResourceTransferService.startDownload(context, "https://ignored.invalid")
                ResourceTransferService.cancel(context)
            }
            assertTrue("Pause terminates the actual service", lifecycle.destroyed.await(5, TimeUnit.SECONDS))
            assertTrue(ResourceTransferService.current.cancelled)
            assertEquals(BASE, JSONObject(journal.readText()).getString("source"))
            assertFalse(File(scratch, "romfs/data/one.data").exists())
            server.releaseRange.countDown()
            val resumed = observe()
            val finished = CountDownLatch(1)
            val listener: (TransferStatus) -> Unit = { if (it.result != null) finished.countDown() }
            ResourceTransferService.addListener(listener)
            try {
                instrumentation.runOnMainSync { ResourceTransferService.resume(context) }
                assertTrue("Journal resumes after the original service was destroyed", finished.await(10, TimeUnit.SECONDS))
                assertTrue(resumed.destroyed.await(5, TimeUnit.SECONDS))
                assertTrue(ResourceTransferService.current.result!!.shaVerified)
                assertFalse(ResourceTransferService.current.result!!.validation.ready)
                assertFalse("Completed transfer clears its journal", journal.exists())
            } finally { ResourceTransferService.removeListener(listener) }
        }
    }

    fun testTimeoutPersistsJobAndOldServiceCannotStopNewGeneration() {
        BlockingTransport("timeout-resource".toByteArray()).use { first ->
            installStore(first)
            val previous = observe()
            instrumentation.runOnMainSync { ResourceTransferService.startDownload(context, BASE) }
            assertTrue(previous.created.await(5, TimeUnit.SECONDS))
            assertTrue(first.rangeStarted.await(5, TimeUnit.SECONDS))
            val old = previous.instance.get()
            instrumentation.runOnMainSync { old.onTimeout(1, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC) }
            assertTrue(previous.destroyed.await(5, TimeUnit.SECONDS))
            assertTrue(ResourceTransferService.current.cancelled)
            assertTrue(ResourceTransferService.current.error!!.contains("time limit"))
            assertTrue(journal.exists())
            BlockingTransport("new-generation-resource".toByteArray()).use { second ->
                installStore(second)
                val next = observe()
                instrumentation.runOnMainSync { ResourceTransferService.resume(context) }
                assertTrue(next.created.await(5, TimeUnit.SECONDS))
                assertTrue(second.rangeStarted.await(5, TimeUnit.SECONDS))
                instrumentation.runOnMainSync { old.onTimeout(1, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC) }
                assertTrue("A stale instance cannot publish timeout state over new work", ResourceTransferService.current.running)
                assertEquals(1L, next.destroyed.count)
                instrumentation.runOnMainSync { ResourceTransferService.cancel(context) }
                assertTrue(next.destroyed.await(5, TimeUnit.SECONDS))
            }
        }
    }

    fun testTimeoutStopsBeforeBlockedProviderCancellationCompletes() {
        val releaseCallback = CountDownLatch(1)
        BlockingTransport("blocked-provider-close".toByteArray(), releaseCallback).use { transport ->
            installStore(transport)
            val lifecycle = observe()
            try {
                instrumentation.runOnMainSync { ResourceTransferService.startDownload(context, BASE) }
                assertTrue(lifecycle.created.await(5, TimeUnit.SECONDS))
                assertTrue(transport.rangeStarted.await(5, TimeUnit.SECONDS))
                instrumentation.runOnMainSync {
                    lifecycle.instance.get().onTimeout(1, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
                }
                assertTrue(transport.cancelStarted.await(5, TimeUnit.SECONDS))
                assertTrue("Slow provider cleanup must not delay timeout destruction", lifecycle.destroyed.await(2, TimeUnit.SECONDS))
                assertEquals("Callback remains blocked until after Android service stops", 1L, releaseCallback.count)
                assertTrue(ResourceTransferService.current.cancelled)
                assertTrue("Cancelled worker cannot delete the resume journal", journal.exists())
                assertFalse(File(scratch, "romfs/data/one.data").exists())
            } finally {
                releaseCallback.countDown()
                assertTrue(transport.cancelCompleted.await(5, TimeUnit.SECONDS))
            }
        }
    }

    private fun installStore(server: BlockingTransport) {
        ResourceTransferService.storeFactoryForTests = { target ->
            ResourceStore(target, { ResourceValidation(false, "Synthetic service fixture; original game absent") },
                server, { Long.MAX_VALUE }, 4, scratch)
        }
    }

    /** Isolates framework service lifecycle from the device's independent network policy. */
    private class BlockingTransport(private val bytes: ByteArray, private val blockedCancellation: CountDownLatch? = null) : ResourceStore.Transport, Closeable {
        val rangeStarted = CountDownLatch(1)
        val releaseRange = CountDownLatch(1)
        val cancelStarted = CountDownLatch(1)
        val cancelCompleted = CountDownLatch(1)
        private val manifest = JSONObject().put("files", JSONArray().put(JSONObject()
            .put("name", "one.data").put("size", bytes.size).put("sha256", MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it.toInt() and 255) }))).toString().toByteArray()

        override fun open(url: String, start: Long?, end: Long?, token: CancellationToken?): ResourceStore.Response {
            if (url.endsWith("manifest.json")) return ResourceStore.Response(200, null, manifest.size.toLong(), ByteArrayInputStream(manifest))
            val first = requireNotNull(start)
            val last = requireNotNull(end)
            rangeStarted.countDown()
            token?.onCancel {
                cancelStarted.countDown()
                try { blockedCancellation?.await(10, TimeUnit.SECONDS) }
                finally { releaseRange.countDown(); cancelCompleted.countDown() }
            }.use {
                if (!releaseRange.await(10, TimeUnit.SECONDS)) throw AssertionError("Service did not cancel blocked transport")
                token?.check()
            }
            val body = bytes.copyOfRange(first.toInt(), last.toInt() + 1)
            return ResourceStore.Response(206, "bytes $first-$last/${bytes.size}", body.size.toLong(), ByteArrayInputStream(body))
        }

        override fun close() { releaseRange.countDown() }
    }

    private class Lifecycle {
        val created = CountDownLatch(1)
        val destroyed = CountDownLatch(1)
        val instance = AtomicReference<ResourceTransferService>()
    }

    private fun observe(): Lifecycle = Lifecycle().also { state ->
        ResourceTransferService.lifecycleObserverForTests = { service, created ->
            if (created) { state.instance.set(service); state.created.countDown() } else state.destroyed.countDown()
        }
    }

    companion object { private const val BASE = "https://fixture.invalid/resources" }
}
