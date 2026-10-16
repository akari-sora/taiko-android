package org.d2rmobile.diagnostics

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.AtomicFile
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.util.concurrent.CancellationException
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.Executors

data class TransferStatus(
    val running: Boolean = false,
    val progress: ResourceProgress? = null,
    val result: ResourceResult? = null,
    val error: String? = null,
    val cancelled: Boolean = false
)

/** A user-started dataSync foreground service. Android time limits leave a resumable job. */
class ResourceTransferService : Service() {
    private val executor = Executors.newSingleThreadExecutor()
    private var token: CancellationToken? = null
    private var lastNotification = 0L
    private lateinit var jobs: AtomicFile
    @Volatile private var timedOut = false
    private var generation = 0L
    private var destroyed = false

    override fun onCreate() {
        super.onCreate()
        synchronized(lifecycle) { generation = ++nextGeneration; activeGeneration = generation }
        jobs = AtomicFile(File(filesDir, JOB_FILE))
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, "Game resource transfer", NotificationManager.IMPORTANCE_LOW)
        )
        lifecycleObserverForTests?.invoke(this, true)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_CANCEL) {
            withCurrentGeneration {
                token?.cancelAsync()
                if (token == null) { publish(TransferStatus(cancelled = true)); stopSelf() }
            }
            return START_NOT_STICKY
        }
        // Foreground promotion precedes metadata/network operations and therefore meets the
        // startForegroundService deadline even when the provider or network stalls.
        startForeground(NOTIFICATION, notification("Preparing resource transfer", null), ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        if (token != null) return START_STICKY
        val requested = try {
            when (intent?.action) {
                ACTION_DOWNLOAD -> Job("download", intent.getStringExtra(EXTRA_SOURCE) ?: throw IOException("Missing resource server URL"))
                ACTION_IMPORT -> Job("import", intent.getStringExtra(EXTRA_SOURCE) ?: throw IOException("Missing selected resource folder"))
                else -> readJob() ?: throw IOException("No paused resource transfer to resume")
            }
        } catch (error: Exception) {
            finish(TransferStatus(error = error.message ?: "Cannot read resource transfer"))
            return START_NOT_STICKY
        }
        try { writeJob(requested) }
        catch (error: Exception) {
            finish(TransferStatus(error = "Cannot persist transfer: ${error.message}"))
            return START_NOT_STICKY
        }
        timedOut = false
        val cancellation = CancellationToken()
        token = cancellation
        publish(TransferStatus(running = true))
        executor.execute {
            val outcome = try {
                val store = storeFactoryForTests?.invoke(applicationContext)
                    ?: ResourceStore(applicationContext, NativeResources::validate)
                val update: (ResourceProgress) -> Unit = { progress ->
                    withCurrentGeneration {
                        publish(TransferStatus(running = true, progress = progress))
                        val now = android.os.SystemClock.elapsedRealtime()
                        if (now - lastNotification >= 1000) {
                            lastNotification = now
                            getSystemService(NotificationManager::class.java).notify(NOTIFICATION,
                                notification("${progress.note}: ${progress.file}", progress))
                        }
                    }
                }
                val result = when (requested.kind) {
                    "download" -> store.download(requested.source, cancellation, update)
                    "import" -> store.importTree(Uri.parse(requested.source), cancellation, update)
                    else -> throw IOException("Invalid persisted transfer operation")
                }
                cancellation.check()
                withCurrentGeneration { cancellation.check(); jobs.delete() }
                TransferStatus(result = result)
            } catch (error: CancellationException) {
                TransferStatus(error = if (timedOut) "Android background transfer time limit reached. Resume to continue." else null, cancelled = true)
            } catch (error: Exception) {
                TransferStatus(error = error.message ?: "Resource transfer failed")
            }
            main.post { withCurrentGeneration { token = null; finish(outcome) } }
        }
        return START_STICKY
    }

    override fun onTimeout(startId: Int, fgsType: Int) {
        withCurrentGeneration {
            timedOut = true
            // Set the flag while holding the same lock as journal deletion. Slow provider
            // disconnect callbacks run off main and cannot delay Android's timeout deadline.
            token?.cancelAsync()
            publish(TransferStatus(error = "Android background transfer time limit reached. Resume to continue.", cancelled = true))
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onDestroy() {
        synchronized(lifecycle) {
            if (!destroyed && activeGeneration == generation && current.running) publish(TransferStatus(cancelled = true))
            destroyed = true
            token?.cancelAsync()
        }
        executor.shutdown()
        lifecycleObserverForTests?.invoke(this, false)
        super.onDestroy()
    }

    private fun finish(status: TransferStatus) = withCurrentGeneration {
        publish(status)
        stopForeground(STOP_FOREGROUND_REMOVE)
        // No queued operation is accepted while one is running. A later pause intent may have
        // a newer startId, so stopping only the first startId would leak this service.
        stopSelf()
    }

    private fun withCurrentGeneration(action: () -> Unit) = synchronized(lifecycle) {
        if (!destroyed && activeGeneration == generation) action()
    }

    private fun notification(message: String, progress: ResourceProgress?): Notification {
        val cancelIntent = PendingIntent.getService(this, 1,
            Intent(this, ResourceTransferService::class.java).setAction(ACTION_CANCEL),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val open = PendingIntent.getActivity(this, 2, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val builder = Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentTitle("D2R Mobile resources")
            .setContentText(message)
            .setContentIntent(open)
            .setOnlyAlertOnce(true)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Pause", cancelIntent).build())
        if (progress != null && progress.total > 0) builder.setProgress(1000,
            ((progress.done.toDouble() / progress.total) * 1000).toInt().coerceIn(0, 1000), false)
        else builder.setProgress(0, 0, true)
        return builder.build()
    }

    private data class Job(val kind: String, val source: String)

    private fun readJob(): Job? {
        // AtomicFile.openRead also recovers an interrupted write's backup when base is absent.
        val input = try { jobs.openRead() } catch (_: java.io.FileNotFoundException) { return null }
        val bytes = input.use {
            val bytes = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(1024)
            while (true) {
                val size = it.read(buffer)
                if (size < 0) break
                if (bytes.size() + size > 16 * 1024) throw IOException("Persisted transfer is too large")
                bytes.write(buffer, 0, size)
            }
            bytes.toByteArray()
        }
        val json = JSONObject(bytes.toString(Charsets.UTF_8))
        return Job(json.getString("kind"), json.getString("source"))
    }

    private fun writeJob(job: Job) {
        val json = JSONObject().put("kind", job.kind).put("source", job.source)
            .put("schema", 1).toString().toByteArray(Charsets.UTF_8)
        if (json.size > 16 * 1024) throw IOException("Resource transfer location is too long")
        val output = jobs.startWrite()
        try { output.write(json); jobs.finishWrite(output) }
        catch (error: Exception) { jobs.failWrite(output); throw error }
    }

    companion object {
        private const val CHANNEL = "resource-transfer"
        private const val NOTIFICATION = 2001
        private const val JOB_FILE = "resource-transfer.json"
        private const val ACTION_DOWNLOAD = "org.d2rmobile.resources.DOWNLOAD"
        private const val ACTION_IMPORT = "org.d2rmobile.resources.IMPORT"
        private const val ACTION_CANCEL = "org.d2rmobile.resources.CANCEL"
        private const val ACTION_RESUME = "org.d2rmobile.resources.RESUME"
        private const val EXTRA_SOURCE = "source"
        private val main = Handler(Looper.getMainLooper())
        private val lifecycle = Any()
        private var nextGeneration = 0L
        private var activeGeneration = 0L
        // Package-internal instrumentation injection; production always constructs the real
        // store/native validator. Tests reset both hooks and use isolated fixture directories.
        @Volatile internal var storeFactoryForTests: ((Context) -> ResourceStore)? = null
        @Volatile internal var lifecycleObserverForTests: ((ResourceTransferService, Boolean) -> Unit)? = null
        private val listeners = CopyOnWriteArraySet<(TransferStatus) -> Unit>()
        @Volatile var current = TransferStatus()
            private set

        fun addListener(listener: (TransferStatus) -> Unit) { listeners.add(listener); main.post { listener(current) } }
        fun removeListener(listener: (TransferStatus) -> Unit) { listeners.remove(listener) }

        fun startDownload(context: Context, baseUrl: String) = start(context, ACTION_DOWNLOAD, baseUrl)
        fun startImport(context: Context, treeUri: Uri) = start(context, ACTION_IMPORT, treeUri.toString())
        fun resume(context: Context) = start(context, ACTION_RESUME, null)
        fun cancel(context: Context) {
            context.startService(Intent(context, ResourceTransferService::class.java).setAction(ACTION_CANCEL))
        }

        private fun start(context: Context, action: String, source: String?) {
            val intent = Intent(context, ResourceTransferService::class.java).setAction(action)
            if (source != null) intent.putExtra(EXTRA_SOURCE, source)
            // Expose pending work before returning to Activity.onStart (e.g. from the picker).
            publish(TransferStatus(running = true))
            try { context.startForegroundService(intent) }
            catch (error: Exception) {
                publish(TransferStatus(error = error.message ?: "Android could not start resource transfer"))
                throw error
            }
        }

        private fun publish(status: TransferStatus) {
            current = status
            main.post { if (current === status) listeners.forEach { listener -> listener(status) } }
        }
    }
}
