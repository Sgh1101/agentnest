package dev.agentnest.app.service

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.ServiceCompat
import dev.agentnest.app.AgentNestApp
import dev.agentnest.app.AppContainer
import dev.agentnest.app.notify.AlertKind
import dev.agentnest.app.notify.AlertPolicy
import dev.agentnest.app.notify.AlertThrottle
import dev.agentnest.app.notify.LinkNotifier
import dev.agentnest.app.notify.NotificationTexts
import dev.agentnest.core.crypto.B64
import dev.agentnest.core.crypto.SpkiPin
import dev.agentnest.core.link.DeviceCredentials
import dev.agentnest.core.link.LinkClient
import dev.agentnest.core.link.OkHttpWsTransport
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.protocol.AgentEvent
import dev.agentnest.core.protocol.EventMessage
import dev.agentnest.core.protocol.SnapshotMessage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant

/**
 * Foreground service (`connectedDevice`) that owns the socket (docs/android.md 3.1). It builds the `LinkClient` from the
 * stored pairing, mirrors it into [dev.agentnest.app.data.NestRepository], keeps the status notification current and
 * posts approval / alert notifications. It NEVER creates decisions: those come from the Activity after authentication.
 *
 * Started only from places where Android allows it: the visible app, the notification's "다시 연결" action, boot.
 */
class LinkService : Service() {
    /** Socket work (decoding frames, the link state machine) stays off the main thread. */
    private val workScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /** Service bookkeeping and notifications are confined to the main thread, so no locking is needed. */
    private val mainScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private lateinit var container: AppContainer

    private var client: LinkClient? = null
    private var transport: OkHttpWsTransport? = null
    private var observers: List<Job> = emptyList()
    private var starting: Job? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    @Volatile
    private var credentials: DeviceCredentials? = null

    private val notifiedApprovals = HashSet<String>()
    private val errorThrottle = AlertThrottle()
    private val completionThrottle = AlertThrottle()

    override fun onCreate() {
        super.onCreate()
        container = (application as AgentNestApp).container
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Must happen first: Android kills the app if startForeground does not follow startForegroundService in time.
        if (!enterForeground()) {
            container.alertNotifier.serviceStartBlocked()
            stopSelf()
            return START_NOT_STICKY
        }
        when (intent?.action) {
            ACTION_STOP -> {
                shutdown()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_RECONNECT -> client?.connectNow()
            ACTION_RESTART -> {
                shutdown()
                startLink()
            }
            else -> if (client != null) container.repository.onForeground() else startLink()
        }
        return START_STICKY
    }

    /** connectedDevice has no time limit; this is only defensive for the API 35 callback. */
    override fun onTimeout(startId: Int, fgsType: Int) {
        shutdown()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        shutdown()
        workScope.cancel()
        mainScope.cancel()
        super.onDestroy()
    }

    // ---------------------------------------------------------------------------------------------

    private fun enterForeground(): Boolean {
        val notification = container.linkNotifier.build(NotificationTexts.linkStatus(container.repository.nest.value.link, null, false, Instant.now()))
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE else 0
        return try {
            ServiceCompat.startForeground(this, LinkNotifier.NOTIFICATION_ID, notification, type)
            true
        } catch (e: Exception) {
            // ForegroundServiceStartNotAllowedException (API 31+) and friends: report it, do not crash.
            Log.w(TAG, "startForeground refused: ${e.javaClass.simpleName}")
            false
        }
    }

    private fun startLink() {
        if (starting?.isActive == true || client != null) return
        starting = mainScope.launch {
            val data = container.pairingStore.load()
            val blob = data?.sealedToken
            if (data == null || blob == null) {
                // Not paired, or the PC revoked this device: nothing to connect with.
                stopFromBackground()
                return@launch
            }
            val token = withContext(Dispatchers.Default) { openToken(blob) }
            if (token == null) {
                // The Keystore refused (invalidated / bad tag): wipe and ask for a new pairing (docs/android.md 4.1).
                container.handleVaultInvalid()
                stopFromBackground()
                return@launch
            }
            val pin = SpkiPin.parse(data.pinString)
            if (pin == null) {
                container.handleVaultInvalid()
                stopFromBackground()
                return@launch
            }
            credentials = DeviceCredentials(data.deviceId, token)
            val newTransport = OkHttpWsTransport(pin)
            val newClient = LinkClient(
                transport = newTransport,
                hosts = data.hosts,
                credentials = { credentials },
                sideEffects = LinkSideEffectsImpl(
                    container = container,
                    scope = workScope,
                    onCredentialsGone = { credentials = null },
                    onPairingWiped = { mainScope.launch { endService() } },
                ),
                scope = workScope,
                initialState = container.repository.nest.value,
                onError = { e -> Log.w(TAG, "link client error: ${e.javaClass.simpleName}") },
            )
            transport = newTransport
            client = newClient
            container.repository.attach(newClient)
            newClient.start(paired = true)
            registerNetworkCallback(newClient)
            observe()
        }
    }

    private fun openToken(blob: String): String? {
        val bytes = B64.decode(blob) ?: return null
        val plain = container.vault.open(bytes) ?: return null
        return try {
            String(plain, Charsets.UTF_8)
        } finally {
            plain.fill(0)
        }
    }

    private fun stopFromBackground() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /** The pairing was wiped (unpair / re-pair / revoked + repair): tear everything down and leave. */
    private fun endService() {
        shutdown()
        stopFromBackground()
    }

    private fun shutdown() {
        starting?.cancel()
        starting = null
        observers.forEach { it.cancel() }
        observers = emptyList()
        unregisterNetworkCallback()
        client?.stop()
        client = null
        transport?.shutdown()
        transport = null
        credentials = null
        container.repository.detach()
        notifiedApprovals.forEach { container.approvalNotifier.cancel(it) }
        notifiedApprovals.clear()
        container.approvalNotifier.updateSummary(0)
    }

    private fun registerNetworkCallback(target: LinkClient) {
        val manager = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                target.onNetworkAvailable()
            }

            override fun onLost(network: Network) {
                // A handover (Wi-Fi -> cellular) can report the old network lost after the new one is up.
                if (manager.activeNetwork == null) target.onNetworkLost() else target.onNetworkAvailable()
            }
        }
        try {
            manager.registerDefaultNetworkCallback(callback)
            networkCallback = callback
        } catch (e: RuntimeException) {
            Log.w(TAG, "network callback not registered: ${e.javaClass.simpleName}")
        }
    }

    private fun unregisterNetworkCallback() {
        val callback = networkCallback ?: return
        networkCallback = null
        val manager = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        try {
            manager.unregisterNetworkCallback(callback)
        } catch (e: RuntimeException) {
            // Already unregistered.
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Mirroring: status notification, approval notifications, alerts, snapshot cache
    // ---------------------------------------------------------------------------------------------

    private fun observe() {
        val repo = container.repository
        observers = listOf(
            mainScope.launch {
                combine(repo.nest, repo.appVisible) { nest, visible -> nest to visible }.collect { (nest, visible) ->
                    onNestChanged(nest, visible)
                }
            },
            mainScope.launch {
                repo.incoming.collect { message ->
                    when (message) {
                        is EventMessage -> onEvent(message.payload)
                        is SnapshotMessage -> container.saveSnapshot(message)
                        else -> Unit
                    }
                }
            },
        )
    }

    private fun onNestChanged(nest: NestState, visible: Boolean) {
        val pcName = container.paired.value?.pcName
        container.linkNotifier.update(NotificationTexts.linkStatus(nest.link, pcName, false, Instant.now()))
        syncApprovalNotifications(nest, visible)
    }

    private fun syncApprovalNotifications(nest: NestState, visible: Boolean) {
        val now = Instant.now()
        val notifier = container.approvalNotifier
        // Gone, expired or decided cards lose their notification.
        for (id in notifiedApprovals.toList()) {
            val card = nest.approvals[id]
            if (card == null || card.isExpired(now, nest.clockSkewMs) || card.inFlight != null) {
                notifier.cancel(id)
                notifiedApprovals.remove(id)
            }
        }
        if (visible) {
            // The user is looking at the cards: take the heads-up notifications down but remember them (no re-post).
            notifiedApprovals.forEach { notifier.cancel(it) }
            notifier.updateSummary(0)
            return
        }
        val silent = !container.settings.state.value.soundEnabled
        val alreadyPosted = notifiedApprovals.size
        for (card in nest.pendingCards(now)) {
            val request = card.request ?: continue
            if (card.inFlight != null || request.requestId in notifiedApprovals) continue
            notifiedApprovals.add(request.requestId)
            notifier.show(request, NotificationTexts.remainingSeconds(request, now, nest.clockSkewMs), silent)
        }
        if (notifiedApprovals.size != alreadyPosted || notifiedApprovals.isNotEmpty()) notifier.updateSummary(notifiedApprovals.size)
    }

    private fun onEvent(event: AgentEvent) {
        if (container.repository.appVisible.value) return
        val nest = container.repository.nest.value
        val session = nest.sessions[event.sessionKey]
        val kind = AlertPolicy.classify(event, session) ?: return
        val now = Instant.now()
        when (kind) {
            AlertKind.ERROR -> if (errorThrottle.allow(event.sessionKey, now)) {
                container.alertNotifier.error(NotificationTexts.alert(event, session), event.sessionKey)
            }
            AlertKind.COMPLETION -> if (completionThrottle.allow(event.sessionKey, now)) {
                container.alertNotifier.completion(NotificationTexts.alert(event, session), event.sessionKey)
            }
        }
    }

    companion object {
        private const val TAG = "LinkService"

        /** Start or nudge the link (also the default for a null intent after a system restart). */
        const val ACTION_START = "dev.agentnest.app.action.START"

        /** Notification action "다시 연결": reset the backoff and retry now. */
        const val ACTION_RECONNECT = "dev.agentnest.app.action.RECONNECT"

        /** Notification action "일시정지": disconnect and stop the service until the app is opened again. */
        const val ACTION_STOP = "dev.agentnest.app.action.STOP"

        /** The pairing changed: rebuild the client from the stored data. */
        const val ACTION_RESTART = "dev.agentnest.app.action.RESTART"
    }
}
