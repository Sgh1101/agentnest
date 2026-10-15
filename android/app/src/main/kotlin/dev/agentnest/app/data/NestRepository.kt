package dev.agentnest.app.data

import dev.agentnest.core.link.HostBookState
import dev.agentnest.core.link.LinkClient
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.nest.ApprovalHistory
import dev.agentnest.core.nest.ApprovalHistoryEntry
import dev.agentnest.core.nest.NestReducer
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.protocol.ClientMessage
import dev.agentnest.core.protocol.DecisionMessage
import dev.agentnest.core.protocol.ServerMessage
import dev.agentnest.core.protocol.SnapshotMessage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.time.Clock
import java.time.Instant

/**
 * Process-wide holder of the UI state (docs/android.md 1.3). The foreground service owns the socket and the
 * [LinkClient]; it [attach]es the client here and this class mirrors the client's `StateFlow<NestState>` and
 * `incoming` messages for the Activity. The UI never talks to the client directly.
 *
 * While no client is attached (service stopped, not paired) the last known state is kept but its link is forced to a
 * non-connected value, so decision buttons stay disabled. Decisions are never queued here.
 */
class NestRepository(
    private val scope: CoroutineScope,
    private val clock: Clock = Clock.systemUTC(),
) {
    private val reducer = NestReducer()
    private val state = MutableStateFlow(reducer.initial(clock.instant()))
    private val incomingFlow = MutableSharedFlow<ServerMessage>(extraBufferCapacity = 64, onBufferOverflow = BufferOverflow.DROP_OLDEST)
    private val pausedFlow = MutableStateFlow(false)
    private val visibleFlow = MutableStateFlow(false)

    @Volatile
    private var client: LinkClient? = null
    private var bridge: List<Job> = emptyList()

    /** The UI state. */
    val nest: StateFlow<NestState> get() = state

    /** Accepted server messages (after the reducer): `snapshot` for the cache, `events_page` for paging, ... */
    val incoming: SharedFlow<ServerMessage> get() = incomingFlow

    /** True when the user paired but the link service is not running ("연결이 일시정지됐어요"). */
    val paused: StateFlow<Boolean> get() = pausedFlow

    /** True while an Activity is started (drives animations and whether notifications are posted). */
    val appVisible: StateFlow<Boolean> get() = visibleFlow

    /** True while a [LinkClient] is attached. */
    val connectedToService: Boolean get() = client != null

    /** Called by the Activity from onStart / onStop. */
    fun setAppVisible(visible: Boolean) {
        visibleFlow.value = visible
    }

    /**
     * Cold start (docs/android.md 2.1): show the cached snapshot right away. [paired] says whether credentials
     * exist; the link then reads "connecting" until the service reports otherwise. No-op while a client is attached.
     */
    @Synchronized
    fun restore(
        snapshot: SnapshotMessage?,
        savedAt: Instant?,
        paired: Boolean,
        history: List<ApprovalHistoryEntry> = emptyList(),
    ) {
        if (client != null) return
        val now = clock.instant()
        val link: LinkState = if (paired) LinkState.Connecting("", 1) else LinkState.Unpaired
        val base = if (paired && snapshot != null) {
            reducer.restoreFromCache(snapshot, savedAt ?: now, now, link)
        } else {
            reducer.initial(now, link)
        }
        state.value = if (paired && history.isNotEmpty()) base.copy(history = ApprovalHistory(history)) else base
        pausedFlow.value = false
    }

    /** The PC revoked this device earlier (stored pairing without a token): show the re-pair banner. No-op while a client is attached. */
    @Synchronized
    fun markRevoked() {
        if (client != null) return
        state.value = reducer.onLink(state.value, LinkState.Revoked("E_DEVICE_REVOKED"), clock.instant())
        pausedFlow.value = false
    }

    /** The service built a client: mirror it. */
    @Synchronized
    fun attach(newClient: LinkClient) {
        detachLocked(markPaused = false)
        client = newClient
        pausedFlow.value = false
        bridge = listOf(
            scope.launch { newClient.nest.collect { state.value = it } },
            scope.launch { newClient.incoming.collect { incomingFlow.emit(it) } },
        )
    }

    /** The service is going away. The state stays visible but is no longer "connected". */
    @Synchronized
    fun detach() {
        detachLocked(markPaused = true)
    }

    private fun detachLocked(markPaused: Boolean) {
        bridge.forEach { it.cancel() }
        bridge = emptyList()
        val had = client != null
        client = null
        if (!had) return
        val current = state.value
        if (current.link is LinkState.Unpaired) {
            // Unpaired / re-paired: nothing of the old PC may stay on screen.
            state.value = reducer.initial(clock.instant(), LinkState.Unpaired)
            return
        }
        state.value = reducer.onLink(current, LinkState.Offline, clock.instant())
        if (markPaused) pausedFlow.value = true
    }

    // ---------------------------------------------------------------------------------------------
    // Commands forwarded to the client (no-ops while the service is not running)
    // ---------------------------------------------------------------------------------------------

    /** Sends a decision built by `DecisionBuilder`. False when not connected or already in flight. Never queued. */
    suspend fun submitDecision(message: DecisionMessage): Boolean = client?.submitDecision(message) ?: false

    private val activeDecisions = HashSet<String>()

    /** Claims the decision flow of [requestId]; false when one is already running (single flight per request). */
    @Synchronized
    fun beginDecision(requestId: String): Boolean = activeDecisions.add(requestId)

    /** Releases the claim taken by [beginDecision]. */
    @Synchronized
    fun endDecision(requestId: String) {
        activeDecisions.remove(requestId)
    }

    /** Sends any client message (`approval_seen`, `events_request`). False when not connected. */
    suspend fun send(message: ClientMessage): Boolean = client?.send(message) ?: false

    /** Pull to refresh. */
    fun refresh() {
        client?.refresh()
    }

    /** "다시 연결": reset the backoff and retry now. */
    fun connectNow() {
        client?.connectNow()
    }

    /** The app came to the foreground: a good moment to retry a failing link. */
    fun onForeground() {
        client?.onNetworkAvailable()
    }

    /** The user confirmed '다시 페어링'. */
    fun repair() {
        client?.repair()
    }

    /** The user disconnected from the PC. */
    fun unpair() {
        client?.unpair()
    }

    /** The address book changed (manual IP / QR rescan). */
    fun onHostsChanged(hosts: HostBookState) {
        client?.onHostsChanged(hosts)
    }

    /** The current address book of the attached client, if any. */
    fun hostBook(): HostBookState? = client?.hostBook
}
