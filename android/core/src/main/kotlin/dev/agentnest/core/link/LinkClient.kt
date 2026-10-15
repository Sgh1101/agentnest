package dev.agentnest.core.link

import dev.agentnest.core.nest.NestReducer
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.protocol.ClientMessage
import dev.agentnest.core.protocol.Codec
import dev.agentnest.core.protocol.DecisionMessage
import dev.agentnest.core.protocol.DecodeResult
import dev.agentnest.core.protocol.ServerMessage
import dev.agentnest.core.util.Uuid7Generator
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.time.Clock
import java.time.Duration
import java.time.Instant

/**
 * Persistence and notification hooks the app implements for [LinkClient]. Called from the client's single
 * processing coroutine; implementations must not block for long.
 */
interface LinkSideEffects {
    /** Persist the updated PC address book. */
    fun persistHosts(hosts: HostBookState)

    /** The PC revoked this device: delete the stored device token. */
    fun wipeDeviceToken()

    /** The user re-paired or unpaired: delete token, pin, pc_id, address book and the Keystore entries. */
    fun wipePairing()

    /** Raise a `security` channel notification. */
    fun securityAlert(kind: SecurityAlertKind)
}

/**
 * Glue between [WsTransport], [LinkStateMachine] and [NestReducer]: executes machine effects, decodes frames,
 * routes them (machine first; to the reducer while connected) and publishes [NestState]. Everything runs on ONE
 * coroutine fed by a channel, so socket callbacks from any thread are safe and no locks are needed.
 *
 * The client never decides anything about approvals: it only transports `decision` messages the app built with
 * `DecisionBuilder` after `DecisionValidator` approved them, and refuses to send while the link is not Connected
 * (decisions are never queued).
 */
class LinkClient(
    private val transport: WsTransport,
    hosts: HostBookState,
    private val credentials: () -> DeviceCredentials?,
    private val sideEffects: LinkSideEffects,
    private val scope: CoroutineScope,
    private val clock: Clock = Clock.systemUTC(),
    private val reducer: NestReducer = NestReducer(),
    config: LinkConfig = LinkConfig(),
    backoff: BackoffPolicy = BackoffPolicy(),
    ids: () -> String = Uuid7Generator()::next,
    initialState: NestState? = null,
    private val tickInterval: Duration = Duration.ofSeconds(1),
    private val onError: (Throwable) -> Unit = {},
) {
    private sealed interface Input {
        data class Link(val event: LinkEvent) : Input
        data class Frame(val connId: Long, val text: String) : Input
        data class Send(val message: ClientMessage, val result: CompletableDeferred<Boolean>) : Input
        data class Decision(val message: DecisionMessage, val result: CompletableDeferred<Boolean>) : Input
        data object Tick : Input
        data object Refresh : Input
    }

    private val inbox = Channel<Input>(Channel.UNLIMITED)
    private val state = MutableStateFlow(initialState ?: reducer.initial(clock.instant()))
    private val incomingFlow = MutableSharedFlow<ServerMessage>(extraBufferCapacity = 64, onBufferOverflow = BufferOverflow.DROP_OLDEST)
    private val machine = LinkStateMachine(hosts, credentials, { state.value.lastSeq }, config, backoff, ids)
    private var connection: WsConnection? = null
    private var jobs: List<Job> = emptyList()

    /** The UI state. Updated after every processed input. */
    val nest: StateFlow<NestState> get() = state

    /**
     * Every server message that was accepted while connected, after the reducer processed it (`snapshot` for the
     * on-disk cache, `events_page` for `EventsPager`, `decision_result` for toasts, `approval_resolved` ...).
     */
    val incoming: SharedFlow<ServerMessage> get() = incomingFlow

    /** The current address book (also delivered through [LinkSideEffects.persistHosts]). */
    val hostBook: HostBookState get() = machine.hosts

    /** Starts processing. [paired] says whether credentials exist; if so the client connects right away. */
    fun start(paired: Boolean) {
        check(jobs.isEmpty()) { "already started" }
        jobs = listOf(
            scope.launch {
                for (input in inbox) {
                    try {
                        process(input)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        // A bug in one input must not brick the link; report it and keep going.
                        onError(e)
                    }
                }
            },
            scope.launch {
                while (isActive) {
                    delay(tickInterval.toMillis())
                    inbox.trySend(Input.Tick)
                }
            },
        )
        post(LinkEvent.Start(paired))
    }

    /** Stops processing and aborts the socket. The client cannot be restarted. */
    fun stop() {
        jobs.forEach { it.cancel() }
        jobs = emptyList()
        inbox.close()
        connection?.cancel()
        connection = null
    }

    /** Pairing just finished (credentials stored): connect. */
    fun onPaired() = post(LinkEvent.Paired)

    /** The OS reports a usable network again (ConnectivityManager `onAvailable`) or the app came to the foreground. */
    fun onNetworkAvailable() = post(LinkEvent.NetworkAvailable)

    /** The OS reports that the network is gone. */
    fun onNetworkLost() = post(LinkEvent.NetworkLost)

    /** The user pressed "reconnect". */
    fun connectNow() = post(LinkEvent.ConnectNow)

    /** The address book was changed by the user (manual IP, QR rescan). */
    fun onHostsChanged(hosts: HostBookState) = post(LinkEvent.HostsChanged(hosts))

    /** The user confirmed '다시 페어링'. */
    fun repair() = post(LinkEvent.UserRepair)

    /** The user disconnected from the PC. */
    fun unpair() = post(LinkEvent.UserUnpair)

    /** Asks the PC for a fresh snapshot (pull to refresh). Does nothing while not connected. */
    fun refresh() {
        inbox.trySend(Input.Refresh)
    }

    /** Sends any client message (for example `approval_seen`, `events_request`). Returns false while not connected. */
    suspend fun send(message: ClientMessage): Boolean {
        val result = CompletableDeferred<Boolean>()
        if (inbox.trySend(Input.Send(message, result)).isFailure) return false
        return result.await()
    }

    /**
     * Sends a decision built by `DecisionBuilder` and marks it in flight. Returns false (and sends nothing) when the
     * link is not connected or the card already has a decision in flight. Decisions are never queued.
     */
    suspend fun submitDecision(message: DecisionMessage): Boolean {
        val result = CompletableDeferred<Boolean>()
        if (inbox.trySend(Input.Decision(message, result)).isFailure) return false
        return result.await()
    }

    // ---------------------------------------------------------------------------------------------

    private fun post(event: LinkEvent) {
        inbox.trySend(Input.Link(event))
    }

    private fun callbacksFor(connId: Long) = object : WsCallbacks {
        override fun onOpen() {
            inbox.trySend(Input.Link(LinkEvent.SocketOpened(connId)))
        }

        override fun onText(text: String) {
            inbox.trySend(Input.Frame(connId, text))
        }

        override fun onClosed(code: Int, reason: String) {
            inbox.trySend(Input.Link(LinkEvent.SocketClosed(connId, code, reason)))
        }

        override fun onFailure(failure: TransportFailure) {
            inbox.trySend(Input.Link(LinkEvent.SocketFailed(connId, failure)))
        }
    }

    private fun process(input: Input) {
        val now = clock.instant()
        when (input) {
            is Input.Link -> handleLink(input.event, now)
            is Input.Tick -> {
                handleLink(LinkEvent.Tick, now)
                val tick = reducer.tick(state.value, now)
                state.value = tick.state
                tick.outbound.forEach(::sendIfConnected)
            }
            is Input.Frame -> handleFrame(input, now)
            Input.Refresh -> if (machine.state is LinkState.Connected) {
                val result = reducer.requestSnapshot(state.value, "pull_to_refresh", now)
                state.value = result.state
                result.outbound.forEach(::sendIfConnected)
            }
            is Input.Send -> input.result.complete(sendIfConnected(input.message))
            is Input.Decision -> {
                val request = input.message.payload.requestId
                val card = state.value.approvals[request]
                val allowed = card != null && card.inFlight == null && machine.state is LinkState.Connected
                val sent = allowed && sendIfConnected(input.message)
                if (sent) {
                    state.value = reducer.markDecisionSent(
                        state.value, request, input.message.meta.id, input.message.payload.decision, now,
                    )
                }
                input.result.complete(sent)
            }
        }
    }

    private fun handleLink(event: LinkEvent, now: Instant) {
        val before = machine.state
        val effects = machine.handle(event, now)
        execute(effects)
        if (machine.state != before || event is LinkEvent.Tick) {
            state.value = reducer.onLink(state.value, machine.state, now)
        }
    }

    private fun handleFrame(frame: Input.Frame, now: Instant) {
        val decoded = Codec.decodeServer(frame.text)
        val message: ServerMessage = (decoded as? DecodeResult.Decoded)?.message as? ServerMessage ?: return
        handleLink(LinkEvent.FrameReceived(frame.connId, message), now)
        if (machine.state is LinkState.Connected) {
            val result = reducer.reduce(state.value, message, now)
            state.value = result.state
            result.outbound.forEach(::sendIfConnected)
            incomingFlow.tryEmit(message)
        }
    }

    /** Messages are only ever sent on a fully connected link (hello/unpair travel as machine effects). */
    private fun sendIfConnected(message: ClientMessage): Boolean {
        val conn = connection ?: return false
        if (machine.state !is LinkState.Connected) return false
        return conn.send(Codec.encode(message))
    }

    private fun execute(effects: List<LinkEffect>) {
        for (effect in effects) {
            when (effect) {
                is LinkEffect.OpenSocket -> {
                    connection?.cancel()
                    connection = transport.open(effect.host, effect.port, callbacksFor(effect.connId))
                }
                is LinkEffect.CloseSocket -> {
                    connection?.close(effect.code, effect.reason)
                    connection = null
                }
                LinkEffect.AbortSocket -> {
                    connection?.cancel()
                    connection = null
                }
                is LinkEffect.Send -> connection?.send(Codec.encode(effect.message))
                is LinkEffect.ScheduleWake -> Unit // the 1 s tick loop covers every deadline
                is LinkEffect.PersistHosts -> sideEffects.persistHosts(effect.hosts)
                LinkEffect.WipeDeviceToken -> sideEffects.wipeDeviceToken()
                LinkEffect.WipePairing -> sideEffects.wipePairing()
                is LinkEffect.SecurityAlert -> sideEffects.securityAlert(effect.kind)
            }
        }
    }
}
