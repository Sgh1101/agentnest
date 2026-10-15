package dev.agentnest.app.pairing

import dev.agentnest.core.link.DeviceDescriptor
import dev.agentnest.core.link.PairingEffect
import dev.agentnest.core.link.PairingFlow
import dev.agentnest.core.link.PairingPhase
import dev.agentnest.core.link.PairingResult
import dev.agentnest.core.link.TransportFailure
import dev.agentnest.core.link.TransportFailureKind
import dev.agentnest.core.link.WsCallbacks
import dev.agentnest.core.link.WsConnection
import dev.agentnest.core.link.WsTransport
import dev.agentnest.core.protocol.Codec
import dev.agentnest.core.protocol.DecodeResult
import dev.agentnest.core.protocol.QrPayload
import dev.agentnest.core.protocol.ServerMessage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.time.Clock
import java.time.Duration
import java.time.Instant

/** What the pairing screen shows. [Failed.messageKo] is user-facing Korean text. */
sealed interface PairingSessionState {
    /** Trying [host] (the QR lists up to 8 addresses; they are tried one after another). */
    data class Connecting(val host: String) : PairingSessionState

    /** The phone-computed [sas] is on screen; the user has to press approve on the PC. */
    data class ShowingSas(val sas: String) : PairingSessionState

    /** The PC accepted; [result] carries the device token, which must go into the Keystore vault at once. */
    data class Completed(val result: PairingResult) : PairingSessionState

    data class Failed(val messageKo: String) : PairingSessionState
}

/**
 * Drives one pairing attempt over a pinned [WsTransport]: walks the QR's host list until a `challenge` arrives, then
 * hands every frame to the pure [PairingFlow]. All inputs (socket callbacks from OkHttp threads, ticks, cancel) go
 * through one channel and are processed by a single coroutine, so [PairingFlow] needs no locking.
 *
 * Never logs anything: frames contain the SAS and the device token.
 */
class PairingSession(
    private val qr: QrPayload,
    device: DeviceDescriptor,
    devicePublicKeySpki: ByteArray?,
    private val transport: WsTransport,
    private val scope: CoroutineScope,
    private val clock: Clock = Clock.systemUTC(),
    private val challengeTimeout: Duration = Duration.ofSeconds(10),
    private val tickInterval: Duration = Duration.ofSeconds(1),
) {
    private sealed interface Input {
        data class Frame(val connId: Long, val text: String) : Input
        data class Closed(val connId: Long) : Input
        data class Failed(val connId: Long, val failure: TransportFailure) : Input
        data object Tick : Input
        data object Cancel : Input
    }

    private val flow = PairingFlow(qr, device, devicePublicKeySpki)
    private val inbox = Channel<Input>(Channel.UNLIMITED)
    private val stateFlow = MutableStateFlow<PairingSessionState>(PairingSessionState.Connecting(qr.hosts.firstOrNull() ?: ""))
    private var jobs: List<Job> = emptyList()
    private var connection: WsConnection? = null
    private var connId = 0L
    private var hostIndex = 0
    private var attemptStartedAt: Instant = Instant.EPOCH
    private var challengeSeen = false
    private var sawPinMismatch = false
    @Volatile
    private var finished = false

    /** The current screen state. */
    val state: StateFlow<PairingSessionState> get() = stateFlow

    /** Starts connecting. Call once. */
    fun start() {
        check(jobs.isEmpty()) { "already started" }
        jobs = listOf(
            scope.launch {
                openHost(0)
                for (input in inbox) {
                    if (finished) break
                    process(input)
                }
            },
            scope.launch {
                while (isActive && !finished) {
                    delay(tickInterval.toMillis())
                    inbox.trySend(Input.Tick)
                }
            },
        )
    }

    /** The user left the screen or pressed cancel. Sends `unpair{pairing_id}` when the PC already knows the attempt. */
    fun cancel() {
        inbox.trySend(Input.Cancel)
    }

    // ---------------------------------------------------------------------------------------------

    private fun callbacksFor(id: Long) = object : WsCallbacks {
        override fun onOpen() = Unit

        override fun onText(text: String) {
            inbox.trySend(Input.Frame(id, text))
        }

        override fun onClosed(code: Int, reason: String) {
            inbox.trySend(Input.Closed(id))
        }

        override fun onFailure(failure: TransportFailure) {
            inbox.trySend(Input.Failed(id, failure))
        }
    }

    private fun openHost(index: Int) {
        hostIndex = index
        val host = qr.hosts[index]
        connId++
        attemptStartedAt = clock.instant()
        stateFlow.value = PairingSessionState.Connecting(host)
        connection = transport.open(host, qr.port, callbacksFor(connId))
    }

    private fun process(input: Input) {
        val now = clock.instant()
        when (input) {
            is Input.Frame -> if (input.connId == connId) onFrame(input.text, now)
            is Input.Closed -> if (input.connId == connId) onConnectionEnded(null)
            is Input.Failed -> if (input.connId == connId) onConnectionEnded(input.failure)
            Input.Tick -> onTick(now)
            Input.Cancel -> run(flow.cancel(now))
        }
    }

    private fun onFrame(text: String, now: Instant) {
        val decoded = Codec.decodeServer(text)
        val message = (decoded as? DecodeResult.Decoded)?.message as? ServerMessage ?: return
        val effects = flow.onMessage(message, now)
        if (flow.phase != PairingPhase.WaitingForChallenge) challengeSeen = true
        run(effects)
    }

    private fun onConnectionEnded(failure: TransportFailure?) {
        if (challengeSeen) {
            run(flow.onConnectionClosed())
            return
        }
        if (failure?.kind == TransportFailureKind.PIN_MISMATCH) sawPinMismatch = true
        nextHostOrFail()
    }

    private fun onTick(now: Instant) {
        if (!challengeSeen && Duration.between(attemptStartedAt, now) > challengeTimeout) {
            connection?.cancel()
            // Late events of the abandoned connection carry the old id and are ignored.
            nextHostOrFail()
            return
        }
        run(flow.onTick(now))
    }

    private fun nextHostOrFail() {
        val next = hostIndex + 1
        if (next < qr.hosts.size) {
            openHost(next)
            return
        }
        qr.wipe()
        stateFlow.value = PairingSessionState.Failed(if (sawPinMismatch) MSG_PIN_MISMATCH else MSG_UNREACHABLE)
        finish()
    }

    private fun run(effects: List<PairingEffect>) {
        for (effect in effects) {
            when (effect) {
                is PairingEffect.Send -> connection?.send(Codec.encode(effect.message))
                is PairingEffect.Close -> connection?.close(effect.code, effect.reason)
                is PairingEffect.ShowSas -> stateFlow.value = PairingSessionState.ShowingSas(effect.sas)
                is PairingEffect.Completed -> {
                    stateFlow.value = PairingSessionState.Completed(effect.result)
                    finish()
                }
                is PairingEffect.Failed -> {
                    stateFlow.value = PairingSessionState.Failed(effect.failure.messageKo)
                    finish()
                }
            }
        }
    }

    private fun finish() {
        if (finished) return
        finished = true
        // Graceful: queued frames (unpair) are flushed first. The pair socket is not reused; LinkService opens its own.
        connection?.close(CLOSE_NORMAL, "done")
        inbox.close()
        jobs.forEach { it.cancel() }
    }

    private companion object {
        const val CLOSE_NORMAL = 1000
        const val MSG_UNREACHABLE = "PC에 연결하지 못했어요. 같은 Wi-Fi에 연결되어 있는지 확인하고, PC에서 새 QR을 만들어 다시 스캔해 주세요"
        const val MSG_PIN_MISMATCH = "PC의 인증 정보가 QR과 달라요. PC에서 새 QR을 만들어 다시 스캔해 주세요"
    }
}
