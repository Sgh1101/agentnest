package dev.agentnest.core.link

import dev.agentnest.core.protocol.ClientMessage
import dev.agentnest.core.protocol.PcInfo
import dev.agentnest.core.protocol.ServerMessage
import java.time.Instant

/** Why a reconnect is being scheduled. */
sealed interface LinkError {
    data object Unreachable : LinkError
    data object PinMismatch : LinkError
    data object Tls : LinkError
    data object AuthFailed : LinkError
    data object Superseded : LinkError
    data object HeartbeatTimeout : LinkError
    data object HandshakeTimeout : LinkError
    data object ProtocolViolation : LinkError
    data object RateLimited : LinkError
    data class ServerClosed(val code: Int) : LinkError
    data class PcShutdown(val messageKo: String?) : LinkError
}

/** Why the user has to pair again. */
enum class RepairReason { AUTH_FAILED, IDENTITY_CHANGED }

/** Connection state exposed to the UI (docs/android.md 3.2). */
sealed interface LinkState {
    data object Unpaired : LinkState
    data class Connecting(val host: String, val attempt: Int) : LinkState

    /** `challenge` received, `hello` sent, waiting for `welcome`. */
    data object Challenged : LinkState
    data class Connected(val pc: PcInfo, val since: Instant, val rttMs: Int?) : LinkState
    data class Reconnecting(val attempt: Int, val nextAt: Instant, val lastError: LinkError) : LinkState

    /** The OS reports no network. */
    data object Offline : LinkState

    /** Five consecutive failed connection rounds: show "enter IP manually" / "rescan QR". */
    data class PcUnreachable(val since: Instant) : LinkState

    /** Pairing must be redone ('다시 페어링'); automatic retries are stopped. */
    data class NeedsRepair(val reason: RepairReason) : LinkState

    /** The PC revoked this device (E_DEVICE_REVOKED / close 4003). Automatic retries are forbidden. */
    data class Revoked(val code: String) : LinkState

    /** Pin mismatch three times in a row: no connection attempts until [until] (or the user re-pairs). */
    data class Suspended(val until: Instant) : LinkState

    /** The PC speaks a protocol version this app does not (close 4010 / E_PROTO_VERSION). */
    data object Incompatible : LinkState
}

/** Why a security notification should be raised. */
enum class SecurityAlertKind { PC_IDENTITY_CHANGED, DEVICE_REVOKED, REPEATED_AUTH_FAILURE }

/** Side effects requested by [LinkStateMachine]. The app executes them; the machine performs no I/O itself. */
sealed interface LinkEffect {
    /** Open a connection; events for it must carry [connId]. */
    data class OpenSocket(val connId: Long, val host: String, val port: Int) : LinkEffect

    /** Graceful close with a WebSocket close code. */
    data class CloseSocket(val code: Int, val reason: String) : LinkEffect

    /** Abort the connection without a close handshake. */
    data object AbortSocket : LinkEffect
    data class Send(val message: ClientMessage) : LinkEffect

    /** Call [LinkStateMachine.handle] with a tick at (or after) [at]. */
    data class ScheduleWake(val at: Instant) : LinkEffect

    /** Persist the updated address book. */
    data class PersistHosts(val hosts: HostBookState) : LinkEffect

    /** Delete only the device token (revoked by the PC). */
    data object WipeDeviceToken : LinkEffect

    /** Delete token, pin, pc_id, address book and the Keystore entries. */
    data object WipePairing : LinkEffect
    data class SecurityAlert(val kind: SecurityAlertKind) : LinkEffect
}

/** Inputs of [LinkStateMachine]. Socket events carry the id of the connection they belong to; stale ones are ignored. */
sealed interface LinkEvent {
    /** App start: connect when [paired] is true. */
    data class Start(val paired: Boolean) : LinkEvent

    /** Pairing just completed: the credentials are stored, connect now. */
    data object Paired : LinkEvent

    /** User pressed "reconnect" / app came to the foreground: reset backoff and retry. */
    data object ConnectNow : LinkEvent
    data object NetworkAvailable : LinkEvent
    data object NetworkLost : LinkEvent

    /** The address book changed (manual IP added, QR rescanned): retry immediately. */
    data class HostsChanged(val hosts: HostBookState) : LinkEvent
    data class SocketOpened(val connId: Long) : LinkEvent
    data class SocketClosed(val connId: Long, val code: Int, val reason: String) : LinkEvent
    data class SocketFailed(val connId: Long, val failure: TransportFailure) : LinkEvent
    data class FrameReceived(val connId: Long, val message: ServerMessage) : LinkEvent

    /** Periodic wake-up (about once a second while connected, and at every `ScheduleWake` time). */
    data object Tick : LinkEvent

    /** User confirmed '다시 페어링'. */
    data object UserRepair : LinkEvent

    /** User chose to disconnect from the PC. */
    data object UserUnpair : LinkEvent
}
