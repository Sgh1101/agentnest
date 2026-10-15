package dev.agentnest.core.link

import dev.agentnest.core.protocol.AckMessage
import dev.agentnest.core.protocol.AckPayload
import dev.agentnest.core.protocol.ByeMessage
import dev.agentnest.core.protocol.ByeReason
import dev.agentnest.core.protocol.ChallengeMessage
import dev.agentnest.core.protocol.ErrorCode
import dev.agentnest.core.protocol.ErrorMessage
import dev.agentnest.core.protocol.FrameMeta
import dev.agentnest.core.protocol.HelloMessage
import dev.agentnest.core.protocol.HelloPayload
import dev.agentnest.core.protocol.HostsUpdateMessage
import dev.agentnest.core.protocol.PingMessage
import dev.agentnest.core.protocol.PingPayload
import dev.agentnest.core.protocol.PongMessage
import dev.agentnest.core.protocol.Ts
import dev.agentnest.core.protocol.UnpairMessage
import dev.agentnest.core.protocol.UnpairPayload
import dev.agentnest.core.protocol.WelcomeMessage
import dev.agentnest.core.util.Uuid7Generator
import java.time.Duration
import java.time.Instant

/** The device credentials needed for `hello`. [toString] never prints the token. */
class DeviceCredentials(val deviceId: String, val deviceToken: String) {
    override fun toString(): String = "DeviceCredentials(deviceId=$deviceId, token=<redacted>)"
}

/** Tunables of [LinkStateMachine]; the defaults are the values fixed in docs/android.md and protocol.md. */
data class LinkConfig(
    val appVersion: String = "0.1.0",
    val pingInterval: Duration = Duration.ofSeconds(30),
    val silenceTimeout: Duration = Duration.ofSeconds(70),
    val handshakeTimeout: Duration = Duration.ofSeconds(10),
    val ackBatchInterval: Duration = Duration.ofSeconds(1),
    val unreachableAfterRounds: Int = 5,
    val authFailuresForRepair: Int = 3,
    val pinMismatchesForSuspend: Int = 3,
    val pinSuspension: Duration = Duration.ofHours(1),
    val pcShutdownRetry: Duration = Duration.ofMinutes(5),
)

/**
 * The security counters of the link that must survive process death (docs/android.md 3.2): without them, killing the
 * service would reset "3 pin mismatches -> 1 h suspension -> NeedsRepair" and "3 auth failures -> NeedsRepair" to zero.
 * [pinMismatchRounds] counts connection ROUNDS in which every host failed the pin check.
 */
data class LinkCounters(
    val authFailures: Int = 0,
    val pinMismatchRounds: Int = 0,
    val suspensions: Int = 0,
    val suspendedUntil: Instant? = null,
    val needsRepair: RepairReason? = null,
) {
    /** True when nothing is remembered (the stored copy can be cleared). */
    val isClear: Boolean
        get() = authFailures == 0 && pinMismatchRounds == 0 && suspensions == 0 && suspendedUntil == null && needsRepair == null
}

/**
 * Connection lifecycle of the phone <-> PC link (docs/android.md 3.2). Pure: it does no I/O and never reads a
 * clock; callers pass `now` and execute the returned [LinkEffect]s. Not thread-safe; drive it from one thread.
 *
 * Contract for the app:
 * - execute [LinkEffect.OpenSocket] and tag every later socket event with its `connId`;
 * - forward every decoded server frame as [LinkEvent.FrameReceived]; pass a frame on to `NestReducer` when the
 *   machine's [state] is [LinkState.Connected] after handling it;
 * - send [LinkEvent.Tick] about once a second while connected and at every [LinkEffect.ScheduleWake] time.
 */
class LinkStateMachine(
    hosts: HostBookState,
    private val credentials: () -> DeviceCredentials?,
    private val lastSeq: () -> Long,
    private val config: LinkConfig = LinkConfig(),
    private val backoff: BackoffPolicy = BackoffPolicy(),
    private val ids: () -> String = Uuid7Generator()::next,
    initialCounters: LinkCounters = LinkCounters(),
) {
    /** The current state. */
    var state: LinkState = LinkState.Unpaired
        private set

    /** The current address book (persist it when [LinkEffect.PersistHosts] is emitted). */
    var hosts: HostBookState = hosts
        private set

    private var connCounter = 0L
    private var activeConn: Long? = null
    private var hostQueue: List<String> = emptyList()
    private var hostIndex = 0
    private var currentHost = ""
    private var failures = 0
    private var authFailures = initialCounters.authFailures
    private var pinMismatches = initialCounters.pinMismatchRounds
    private var suspensions = initialCounters.suspensions
    private var suspendedUntil: Instant? = initialCounters.suspendedUntil
    private var needsRepairReason: RepairReason? = initialCounters.needsRepair
    private var roundAttempts = 0
    private var roundPinMismatches = 0
    private var persisted = initialCounters
    private var authFailedThisConnection = false
    private var phaseStartedAt: Instant = Instant.EPOCH
    private var lastReceivedAt: Instant = Instant.EPOCH
    private var lastSentAt: Instant = Instant.EPOCH
    private var lastAckAt: Instant = Instant.EPOCH
    private var lastAckedSeq = 0L
    private var pingId: String? = null
    private var pingSentAt: Instant? = null
    private var nextRetryAt: Instant? = null
    private var unreachableSince: Instant? = null

    /** Applies [event] at time [now] and returns the effects the app must execute, in order. */
    fun handle(event: LinkEvent, now: Instant): List<LinkEffect> {
        val effects = ArrayList<LinkEffect>()
        when (event) {
            is LinkEvent.Start -> if (event.paired) startPaired(now, effects) else state = LinkState.Unpaired
            LinkEvent.Paired -> {
                resetCounters(effects) // a fresh pairing starts with a clean slate
                startFresh(now, effects)
            }
            LinkEvent.ConnectNow -> if (isRetryable()) startFresh(now, effects)
            LinkEvent.NetworkAvailable -> if (isRetryable()) startFresh(now, effects)
            LinkEvent.NetworkLost -> onNetworkLost(effects)
            is LinkEvent.HostsChanged -> {
                hosts = event.hosts
                if (state is LinkState.Reconnecting || state is LinkState.PcUnreachable) startFresh(now, effects)
            }
            is LinkEvent.SocketOpened -> if (event.connId == activeConn) lastReceivedAt = now
            is LinkEvent.SocketClosed -> if (event.connId == activeConn) onSocketClosed(event.code, now, effects)
            is LinkEvent.SocketFailed -> if (event.connId == activeConn) onSocketFailed(event.failure, now, effects)
            is LinkEvent.FrameReceived -> if (event.connId == activeConn) onFrame(event, now, effects)
            LinkEvent.Tick -> onTick(now, effects)
            LinkEvent.UserRepair -> onUserRepair(effects)
            LinkEvent.UserUnpair -> onUserUnpair(now, effects)
        }
        return effects
    }

    // ---------------------------------------------------------------------------------------------
    // Connection rounds
    // ---------------------------------------------------------------------------------------------

    private fun isRetryable(): Boolean =
        state is LinkState.Reconnecting || state is LinkState.PcUnreachable || state is LinkState.Offline

    /** App / service start: a remembered NeedsRepair or a still-running suspension is restored instead of reconnecting. */
    private fun startPaired(now: Instant, effects: MutableList<LinkEffect>) {
        needsRepairReason?.let { reason ->
            state = LinkState.NeedsRepair(reason)
            return
        }
        val until = suspendedUntil
        if (until != null && now.isBefore(until)) {
            nextRetryAt = until
            state = LinkState.Suspended(until)
            effects += LinkEffect.ScheduleWake(until)
            return
        }
        if (until != null) {
            // The suspension ran out while the service was down: forget it (suspensions stays 1, so a repeat escalates).
            pinMismatches = 0
            suspendedUntil = null
            persistCounters(effects)
        }
        startFresh(now, effects)
    }

    private fun startFresh(now: Instant, effects: MutableList<LinkEffect>) {
        failures = 0
        unreachableSince = null
        authFailedThisConnection = false
        beginRound(now, effects)
    }

    private fun beginRound(now: Instant, effects: MutableList<LinkEffect>) {
        hostQueue = hosts.candidates()
        hostIndex = 0
        roundAttempts = 0
        roundPinMismatches = 0
        if (hostQueue.isEmpty()) {
            roundFailed(now, LinkError.Unreachable, effects)
        } else {
            startAttempt(now, effects)
        }
    }

    private fun startAttempt(now: Instant, effects: MutableList<LinkEffect>) {
        currentHost = hostQueue[hostIndex]
        connCounter++
        activeConn = connCounter
        authFailedThisConnection = false
        pingId = null
        pingSentAt = null
        phaseStartedAt = now
        lastReceivedAt = now
        state = LinkState.Connecting(currentHost, failures + 1)
        effects += LinkEffect.OpenSocket(connCounter, currentHost, hosts.port)
        effects += LinkEffect.ScheduleWake(now.plus(config.handshakeTimeout))
    }

    /** The current host did not work; try the next one, or finish the round. */
    private fun attemptFailed(now: Instant, error: LinkError, effects: MutableList<LinkEffect>) {
        activeConn = null
        roundAttempts++
        if (error == LinkError.PinMismatch) roundPinMismatches++
        hostIndex++
        if (hostIndex < hostQueue.size) startAttempt(now, effects) else roundFailed(now, error, effects)
    }

    private fun roundFailed(now: Instant, error: LinkError, effects: MutableList<LinkEffect>) {
        // A pin mismatch counts ONCE per round, and only when no host of the round did anything else: a stale
        // address now owned by another device must not drive the link to Suspended / NeedsRepair on its own.
        val pinRound = roundAttempts > 0 && roundPinMismatches == roundAttempts
        roundAttempts = 0
        roundPinMismatches = 0
        if (pinRound) {
            pinMismatches++
            if (pinMismatches >= config.pinMismatchesForSuspend) {
                // The first time: wait an hour. If the mismatch persists after that, the identity change is confirmed.
                if (suspensions >= 1) enterIdentityChanged(effects) else enterSuspended(now, effects)
                return
            }
            persistCounters(effects)
        }
        failures++
        scheduleRetry(now, error, effects)
    }

    /** A connection that had been established was lost. */
    private fun connectionLost(now: Instant, error: LinkError, effects: MutableList<LinkEffect>) {
        activeConn = null
        failures = 1
        scheduleRetry(now, error, effects)
    }

    private fun scheduleRetry(now: Instant, error: LinkError, effects: MutableList<LinkEffect>) {
        val at = now.plus(backoff.delay(failures))
        nextRetryAt = at
        if (failures >= config.unreachableAfterRounds) {
            val since = unreachableSince ?: now
            unreachableSince = since
            state = LinkState.PcUnreachable(since)
        } else {
            state = LinkState.Reconnecting(failures, at, error)
        }
        effects += LinkEffect.ScheduleWake(at)
    }

    // ---------------------------------------------------------------------------------------------
    // Terminal / blocking states
    // ---------------------------------------------------------------------------------------------

    private fun enterRevoked(code: String, effects: MutableList<LinkEffect>) {
        if (activeConn != null) effects += LinkEffect.AbortSocket
        activeConn = null
        nextRetryAt = null
        state = LinkState.Revoked(code)
        effects += LinkEffect.WipeDeviceToken
        effects += LinkEffect.SecurityAlert(SecurityAlertKind.DEVICE_REVOKED)
    }

    private fun enterIncompatible(effects: MutableList<LinkEffect>) {
        if (activeConn != null) effects += LinkEffect.AbortSocket
        activeConn = null
        nextRetryAt = null
        state = LinkState.Incompatible
    }

    private fun enterNeedsRepair(reason: RepairReason, effects: MutableList<LinkEffect>) {
        if (activeConn != null) effects += LinkEffect.AbortSocket
        activeConn = null
        nextRetryAt = null
        state = LinkState.NeedsRepair(reason)
        needsRepairReason = reason
        persistCounters(effects)
        effects += LinkEffect.SecurityAlert(SecurityAlertKind.REPEATED_AUTH_FAILURE)
    }

    private fun enterIdentityChanged(effects: MutableList<LinkEffect>) {
        if (activeConn != null) effects += LinkEffect.AbortSocket
        activeConn = null
        nextRetryAt = null
        state = LinkState.NeedsRepair(RepairReason.IDENTITY_CHANGED)
        needsRepairReason = RepairReason.IDENTITY_CHANGED
        persistCounters(effects)
        effects += LinkEffect.SecurityAlert(SecurityAlertKind.PC_IDENTITY_CHANGED)
    }

    private fun enterSuspended(now: Instant, effects: MutableList<LinkEffect>) {
        if (activeConn != null) effects += LinkEffect.AbortSocket
        activeConn = null
        suspensions++
        val until = now.plus(config.pinSuspension)
        nextRetryAt = until
        suspendedUntil = until
        state = LinkState.Suspended(until)
        persistCounters(effects)
        effects += LinkEffect.SecurityAlert(SecurityAlertKind.PC_IDENTITY_CHANGED)
        effects += LinkEffect.ScheduleWake(until)
    }

    /** Counts one authentication failure per connection (the error frame and the 4002 close are the same event). */
    private fun countAuthFailure(effects: MutableList<LinkEffect>) {
        if (authFailedThisConnection) return
        authFailedThisConnection = true
        authFailures++
        persistCounters(effects)
        if (authFailures >= config.authFailuresForRepair) enterNeedsRepair(RepairReason.AUTH_FAILED, effects)
    }

    // ---------------------------------------------------------------------------------------------
    // Socket events
    // ---------------------------------------------------------------------------------------------

    private fun onNetworkLost(effects: MutableList<LinkEffect>) {
        when (state) {
            is LinkState.Connecting, LinkState.Challenged, is LinkState.Connected,
            is LinkState.Reconnecting, is LinkState.PcUnreachable,
            -> {
                if (activeConn != null) effects += LinkEffect.AbortSocket
                activeConn = null
                nextRetryAt = null
                state = LinkState.Offline
            }
            else -> Unit
        }
    }

    private fun onSocketClosed(code: Int, now: Instant, effects: MutableList<LinkEffect>) {
        val wasConnected = state is LinkState.Connected
        when {
            state !is LinkState.Connecting && state != LinkState.Challenged && !wasConnected -> return
            code == CLOSE_REVOKED -> enterRevoked(code.toString(), effects)
            code == CLOSE_INCOMPATIBLE -> enterIncompatible(effects)
            code == CLOSE_AUTH_FAILED -> {
                countAuthFailure(effects)
                if (state !is LinkState.NeedsRepair) {
                    activeConn = null
                    roundAttempts++ // an auth failure is not a pin mismatch: this round no longer counts as one
                    roundFailed(now, LinkError.AuthFailed, effects)
                }
            }
            wasConnected -> connectionLost(now, closeError(code), effects)
            else -> attemptFailed(now, closeError(code), effects)
        }
    }

    private fun closeError(code: Int): LinkError = when (code) {
        CLOSE_SUPERSEDED -> LinkError.Superseded
        CLOSE_RATE_LIMITED -> LinkError.RateLimited
        CLOSE_HEARTBEAT -> LinkError.HeartbeatTimeout
        CLOSE_PROTOCOL -> LinkError.ProtocolViolation
        else -> LinkError.ServerClosed(code)
    }

    private fun onSocketFailed(failure: TransportFailure, now: Instant, effects: MutableList<LinkEffect>) {
        val wasConnected = state is LinkState.Connected
        if (!wasConnected && state !is LinkState.Connecting && state != LinkState.Challenged) return
        val error = when (failure.kind) {
            TransportFailureKind.PIN_MISMATCH -> LinkError.PinMismatch
            TransportFailureKind.TLS -> LinkError.Tls
            TransportFailureKind.PROTOCOL -> LinkError.ProtocolViolation
            TransportFailureKind.UNREACHABLE -> LinkError.Unreachable
        }
        if (wasConnected) connectionLost(now, error, effects) else attemptFailed(now, error, effects)
    }

    // ---------------------------------------------------------------------------------------------
    // Frames
    // ---------------------------------------------------------------------------------------------

    private fun onFrame(event: LinkEvent.FrameReceived, now: Instant, effects: MutableList<LinkEffect>) {
        lastReceivedAt = now
        when (val message = event.message) {
            is ChallengeMessage -> if (state is LinkState.Connecting) onChallenge(message, now, effects)
            is WelcomeMessage -> if (state == LinkState.Challenged) onWelcome(message, now, effects)
            is PongMessage -> onPong(message, now)
            is HostsUpdateMessage -> if (state is LinkState.Connected) {
                hosts = hosts.withWelcomeHosts(message.payload.addresses, message.payload.port)
                effects += LinkEffect.PersistHosts(hosts)
            }
            is ErrorMessage -> onError(message, now, effects)
            is ByeMessage -> onBye(message, now, effects)
            else -> Unit
        }
    }

    private fun onChallenge(message: ChallengeMessage, now: Instant, effects: MutableList<LinkEffect>) {
        val creds = credentials()
        if (creds == null) {
            // Nothing to authenticate with: the pairing was wiped. Stop cleanly.
            effects += LinkEffect.CloseSocket(CLOSE_NORMAL, "no credentials")
            activeConn = null
            state = LinkState.Unpaired
            return
        }
        state = LinkState.Challenged
        phaseStartedAt = now
        val hello = HelloMessage(
            meta(now),
            HelloPayload(
                deviceId = creds.deviceId,
                deviceToken = creds.deviceToken,
                challengeB64 = message.payload.challengeB64,
                protocol = 1,
                appVersion = config.appVersion,
                lastSeq = lastSeq(),
                wantsSnapshot = false,
            ),
        )
        send(hello, now, effects)
        effects += LinkEffect.ScheduleWake(now.plus(config.handshakeTimeout))
    }

    private fun onWelcome(message: WelcomeMessage, now: Instant, effects: MutableList<LinkEffect>) {
        state = LinkState.Connected(message.payload.pc, now, null)
        failures = 0
        resetCounters(effects)
        unreachableSince = null
        nextRetryAt = null
        lastAckedSeq = lastSeq()
        lastAckAt = now
        var updated = hosts.withSuccess(currentHost)
        message.payload.hosts?.let { updated = updated.withWelcomeHosts(it.addresses, it.port) }
        hosts = updated
        effects += LinkEffect.PersistHosts(updated)
    }

    private fun onPong(message: PongMessage, now: Instant) {
        val current = state as? LinkState.Connected ?: return
        val sentAt = pingSentAt
        if (message.payload.inReplyTo != null && message.payload.inReplyTo == pingId && sentAt != null) {
            val rtt = Duration.between(sentAt, now).toMillis().coerceIn(0, Int.MAX_VALUE.toLong()).toInt()
            state = current.copy(rttMs = rtt)
            pingId = null
            pingSentAt = null
        }
    }

    private fun onError(message: ErrorMessage, now: Instant, effects: MutableList<LinkEffect>) {
        if (state !is LinkState.Connecting && state != LinkState.Challenged) {
            if (message.payload.errorCode == ErrorCode.E_DEVICE_REVOKED) enterRevoked(ErrorCode.E_DEVICE_REVOKED.wire, effects)
            return
        }
        when (message.payload.errorCode) {
            ErrorCode.E_AUTH_FAILED -> countAuthFailure(effects)
            ErrorCode.E_DEVICE_REVOKED -> enterRevoked(ErrorCode.E_DEVICE_REVOKED.wire, effects)
            ErrorCode.E_PROTO_VERSION -> enterIncompatible(effects)
            else -> Unit
        }
    }

    private fun onBye(message: ByeMessage, now: Instant, effects: MutableList<LinkEffect>) {
        val bye = message.payload
        when (bye.reason) {
            ByeReason.DEVICE_REVOKED, ByeReason.UNPAIRED -> enterRevoked(bye.reason.wire, effects)
            ByeReason.SHUTDOWN -> {
                effects += LinkEffect.CloseSocket(CLOSE_NORMAL, "bye")
                if (bye.reconnect) {
                    connectionLost(now, LinkError.PcShutdown(bye.messageKo), effects)
                } else {
                    activeConn = null
                    failures = 1
                    val at = now.plus(config.pcShutdownRetry)
                    nextRetryAt = at
                    state = LinkState.Reconnecting(failures, at, LinkError.PcShutdown(bye.messageKo))
                    effects += LinkEffect.ScheduleWake(at)
                }
            }
            ByeReason.SUPERSEDED_CONNECTION -> {
                effects += LinkEffect.CloseSocket(CLOSE_NORMAL, "bye")
                connectionLost(now, LinkError.Superseded, effects)
            }
            ByeReason.RESTART, ByeReason.UNKNOWN -> {
                effects += LinkEffect.CloseSocket(CLOSE_NORMAL, "bye")
                connectionLost(now, LinkError.ServerClosed(CLOSE_SERVER_RESTART), effects)
            }
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Timers
    // ---------------------------------------------------------------------------------------------

    private fun onTick(now: Instant, effects: MutableList<LinkEffect>) {
        when (val current = state) {
            is LinkState.Reconnecting, is LinkState.PcUnreachable -> {
                val at = nextRetryAt
                if (at != null && !now.isBefore(at)) beginRound(now, effects)
            }
            is LinkState.Suspended -> if (!now.isBefore(current.until)) {
                pinMismatches = 0
                suspendedUntil = null
                persistCounters(effects)
                startFresh(now, effects)
            }
            is LinkState.Connecting, LinkState.Challenged -> {
                if (Duration.between(phaseStartedAt, now) >= config.handshakeTimeout) {
                    effects += LinkEffect.AbortSocket
                    attemptFailed(now, LinkError.HandshakeTimeout, effects)
                }
            }
            is LinkState.Connected -> connectedTick(now, effects)
            else -> Unit
        }
    }

    private fun connectedTick(now: Instant, effects: MutableList<LinkEffect>) {
        if (Duration.between(lastReceivedAt, now) > config.silenceTimeout) {
            effects += LinkEffect.AbortSocket
            connectionLost(now, LinkError.HeartbeatTimeout, effects)
            return
        }
        val seq = lastSeq()
        if (seq > lastAckedSeq && Duration.between(lastAckAt, now) >= config.ackBatchInterval) {
            send(AckMessage(meta(now), AckPayload(throughSeq = seq)), now, effects)
            lastAckedSeq = seq
            lastAckAt = now
        }
        if (Duration.between(lastSentAt, now) >= config.pingInterval) {
            val ping = PingMessage(meta(now), PingPayload(Ts.of(now)))
            pingId = ping.meta.id
            pingSentAt = now
            send(ping, now, effects)
        }
    }

    // ---------------------------------------------------------------------------------------------
    // User actions
    // ---------------------------------------------------------------------------------------------

    private fun onUserRepair(effects: MutableList<LinkEffect>) {
        if (activeConn != null) effects += LinkEffect.AbortSocket
        activeConn = null
        nextRetryAt = null
        failures = 0
        unreachableSince = null
        hosts = HostBookState()
        state = LinkState.Unpaired
        effects += LinkEffect.WipePairing
        effects += LinkEffect.PersistHosts(hosts)
        resetCounters(effects)
    }

    private fun onUserUnpair(now: Instant, effects: MutableList<LinkEffect>) {
        val creds = credentials()
        if (state is LinkState.Connected && creds != null) {
            send(UnpairMessage(meta(now), UnpairPayload(deviceId = creds.deviceId)), now, effects)
            effects += LinkEffect.CloseSocket(CLOSE_NORMAL, "unpair")
        } else if (activeConn != null) {
            effects += LinkEffect.AbortSocket
        }
        activeConn = null
        nextRetryAt = null
        hosts = HostBookState()
        state = LinkState.Unpaired
        effects += LinkEffect.WipePairing
        effects += LinkEffect.PersistHosts(hosts)
        resetCounters(effects)
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------

    private fun meta(now: Instant) = FrameMeta(ids(), Ts.of(now))

    private fun currentCounters() = LinkCounters(authFailures, pinMismatches, suspensions, suspendedUntil, needsRepairReason)

    /** Emits [LinkEffect.PersistCounters] when the counters differ from what was last handed to the app. */
    private fun persistCounters(effects: MutableList<LinkEffect>) {
        val now = currentCounters()
        if (now == persisted) return
        persisted = now
        effects += LinkEffect.PersistCounters(now)
    }

    private fun resetCounters(effects: MutableList<LinkEffect>) {
        authFailures = 0
        pinMismatches = 0
        suspensions = 0
        suspendedUntil = null
        needsRepairReason = null
        persistCounters(effects)
    }

    private fun send(message: dev.agentnest.core.protocol.ClientMessage, now: Instant, effects: MutableList<LinkEffect>) {
        lastSentAt = now
        effects += LinkEffect.Send(message)
    }

    companion object {
        const val CLOSE_NORMAL = 1000
        const val CLOSE_SERVER_RESTART = 1012
        const val CLOSE_PRE_AUTH_TIMEOUT = 4001
        const val CLOSE_AUTH_FAILED = 4002
        const val CLOSE_REVOKED = 4003
        const val CLOSE_PROTOCOL = 4004
        const val CLOSE_RATE_LIMITED = 4005
        const val CLOSE_HEARTBEAT = 4008
        const val CLOSE_SUPERSEDED = 4009
        const val CLOSE_INCOMPATIBLE = 4010
    }
}
