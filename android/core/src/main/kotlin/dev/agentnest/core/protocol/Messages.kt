package dev.agentnest.core.protocol

import kotlinx.serialization.Serializable

// Payloads and typed messages of the wire protocol v1 (docs/protocol.md sections 3-4).
// Secrets (tokens, nonces, HMAC proofs) are redacted from toString() so they can never reach a log line.

/** Envelope metadata shared by every message. [seq] is present only on replayable server messages. */
data class FrameMeta(val id: String, val ts: Ts, val seq: Long? = null)

// ---------------------------------------------------------------------------------------------------
// Phone -> PC payloads
// ---------------------------------------------------------------------------------------------------

@Serializable
data class PairPayload(
    val pairingId: String,
    val challengeB64: String,
    val device: DeviceInfo,
    val devicePubkeySpkiB64: String? = null,
    val proofB64: String,
    val protocol: Int = 1,
) {
    override fun toString(): String = "PairPayload(pairingId=$pairingId, device=${device.name}, proof=<redacted>)"
}

@Serializable
data class HelloPayload(
    val deviceId: String,
    val deviceToken: String,
    val challengeB64: String,
    val protocol: Int = 1,
    val appVersion: String? = null,
    val lastSeq: Long = 0,
    val wantsSnapshot: Boolean = false,
) {
    override fun toString(): String = "HelloPayload(deviceId=$deviceId, lastSeq=$lastSeq, token=<redacted>)"
}

@Serializable
data class AckPayload(
    val throughSeq: Long? = null,
    val approvalIds: List<String> = emptyList(),
)

@Serializable
data class PingPayload(val sentAt: Ts)

@Serializable
data class SnapshotRequestPayload(val reason: String? = null)

@Serializable
data class EventsRequestPayload(
    val sessionKey: String? = null,
    val beforeSeq: Long,
    val limit: Int = 50,
    val kinds: List<EventKind>? = null,
)

/** A decision. All four binding fields are echoed verbatim from the [ApprovalRequest]. */
@Serializable
data class DecisionPayload(
    val requestId: String,
    val sessionKey: String,
    val nonceB64: String,
    val toolInputSha256: String,
    val decision: Decision,
    val reason: String? = null,
    val decidedAt: Ts,
    val auth: AuthClaim? = null,
    val extraConfirmation: ExtraConfirmationClaim? = null,
) {
    override fun toString(): String =
        "DecisionPayload(requestId=$requestId, decision=${decision.wire}, auth=${auth?.method?.wire})"
}

@Serializable
data class ApprovalSeenPayload(val requestId: String, val seenAt: Ts)

/** Either [deviceId] (unpair this device) or [pairingId] (abort a pairing in `PairPending`). */
@Serializable
data class UnpairPayload(val deviceId: String? = null, val pairingId: String? = null)

// ---------------------------------------------------------------------------------------------------
// PC -> phone payloads
// ---------------------------------------------------------------------------------------------------

@Serializable
data class ChallengePayload(
    val challengeB64: String,
    val pcId: String,
    val serverTime: Ts,
    val expiresInMs: Long = 5000,
)

@Serializable
data class PairPendingPayload(
    val pairingId: String,
    val sas: String,
    val confirmTimeoutMs: Long = 60_000,
)

@Serializable
data class PairResultPayload(
    val ok: Boolean,
    val deviceId: String? = null,
    val deviceToken: String? = null,
    val pc: PcInfo? = null,
    val errorCode: String? = null,
) {
    override fun toString(): String = "PairResultPayload(ok=$ok, deviceId=$deviceId, errorCode=$errorCode, token=<redacted>)"
}

@Serializable
data class WelcomePayload(
    val pc: PcInfo,
    val protocol: ProtocolInfo = ProtocolInfo(),
    val hosts: HostsInfo? = null,
    val capabilities: List<String>,
    val serverTime: Ts,
    val heartbeat: HeartbeatInfo = HeartbeatInfo(),
    val resync: Resync,
    val limits: Limits,
    val policy: Policy,
) {
    /** True when the PC advertises [capability] (the phone hides UI for missing capabilities). */
    fun has(capability: String): Boolean = capability in capabilities
}

@Serializable
data class SnapshotPayload(
    val sessions: List<SessionState> = emptyList(),
    val pendingApprovals: List<ApprovalRequest> = emptyList(),
    val recentErrors: List<AgentEvent> = emptyList(),
    val recentEvents: List<AgentEvent> = emptyList(),
    val adapters: List<AdapterStatusPayload> = emptyList(),
    val focus: FocusInfo? = null,
    val pendingApprovalIdsComplete: List<String>,
    val pendingFollowup: Int = 0,
    val truncated: SnapshotTruncated,
)

@Serializable
data class DecisionResultPayload(
    val requestId: String,
    val inReplyTo: String? = null,
    val accepted: Boolean,
    val reason: DecisionResultReason = DecisionResultReason.UNKNOWN,
    val messageKo: String? = null,
)

@Serializable
data class ApprovalResolvedPayload(
    val requestId: String,
    val sessionKey: String = "",
    val outcome: ApprovalOutcome = ApprovalOutcome.UNKNOWN,
    val resolvedBy: ResolvedBy = ResolvedBy.UNKNOWN,
    val resolvedDeviceId: String? = null,
    val resolvedAt: Ts? = null,
    val delivery: Delivery,
    val observedResult: ObservedResult = ObservedResult.NOT_YET_KNOWN,
    val messageKo: String? = null,
)

@Serializable
data class EventsPagePayload(
    val inReplyTo: String? = null,
    val events: List<AgentEvent> = emptyList(),
    val hasMore: Boolean = false,
    val nextBeforeSeq: Long? = null,
    val detailOmitted: Boolean = false,
)

@Serializable
data class HostsUpdatePayload(val addresses: List<String> = emptyList(), val port: Int = 47832)

@Serializable
data class PongPayload(val inReplyTo: String? = null, val serverTime: Ts? = null)

@Serializable
data class ErrorPayload(
    val code: String,
    val message: String? = null,
    val messageKo: String? = null,
    val inReplyTo: String? = null,
    val fatal: Boolean = false,
) {
    /** Typed view of [code]; unknown codes map to [ErrorCode.UNKNOWN]. */
    val errorCode: ErrorCode get() = ErrorCode.entries.firstOrNull { it != ErrorCode.UNKNOWN && it.wire == code } ?: ErrorCode.UNKNOWN
}

@Serializable
data class ByePayload(
    val reason: ByeReason = ByeReason.UNKNOWN,
    val reconnect: Boolean = true,
    val messageKo: String? = null,
)

// ---------------------------------------------------------------------------------------------------
// Typed messages
// ---------------------------------------------------------------------------------------------------

/** Any decoded protocol message (either direction). */
sealed interface WireMessage {
    val meta: FrameMeta

    /** The wire `type` string. */
    val type: String
}

/** A message sent by the PC. */
sealed interface ServerMessage : WireMessage

/** A message sent by the phone. */
sealed interface ClientMessage : WireMessage

// --- server -> client

data class ChallengeMessage(override val meta: FrameMeta, val payload: ChallengePayload) : ServerMessage {
    override val type get() = "challenge"
}

data class PairPendingMessage(override val meta: FrameMeta, val payload: PairPendingPayload) : ServerMessage {
    override val type get() = "pair_pending"
}

data class PairResultMessage(override val meta: FrameMeta, val payload: PairResultPayload) : ServerMessage {
    override val type get() = "pair_result"
}

data class WelcomeMessage(override val meta: FrameMeta, val payload: WelcomePayload) : ServerMessage {
    override val type get() = "welcome"
}

data class SnapshotMessage(override val meta: FrameMeta, val payload: SnapshotPayload) : ServerMessage {
    override val type get() = "snapshot"
}

data class EventMessage(override val meta: FrameMeta, val payload: AgentEvent) : ServerMessage {
    override val type get() = "event"
}

data class SessionStateMessage(override val meta: FrameMeta, val payload: SessionState) : ServerMessage {
    override val type get() = "session_state"
}

data class ApprovalRequestMessage(override val meta: FrameMeta, val payload: ApprovalRequest) : ServerMessage {
    override val type get() = "approval_request"
}

data class ApprovalResolvedMessage(override val meta: FrameMeta, val payload: ApprovalResolvedPayload) : ServerMessage {
    override val type get() = "approval_resolved"
}

data class DecisionResultMessage(override val meta: FrameMeta, val payload: DecisionResultPayload) : ServerMessage {
    override val type get() = "decision_result"
}

data class EventsPageMessage(override val meta: FrameMeta, val payload: EventsPagePayload) : ServerMessage {
    override val type get() = "events_page"
}

data class HostsUpdateMessage(override val meta: FrameMeta, val payload: HostsUpdatePayload) : ServerMessage {
    override val type get() = "hosts_update"
}

data class AdapterStatusMessage(override val meta: FrameMeta, val payload: AdapterStatusPayload) : ServerMessage {
    override val type get() = "adapter_status"
}

data class PongMessage(override val meta: FrameMeta, val payload: PongPayload) : ServerMessage {
    override val type get() = "pong"
}

data class ErrorMessage(override val meta: FrameMeta, val payload: ErrorPayload) : ServerMessage {
    override val type get() = "error"
}

data class ByeMessage(override val meta: FrameMeta, val payload: ByePayload) : ServerMessage {
    override val type get() = "bye"
}

// --- client -> server

data class PairMessage(override val meta: FrameMeta, val payload: PairPayload) : ClientMessage {
    override val type get() = "pair"
}

data class HelloMessage(override val meta: FrameMeta, val payload: HelloPayload) : ClientMessage {
    override val type get() = "hello"
}

data class AckMessage(override val meta: FrameMeta, val payload: AckPayload) : ClientMessage {
    override val type get() = "ack"
}

data class PingMessage(override val meta: FrameMeta, val payload: PingPayload) : ClientMessage {
    override val type get() = "ping"
}

data class SnapshotRequestMessage(override val meta: FrameMeta, val payload: SnapshotRequestPayload) : ClientMessage {
    override val type get() = "snapshot_request"
}

data class EventsRequestMessage(override val meta: FrameMeta, val payload: EventsRequestPayload) : ClientMessage {
    override val type get() = "events_request"
}

data class DecisionMessage(override val meta: FrameMeta, val payload: DecisionPayload) : ClientMessage {
    override val type get() = "decision"
}

data class ApprovalSeenMessage(override val meta: FrameMeta, val payload: ApprovalSeenPayload) : ClientMessage {
    override val type get() = "approval_seen"
}

data class UnpairMessage(override val meta: FrameMeta, val payload: UnpairPayload) : ClientMessage {
    override val type get() = "unpair"
}
