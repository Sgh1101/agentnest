package dev.agentnest.core.protocol

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonObject

// Wire models that are shared by several messages. Property names are camelCase; the codec applies the
// snake_case naming strategy, so `requestId` <-> "request_id". Everything here mirrors docs/protocol.md.

/** Project reference carried by sessions, events and approval cards. */
@Serializable
data class Project(
    val projectKey: String = "",
    val name: String = "",
    val pathHint: String? = null,
    val repo: String? = null,
    val branch: String? = null,
)

/** Sub-agent / teammate context of an event. */
@Serializable
data class Actor(
    val agentId: String? = null,
    val agentType: String? = null,
    val isSubagent: Boolean = false,
)

/** Korean summary built by the PC. The phone never rewrites it. */
@Serializable
data class Summary(
    val headline: String = "",
    val detail: String? = null,
)

/** Where an event came from; `nativeIds` is used to correlate and de-duplicate (e.g. `request_id`). */
@Serializable
data class EventSource(
    val channel: String = "",
    val nativeEvent: String? = null,
    val nativeIds: Map<String, String> = emptyMap(),
)

/** Normalised agent event (protocol.md 5.1). `detail` is a bounded kind-specific object kept as raw JSON. */
@Serializable
data class AgentEvent(
    val eventId: String,
    val seq: Long,
    val ts: Ts,
    val agentKind: AgentKind,
    val sessionKey: String,
    val actor: Actor? = null,
    val project: Project? = null,
    val kind: EventKind,
    val category: EventCategory = EventCategory.UNKNOWN,
    val severity: Severity = Severity.INFO,
    val summary: Summary = Summary(),
    val stateHint: AgentState? = null,
    val detail: JsonObject? = null,
    val source: EventSource = EventSource(),
    val redacted: Boolean = false,
) {
    /** Timeline de-duplication key for the three timeline-only kinds: `(kind, native_ids.request_id)`. */
    val timelineKey: String
        get() = source.nativeIds["request_id"]?.let { "${kind.wire}:$it" } ?: "event:$eventId"
}

@Serializable
data class TurnInfo(
    val active: Boolean = false,
    val startedAt: Ts? = null,
    val completedAt: Ts? = null,
    val promptPreview: String? = null,
)

@Serializable
data class Counters(
    val tools: Int = 0,
    val filesModified: Int = 0,
    val commands: Int = 0,
    val tests: Int = 0,
    val errors: Int = 0,
)

@Serializable
data class RecentFile(val pathHint: String = "", val op: String = "", val at: Ts? = null)

@Serializable
data class RecentCommand(
    val commandPreview: String = "",
    val commandClass: String = "",
    val exitCode: Int? = null,
    val at: Ts? = null,
)

@Serializable
data class LastTest(
    val status: TestStatus = TestStatus.UNKNOWN,
    val commandClass: String? = null,
    val runner: String? = null,
    val at: Ts? = null,
)

@Serializable
data class ReviewInfo(
    val p0: Int = 0,
    val p1: Int = 0,
    val state: ReviewState = ReviewState.UNAVAILABLE,
)

@Serializable
data class SessionMeta(
    val title: String? = null,
    val model: String? = null,
    val costUsd: Double? = null,
    val contextUsedPct: Double? = null,
    val review: ReviewInfo? = null,
)

/**
 * Per-session derived state computed by the PC (protocol.md 5.3). A missing or unknown `remote_approval`
 * decodes to [RemoteApproval.UNKNOWN] which the UI renders like `unavailable`.
 */
@Serializable
data class SessionState(
    val sessionKey: String,
    val agentKind: AgentKind,
    val agentLabel: String = "",
    val project: Project = Project(),
    val state: AgentState,
    val stateSince: Ts? = null,
    val headline: String = "",
    val detail: String? = null,
    val startedAt: Ts? = null,
    val turn: TurnInfo = TurnInfo(),
    val permissionMode: String? = null,
    val remoteApproval: RemoteApproval = RemoteApproval.UNKNOWN,
    val pendingApprovalIds: List<String> = emptyList(),
    val counters: Counters,
    val recentFiles: List<RecentFile> = emptyList(),
    val recentCommands: List<RecentCommand> = emptyList(),
    val lastTest: LastTest? = null,
    val meta: SessionMeta = SessionMeta(),
    val lastEventSeq: Long = 0,
    val lastEventAt: Ts? = null,
    val ended: Boolean = false,
    val stale: Boolean = false,
)

/** Decodes a list of decisions and silently drops values this build does not know (no button for them). */
object KnownDecisionListSerializer : KSerializer<List<Decision>> {
    private val delegate = ListSerializer(DecisionSerializer)
    override val descriptor: SerialDescriptor = delegate.descriptor
    override fun deserialize(decoder: Decoder): List<Decision> =
        delegate.deserialize(decoder).filter { it != Decision.UNKNOWN }

    override fun serialize(encoder: Encoder, value: List<Decision>) = delegate.serialize(encoder, value)
}

/** Bounded, display-only details of an approval card (protocol.md 6.1). */
@Serializable
data class ApprovalDetails(
    val kind: DetailsKind = DetailsKind.OTHER,
    val command: String? = null,
    val cwdHint: String? = null,
    val filePaths: List<String> = emptyList(),
    val diffPreview: String? = null,
    val contentPreview: String? = null,
    val mcpServer: String? = null,
    val reason: String? = null,
    val truncated: Boolean = false,
    val permissionSuggestionsCount: Int = 0,
)

@Serializable
data class RiskInfo(
    val level: RiskLevel,
    val reasons: List<String> = emptyList(),
    val reasonsKo: List<String> = emptyList(),
    val extraConfirmation: ExtraConfirmationLevel = ExtraConfirmationLevel.NONE,
)

/**
 * Approval card sent by the PC (protocol.md 6.1). The phone echoes `requestId`, `sessionKey`, `nonceB64`
 * and `toolInputSha256` in its decision and never computes the hash itself.
 * [purpose] is agent-written, unverified text: UI must label it as such and never use it to justify an allow.
 */
@Serializable
data class ApprovalRequest(
    val requestId: String,
    val nonceB64: String,
    val sessionKey: String,
    val agentKind: AgentKind = AgentKind.UNKNOWN,
    val agentLabel: String = "",
    val project: Project = Project(),
    val origin: String = "",
    val createdAt: Ts,
    val expiresAt: Ts,
    val ttlSeconds: Int = 0,
    val toolName: String = "",
    val title: String = "",
    val purpose: String? = null,
    val details: ApprovalDetails = ApprovalDetails(),
    val toolInputSha256: String,
    val risk: RiskInfo,
    @Serializable(with = KnownDecisionListSerializer::class)
    val allowedDecisions: List<Decision> = emptyList(),
    @Serializable(with = KnownDecisionListSerializer::class)
    val authRequiredFor: List<Decision> = listOf(Decision.ALLOW, Decision.DENY_AND_STOP),
    val permissionMode: String? = null,
    val localPrompt: LocalPrompt = LocalPrompt.UNDETERMINED,
) {
    /** True when [origin] is the Codex hooks channel, where `deny_and_stop` can never be offered. */
    val isCodexHooksOrigin: Boolean get() = origin == "codex.hook.cli"
}

@Serializable
data class AdapterStatusPayload(
    val agentKind: AgentKind,
    val status: AdapterStatusKind,
    val mode: AdapterMode = AdapterMode.NONE,
    val detail: String? = null,
    val updatedAt: Ts? = null,
)

@Serializable
data class FocusInfo(val sessionKey: String, val state: AgentState = AgentState.UNKNOWN)

@Serializable
data class SnapshotTruncated(
    val sessions: Boolean = false,
    val pendingApprovals: Boolean = false,
    val recentEvents: Boolean = false,
    val recentEventsDetail: Boolean = false,
    val approvalPreviews: Boolean = false,
)

/** PC identity as shown to the user. */
@Serializable
data class PcInfo(
    val pcId: String,
    val name: String = "",
    val appVersion: String = "",
    val os: String? = null,
)

@Serializable
data class ProtocolInfo(val version: Int = 1, val minor: Int = 0, val minClientVersion: String? = null)

@Serializable
data class HostsInfo(val addresses: List<String> = emptyList(), val port: Int = 47832)

@Serializable
data class HeartbeatInfo(val clientPingIntervalS: Int = 30, val serverIdleCloseS: Int = 90)

@Serializable
data class Resync(
    val mode: ResyncMode = ResyncMode.SNAPSHOT,
    val fromSeq: Long? = null,
    val toSeq: Long? = null,
)

@Serializable
data class Limits(
    val approvalTtlS: Int = 120,
    val maxFrameBytes: Int = 262_144,
    val snapshotMaxBytes: Int = 196_608,
    val eventsPageMaxBytes: Int = 196_608,
)

/**
 * Server policy surfaced read-only on the phone. `denyRequiresAuth` is owned by the PC settings and the
 * phone has no local toggle for it.
 */
@Serializable
data class Policy(
    val remoteApproval: Map<String, String> = emptyMap(),
    val denyRequiresAuth: Boolean = false,
)

/** Device description sent while pairing. */
@Serializable
data class DeviceInfo(
    val name: String,
    val platform: String = "android",
    val model: String? = null,
    val osVersion: String? = null,
    val appVersion: String? = null,
)

/** The phone's claim that the user authenticated (protocol.md 4.10; a claim, not proof, in Phase 1). */
@Serializable
data class AuthClaim(
    val method: AuthMethod,
    val authenticatedAt: Ts? = null,
)

/** The phone's claim that the extra-confirmation gate (hold / re-confirm sheet) was completed. */
@Serializable
data class ExtraConfirmationClaim(
    val method: ExtraConfirmationLevel,
    val completed: Boolean,
)
