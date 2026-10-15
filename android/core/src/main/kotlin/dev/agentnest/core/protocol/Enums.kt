package dev.agentnest.core.protocol

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/** An enum whose JSON representation is a fixed snake_case string. */
interface WireEnum {
    val wire: String
}

/**
 * Serializer for forward-compatible enums (protocol.md section 10): unknown wire values decode to
 * [unknown]. Encoding [unknown] is refused when [encodeUnknown] is false (everything the phone SENDS),
 * so an unrecognised value can never be put on the wire.
 */
abstract class WireEnumSerializer<E>(
    name: String,
    private val entries: List<E>,
    private val unknown: E,
    private val encodeUnknown: Boolean = true,
) : KSerializer<E> where E : Enum<E>, E : WireEnum {
    override val descriptor = PrimitiveSerialDescriptor(name, PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): E {
        val text = decoder.decodeString()
        return entries.firstOrNull { it !== unknown && it.wire == text } ?: unknown
    }

    override fun serialize(encoder: Encoder, value: E) {
        if (value === unknown && !encodeUnknown) throw SerializationException("refusing to encode unknown enum value")
        encoder.encodeString(value.wire)
    }
}

@Serializable(with = AgentKindSerializer::class)
enum class AgentKind(override val wire: String) : WireEnum {
    CLAUDE_CODE("claude_code"), CODEX("codex"), GEMINI_CLI("gemini_cli"), OPENCODE("opencode"), OTHER("other"),
    UNKNOWN("unknown");

    /** Short Korean-friendly product name used in the home headline ("Claude가 ..."). */
    val shortName: String
        get() = when (this) {
            CLAUDE_CODE -> "Claude"
            CODEX -> "Codex"
            GEMINI_CLI -> "Gemini"
            OPENCODE -> "OpenCode"
            else -> "AI"
        }
}

object AgentKindSerializer : WireEnumSerializer<AgentKind>("AgentKind", AgentKind.entries, AgentKind.UNKNOWN)

/** Normalised session state (protocol.md 5.4). Unknown values render as [WORKING] (see [effective]). */
@Serializable(with = AgentStateSerializer::class)
enum class AgentState(override val wire: String) : WireEnum {
    IDLE("idle"), WORKING("working"), WRITING_CODE("writing_code"), REVIEWING("reviewing"), TESTING("testing"),
    AWAITING_APPROVAL("awaiting_approval"), AWAITING_INPUT("awaiting_input"), ERROR("error"),
    COMPLETED("completed"), DISCONNECTED("disconnected"),
    UNKNOWN("unknown");

    /** protocol.md section 10: an unknown state is rendered as [WORKING]. */
    val effective: AgentState get() = if (this == UNKNOWN) WORKING else this
}

object AgentStateSerializer : WireEnumSerializer<AgentState>("AgentState", AgentState.entries, AgentState.UNKNOWN)

@Serializable(with = EventCategorySerializer::class)
enum class EventCategory(override val wire: String) : WireEnum {
    LIFECYCLE("lifecycle"), TURN("turn"), TOOL("tool"), FILE("file"), COMMAND("command"), APPROVAL("approval"),
    ERROR("error"), REVIEW("review"), NOTIFICATION("notification"), USAGE("usage"), ADAPTER("adapter"),
    UNKNOWN("unknown"),
}

object EventCategorySerializer :
    WireEnumSerializer<EventCategory>("EventCategory", EventCategory.entries, EventCategory.UNKNOWN)

@Serializable(with = SeveritySerializer::class)
enum class Severity(override val wire: String) : WireEnum {
    DEBUG("debug"), INFO("info"), NOTICE("notice"), WARNING("warning"), ERROR("error"), UNKNOWN("unknown"),
}

object SeveritySerializer : WireEnumSerializer<Severity>("Severity", Severity.entries, Severity.UNKNOWN)

/** AgentEvent.kind (protocol.md 5.2). Unknown kinds show up as "기타" in timelines and never change state. */
@Serializable(with = EventKindSerializer::class)
enum class EventKind(override val wire: String) : WireEnum {
    SESSION_STARTED("session_started"), SESSION_ENDED("session_ended"), PROMPT_SUBMITTED("prompt_submitted"),
    TURN_STARTED("turn_started"), TURN_COMPLETED("turn_completed"), TURN_FAILED("turn_failed"),
    TURN_INTERRUPTED("turn_interrupted"), TOOL_STARTED("tool_started"), TOOL_COMPLETED("tool_completed"),
    TOOL_FAILED("tool_failed"), FILE_READ("file_read"), FILE_MODIFIED("file_modified"),
    COMMAND_STARTED("command_started"), COMMAND_COMPLETED("command_completed"), COMMAND_FAILED("command_failed"),
    TEST_RUN("test_run"), TEST_PASSED("test_passed"), TEST_FAILED("test_failed"),
    SUBAGENT_STARTED("subagent_started"), SUBAGENT_STOPPED("subagent_stopped"),
    TASK_CREATED("task_created"), TASK_COMPLETED("task_completed"),
    APPROVAL_REQUESTED("approval_requested"), APPROVAL_RESOLVED("approval_resolved"),
    PERMISSION_DENIED_AUTO("permission_denied_auto"), NOTIFICATION("notification"), IDLE("idle"),
    CONTEXT_COMPACTED("context_compacted"), REVIEW_STARTED("review_started"), REVIEW_COMPLETED("review_completed"),
    REVIEW_FINDING("review_finding"), TOKEN_USAGE_UPDATED("token_usage_updated"),
    SESSION_META_UPDATED("session_meta_updated"), AGENT_ERROR("agent_error"), ADAPTER_STATUS("adapter_status"),
    UNKNOWN("unknown");

    /** The three kinds that duplicate dedicated wire messages and are timeline-only (protocol.md 5.1). */
    val isTimelineOnly: Boolean
        get() = this == APPROVAL_REQUESTED || this == APPROVAL_RESOLVED || this == ADAPTER_STATUS
}

object EventKindSerializer : WireEnumSerializer<EventKind>("EventKind", EventKind.entries, EventKind.UNKNOWN)

@Serializable(with = RemoteApprovalSerializer::class)
enum class RemoteApproval(override val wire: String) : WireEnum {
    AVAILABLE("available"), UNAVAILABLE("unavailable"), PAUSED("paused"), UNKNOWN("unknown");

    /** `unknown` renders exactly like `unavailable` (no approve buttons). */
    val allowsRemoteApproval: Boolean get() = this == AVAILABLE
}

object RemoteApprovalSerializer :
    WireEnumSerializer<RemoteApproval>("RemoteApproval", RemoteApproval.entries, RemoteApproval.UNKNOWN)

@Serializable(with = ReviewStateSerializer::class)
enum class ReviewState(override val wire: String) : WireEnum {
    NONE("none"), RUNNING("running"), COMPLETED("completed"), UNAVAILABLE("unavailable"), UNKNOWN("unknown");

    /** Unknown values are rendered as `unavailable`. */
    val effective: ReviewState get() = if (this == UNKNOWN) UNAVAILABLE else this
}

object ReviewStateSerializer : WireEnumSerializer<ReviewState>("ReviewState", ReviewState.entries, ReviewState.UNKNOWN)

@Serializable(with = TestStatusSerializer::class)
enum class TestStatus(override val wire: String) : WireEnum {
    RUNNING("running"), PASSED("passed"), FAILED("failed"), UNKNOWN("unknown"),
}

object TestStatusSerializer : WireEnumSerializer<TestStatus>("TestStatus", TestStatus.entries, TestStatus.UNKNOWN)

/** `risk.level`. protocol.md section 10: an unknown level is treated as [HIGH], never lower. */
@Serializable(with = RiskLevelSerializer::class)
enum class RiskLevel(override val wire: String) : WireEnum {
    LOW("low"), MEDIUM("medium"), HIGH("high"), CRITICAL("critical"), UNKNOWN("unknown");

    /** Level used for every gating decision: unknown -> high. */
    val effective: RiskLevel get() = if (this == UNKNOWN) HIGH else this
}

object RiskLevelSerializer : WireEnumSerializer<RiskLevel>("RiskLevel", RiskLevel.entries, RiskLevel.UNKNOWN)

/**
 * Extra confirmation strength, ordered weakest to strongest. [UNKNOWN] is treated as the strongest
 * known requirement ([HOLD_AND_RECONFIRM]) because the phone cannot know what the server expects.
 */
@Serializable(with = ExtraConfirmationLevelSerializer::class)
enum class ExtraConfirmationLevel(override val wire: String) : WireEnum {
    NONE("none"), HOLD("hold"), HOLD_AND_RECONFIRM("hold_and_reconfirm"), UNKNOWN("unknown");

    /** Strength used for comparisons: unknown counts as the strongest known level. */
    val effective: ExtraConfirmationLevel get() = if (this == UNKNOWN) HOLD_AND_RECONFIRM else this
}

object ExtraConfirmationLevelSerializer : WireEnumSerializer<ExtraConfirmationLevel>(
    "ExtraConfirmationLevel", ExtraConfirmationLevel.entries, ExtraConfirmationLevel.UNKNOWN, encodeUnknown = false,
)

/**
 * Approval decision. v1 has NO scope-expanding value (no `allow_for_session`, ...). A value the phone does
 * not know decodes to [UNKNOWN] and can never be encoded or offered as a button.
 */
@Serializable(with = DecisionSerializer::class)
enum class Decision(override val wire: String) : WireEnum {
    ALLOW("allow"), DENY("deny"), DENY_AND_STOP("deny_and_stop"), UNKNOWN("unknown"),
}

object DecisionSerializer :
    WireEnumSerializer<Decision>("Decision", Decision.entries, Decision.UNKNOWN, encodeUnknown = false)

@Serializable(with = AuthMethodSerializer::class)
enum class AuthMethod(override val wire: String) : WireEnum {
    BIOMETRIC("biometric"), DEVICE_CREDENTIAL("device_credential"), NONE("none"), UNKNOWN("unknown"),
}

object AuthMethodSerializer :
    WireEnumSerializer<AuthMethod>("AuthMethod", AuthMethod.entries, AuthMethod.UNKNOWN, encodeUnknown = false)

@Serializable(with = ApprovalOutcomeSerializer::class)
enum class ApprovalOutcome(override val wire: String) : WireEnum {
    ALLOWED("allowed"), DENIED("denied"), DENIED_AND_STOPPED("denied_and_stopped"), EXPIRED("expired"),
    HANDED_OFF_LOCAL("handed_off_local"), SUPERSEDED("superseded"), FAILED("failed"), UNKNOWN("unknown"),
}

object ApprovalOutcomeSerializer :
    WireEnumSerializer<ApprovalOutcome>("ApprovalOutcome", ApprovalOutcome.entries, ApprovalOutcome.UNKNOWN)

@Serializable(with = ResolvedBySerializer::class)
enum class ResolvedBy(override val wire: String) : WireEnum {
    PHONE("phone"), DESKTOP("desktop"), TIMEOUT("timeout"), AGENT("agent"), SYSTEM("system"), UNKNOWN("unknown"),
}

object ResolvedBySerializer : WireEnumSerializer<ResolvedBy>("ResolvedBy", ResolvedBy.entries, ResolvedBy.UNKNOWN)

@Serializable(with = DeliverySerializer::class)
enum class Delivery(override val wire: String) : WireEnum {
    DELIVERED("delivered"), NOT_DELIVERED("not_delivered"), UNKNOWN("unknown"),
}

object DeliverySerializer : WireEnumSerializer<Delivery>("Delivery", Delivery.entries, Delivery.UNKNOWN)

@Serializable(with = ObservedResultSerializer::class)
enum class ObservedResult(override val wire: String) : WireEnum {
    EXECUTED("executed"), DECLINED("declined"), NOT_YET_KNOWN("unknown"), UNKNOWN("__unknown__"),
}

object ObservedResultSerializer :
    WireEnumSerializer<ObservedResult>("ObservedResult", ObservedResult.entries, ObservedResult.UNKNOWN)

/** `decision_result.reason` (protocol.md 4.11). */
@Serializable(with = DecisionResultReasonSerializer::class)
enum class DecisionResultReason(override val wire: String) : WireEnum {
    APPLIED("APPLIED"), UNKNOWN_REQUEST("UNKNOWN_REQUEST"), ALREADY_RESOLVED("ALREADY_RESOLVED"),
    EXPIRED("EXPIRED"), BINDING_MISMATCH("BINDING_MISMATCH"), INPUT_HASH_MISMATCH("INPUT_HASH_MISMATCH"),
    NOT_ALLOWED("NOT_ALLOWED"), AUTH_REQUIRED("AUTH_REQUIRED"),
    EXTRA_CONFIRMATION_REQUIRED("EXTRA_CONFIRMATION_REQUIRED"), CLOCK_SKEW("CLOCK_SKEW"), PAUSED("PAUSED"),
    DEVICE_REVOKED("DEVICE_REVOKED"), UNKNOWN("__unknown__"),
}

object DecisionResultReasonSerializer : WireEnumSerializer<DecisionResultReason>(
    "DecisionResultReason", DecisionResultReason.entries, DecisionResultReason.UNKNOWN,
)

@Serializable(with = AdapterStatusKindSerializer::class)
enum class AdapterStatusKind(override val wire: String) : WireEnum {
    CONNECTED("connected"), DEGRADED("degraded"), DISCONNECTED("disconnected"), NOT_CONFIGURED("not_configured"),
    UNKNOWN("unknown"),
}

object AdapterStatusKindSerializer :
    WireEnumSerializer<AdapterStatusKind>("AdapterStatusKind", AdapterStatusKind.entries, AdapterStatusKind.UNKNOWN)

@Serializable(with = AdapterModeSerializer::class)
enum class AdapterMode(override val wire: String) : WireEnum {
    HOOKS_HTTP("hooks_http"), HOOKS_CLI("hooks_cli"), DAEMON_OBSERVER("daemon_observer"),
    ROLLOUT_TAIL("rollout_tail"), NONE("none"), UNKNOWN("unknown"),
}

object AdapterModeSerializer : WireEnumSerializer<AdapterMode>("AdapterMode", AdapterMode.entries, AdapterMode.UNKNOWN)

@Serializable(with = ResyncModeSerializer::class)
enum class ResyncMode(override val wire: String) : WireEnum {
    REPLAY("replay"), SNAPSHOT("snapshot"), NONE("none"), UNKNOWN("unknown"),
}

object ResyncModeSerializer : WireEnumSerializer<ResyncMode>("ResyncMode", ResyncMode.entries, ResyncMode.UNKNOWN)

@Serializable(with = DetailsKindSerializer::class)
enum class DetailsKind(override val wire: String) : WireEnum {
    COMMAND("command"), FILE_WRITE("file_write"), FILE_EDIT("file_edit"), FILE_READ("file_read"),
    MCP_TOOL("mcp_tool"), WEB("web"), AGENT("agent"), FILE_CHANGE("file_change"), PERMISSIONS("permissions"),
    OTHER("other"), UNKNOWN("unknown"),
}

object DetailsKindSerializer : WireEnumSerializer<DetailsKind>("DetailsKind", DetailsKind.entries, DetailsKind.UNKNOWN)

@Serializable(with = LocalPromptSerializer::class)
enum class LocalPrompt(override val wire: String) : WireEnum {
    UNDETERMINED("unknown"), VISIBLE("visible"), HIDDEN("hidden"), UNKNOWN("__unrecognised__"),
}

object LocalPromptSerializer :
    WireEnumSerializer<LocalPrompt>("LocalPrompt", LocalPrompt.entries, LocalPrompt.UNKNOWN)

@Serializable(with = ByeReasonSerializer::class)
enum class ByeReason(override val wire: String) : WireEnum {
    DEVICE_REVOKED("device_revoked"), SHUTDOWN("shutdown"), RESTART("restart"),
    SUPERSEDED_CONNECTION("superseded_connection"), UNPAIRED("unpaired"), UNKNOWN("unknown"),
}

object ByeReasonSerializer : WireEnumSerializer<ByeReason>("ByeReason", ByeReason.entries, ByeReason.UNKNOWN)

/** `error.code` values (protocol.md 9.1). */
@Serializable(with = ErrorCodeSerializer::class)
enum class ErrorCode(override val wire: String) : WireEnum {
    E_PROTO_VERSION("E_PROTO_VERSION"), E_AUTH_REQUIRED("E_AUTH_REQUIRED"), E_AUTH_FAILED("E_AUTH_FAILED"),
    E_DEVICE_REVOKED("E_DEVICE_REVOKED"), E_PAIR_FAILED("E_PAIR_FAILED"), E_PAIR_REJECTED("E_PAIR_REJECTED"),
    E_PAIR_BUSY("E_PAIR_BUSY"), E_RATE_LIMITED("E_RATE_LIMITED"), E_BAD_MESSAGE("E_BAD_MESSAGE"),
    E_RESUME_TOO_OLD("E_RESUME_TOO_OLD"), E_INTERNAL("E_INTERNAL"), UNKNOWN("__unknown__"),
}

object ErrorCodeSerializer : WireEnumSerializer<ErrorCode>("ErrorCode", ErrorCode.entries, ErrorCode.UNKNOWN)
