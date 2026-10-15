package dev.agentnest.core.nest

import dev.agentnest.core.protocol.AgentEvent
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.EventKind
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.booleanOrNull
import java.time.Duration
import java.time.Instant

/** Error overlay kinds (protocol.md 5.4): 5 s for a failed tool/command, 30 s for a failed test, sticky for a failed turn. */
enum class LatchKind { TRANSIENT, TEST, STICKY }

/** A running error latch. */
data class ErrorLatch(val kind: LatchKind, val startedAt: Instant)

/**
 * Per-session derivation state. Port of the PC's `state::SessionReducer` (docs/protocol.md 5.4), kept in step with
 * `protocol/fixtures/state_transitions.json`, which both implementations execute.
 *
 * The phone normally receives the derived state from the PC (`session_state` / `snapshot`) and does not need this;
 * it exists so that the same transition table can be replayed locally (offline rebuilds from cached events, tests
 * of the shared fixture) without a second interpretation of the rules.
 */
data class SessionDerivation(
    /** The underlying state; error, approval and timer effects are overlays on top of it. */
    val base: AgentState = AgentState.IDLE,
    val turnActive: Boolean = false,
    /** Pending approval request ids in arrival order. While non-empty the base state is frozen. */
    val pendingApprovalIds: List<String> = emptyList(),
    val latches: List<ErrorLatch> = emptyList(),
    /** State before a Codex `waitingOn*` flag put the session into an awaiting state. */
    val flagPrevious: AgentState? = null,
    val consecutiveFileReads: Int = 0,
    val completedAt: Instant? = null,
    val lastEventAt: Instant,
    val adapterDisconnected: Boolean = false,
    val ended: Boolean = false,
)

/** What a UI/consumer sees at a point in time. */
data class SessionView(
    val state: AgentState,
    val stale: Boolean,
    val ended: Boolean,
    val turnActive: Boolean,
    val pendingApprovalIds: List<String>,
)

/** Pure transition function `reduce(prev, event, now)` plus time-dependent [view]. */
object SessionReducer {
    val COMPLETED_TO_IDLE: Duration = Duration.ofSeconds(60)
    val TRANSIENT_ERROR: Duration = Duration.ofSeconds(5)
    val TEST_ERROR: Duration = Duration.ofSeconds(30)
    val STALE_AFTER: Duration = Duration.ofMinutes(15)
    val DEAD_AFTER_ACTIVE_TURN: Duration = Duration.ofMinutes(45)
    val DEAD_AFTER_IDLE: Duration = Duration.ofMinutes(30)

    private val EDIT_TOOLS = setOf("Edit", "Write", "MultiEdit", "NotebookEdit", "apply_patch")

    /** A fresh session: idle, no turn, last event at [at]. */
    fun initial(at: Instant) = SessionDerivation(lastEventAt = at)

    /** The state at [now] (timers evaluated lazily from the stored timestamps). */
    fun view(s: SessionDerivation, now: Instant): SessionView {
        val sinceLast = Duration.between(s.lastEventAt, now)
        val dead = s.adapterDisconnected ||
            sinceLast >= (if (s.turnActive) DEAD_AFTER_ACTIVE_TURN else DEAD_AFTER_IDLE)
        val stale = s.turnActive && sinceLast >= STALE_AFTER
        val base = effectiveBase(s, now)
        val state = when {
            dead -> AgentState.DISCONNECTED
            s.pendingApprovalIds.isNotEmpty() -> AgentState.AWAITING_APPROVAL
            s.latches.any { active(it, now) } -> AgentState.ERROR
            else -> base
        }
        return SessionView(state, stale, s.ended, s.turnActive, s.pendingApprovalIds)
    }

    private fun effectiveBase(s: SessionDerivation, now: Instant): AgentState {
        val completed = s.completedAt
        return if (s.base == AgentState.COMPLETED && completed != null && Duration.between(completed, now) >= COMPLETED_TO_IDLE) {
            AgentState.IDLE
        } else {
            s.base
        }
    }

    private fun active(l: ErrorLatch, now: Instant): Boolean = when (l.kind) {
        LatchKind.TRANSIENT -> now.isBefore(l.startedAt.plus(TRANSIENT_ERROR))
        LatchKind.TEST -> now.isBefore(l.startedAt.plus(TEST_ERROR))
        LatchKind.STICKY -> true
    }

    /** Applies [event] at time [now]. Any event revives a disconnected/stale session. */
    fun reduce(prev: SessionDerivation, event: AgentEvent, now: Instant): SessionDerivation {
        // Materialise timers that have fired, then record the event time (clears stale/disconnected).
        var s = prev.copy(
            base = effectiveBase(prev, now),
            latches = prev.latches.filter { active(it, now) },
            lastEventAt = now,
            adapterDisconnected = false,
        )
        val d = event.detail ?: JsonObject(emptyMap())
        val frozen = s.pendingApprovalIds.isNotEmpty()

        fun setBase(state: AgentState, resetReads: Boolean = true): SessionDerivation {
            val next = if (frozen) s else s.copy(base = state, flagPrevious = null)
            return if (resetReads) next.copy(consecutiveFileReads = 0) else next
        }
        fun clear(vararg kinds: LatchKind) = s.latches.filter { it.kind !in kinds }

        when (event.kind) {
            EventKind.SESSION_STARTED -> {
                s = when (d.str("source_reason")) {
                    "resume" -> s.copy(latches = clear(LatchKind.STICKY))
                    "fork", "compact" -> s
                    else -> initial(now) // startup, clear, unknown: reducer reset
                }
            }
            EventKind.PROMPT_SUBMITTED -> {
                s = setBase(AgentState.WORKING).copy(turnActive = true, latches = emptyList(), completedAt = null)
            }
            EventKind.TURN_STARTED -> {
                val moved = if (s.base == AgentState.IDLE || s.base == AgentState.COMPLETED) setBase(AgentState.WORKING) else s
                s = moved.copy(turnActive = true, latches = clear(LatchKind.TRANSIENT), completedAt = null)
            }
            EventKind.COMMAND_STARTED -> {
                val cls = d.str("command_class")
                val target = if (cls == "test" || cls == "build") AgentState.TESTING else AgentState.WORKING
                s = setBase(target).copy(latches = clear(LatchKind.TRANSIENT))
            }
            EventKind.TEST_RUN -> s = setBase(AgentState.TESTING).copy(latches = clear(LatchKind.TRANSIENT))
            EventKind.TOOL_STARTED -> {
                val editing = d.str("tool_name") in EDIT_TOOLS || d.str("item_type") == "fileChange"
                s = setBase(if (editing) AgentState.WRITING_CODE else AgentState.WORKING).copy(latches = clear(LatchKind.TRANSIENT))
            }
            EventKind.FILE_MODIFIED -> s = setBase(AgentState.WRITING_CODE)
            EventKind.FILE_READ -> {
                val reads = s.consecutiveFileReads + 1
                val explore = event.actor?.agentType == "Explore"
                s = if (reads >= 2 || explore) setBase(AgentState.REVIEWING, resetReads = false).copy(consecutiveFileReads = reads)
                else s.copy(consecutiveFileReads = reads)
            }
            EventKind.REVIEW_STARTED -> s = setBase(AgentState.REVIEWING).copy(latches = clear(LatchKind.TRANSIENT))
            EventKind.REVIEW_COMPLETED -> s = setBase(AgentState.WORKING)
            EventKind.SUBAGENT_STARTED -> s = s.copy(latches = clear(LatchKind.TRANSIENT))
            EventKind.TOOL_FAILED, EventKind.COMMAND_FAILED ->
                s = s.copy(latches = clear(LatchKind.TRANSIENT) + ErrorLatch(LatchKind.TRANSIENT, now))
            EventKind.TEST_FAILED ->
                s = s.copy(latches = clear(LatchKind.TEST) + ErrorLatch(LatchKind.TEST, now))
            EventKind.TEST_PASSED -> s = s.copy(latches = clear(LatchKind.TEST))
            EventKind.TURN_FAILED ->
                s = s.copy(latches = clear(LatchKind.STICKY) + ErrorLatch(LatchKind.STICKY, now), turnActive = false)
            EventKind.AGENT_ERROR ->
                s = s.copy(latches = clear(LatchKind.STICKY) + ErrorLatch(LatchKind.STICKY, now))
            EventKind.TURN_COMPLETED -> {
                val background = d.int("background_tasks") ?: 0
                s = if (background > 0) {
                    setBase(AgentState.WORKING).copy(latches = clear(LatchKind.TEST))
                } else {
                    setBase(AgentState.COMPLETED).copy(turnActive = false, completedAt = now, latches = clear(LatchKind.TEST))
                }
            }
            EventKind.TURN_INTERRUPTED -> s = setBase(AgentState.IDLE).copy(turnActive = false)
            EventKind.IDLE -> s = setBase(AgentState.IDLE)
            EventKind.SESSION_ENDED -> s = s.copy(ended = true)
            EventKind.APPROVAL_REQUESTED -> {
                val id = d.str("request_id")
                if (id != null && id !in s.pendingApprovalIds) s = s.copy(pendingApprovalIds = s.pendingApprovalIds + id)
            }
            EventKind.APPROVAL_RESOLVED -> {
                val id = d.str("request_id")
                if (id != null && id in s.pendingApprovalIds) {
                    s = s.copy(pendingApprovalIds = s.pendingApprovalIds - id)
                    if (s.pendingApprovalIds.isEmpty() && d.str("outcome") == "denied_and_stopped") {
                        s = s.copy(base = AgentState.IDLE, turnActive = false, flagPrevious = null)
                    }
                }
            }
            EventKind.NOTIFICATION -> s = notification(s, d, frozen)
            EventKind.ADAPTER_STATUS -> {
                if (d.str("status") == "disconnected" && event.source.channel == "codex.app_server") {
                    s = s.copy(adapterDisconnected = true)
                }
            }
            else -> Unit // tool_completed, command_completed, subagent_stopped, task_*, token usage, meta, unknown: no transition
        }
        return s
    }

    private fun notification(s: SessionDerivation, d: JsonObject, frozen: Boolean): SessionDerivation {
        when (d.str("notification_type")) {
            "agent_needs_input" -> return if (frozen) s else s.copy(base = AgentState.AWAITING_INPUT, flagPrevious = null, consecutiveFileReads = 0)
            "permission_prompt" ->
                return if (frozen || s.base == AgentState.AWAITING_APPROVAL) s
                else s.copy(base = AgentState.AWAITING_APPROVAL, flagPrevious = null, consecutiveFileReads = 0)
            "codex_thread_status" -> Unit
            else -> return s
        }
        if (d.str("status") != "active" || frozen) return s
        val flags = (d["active_flags"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull } ?: emptyList()
        val awaiting = s.base == AgentState.AWAITING_APPROVAL || s.base == AgentState.AWAITING_INPUT
        return when {
            "waitingOnApproval" in flags -> flagState(s, AgentState.AWAITING_APPROVAL, awaiting)
            "waitingOnUserInput" in flags -> flagState(s, AgentState.AWAITING_INPUT, awaiting)
            awaiting && s.flagPrevious != null -> s.copy(base = s.flagPrevious, flagPrevious = null)
            !awaiting && s.base == AgentState.IDLE && d.bool("has_recent_items") == false -> s.copy(base = AgentState.WORKING)
            else -> s
        }
    }

    private fun flagState(s: SessionDerivation, target: AgentState, alreadyAwaiting: Boolean): SessionDerivation =
        s.copy(base = target, flagPrevious = if (alreadyAwaiting) s.flagPrevious else s.base, consecutiveFileReads = 0)

    private fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
    private fun JsonObject.int(key: String): Int? = (this[key] as? JsonPrimitive)?.intOrNull
    private fun JsonObject.bool(key: String): Boolean? = (this[key] as? JsonPrimitive)?.booleanOrNull
}
