package dev.agentnest.core.nest

import dev.agentnest.core.link.ClockSkew
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.protocol.AdapterStatusPayload
import dev.agentnest.core.protocol.AgentEvent
import dev.agentnest.core.protocol.AgentKind
import dev.agentnest.core.protocol.ApprovalRequest
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.DecisionResultPayload
import dev.agentnest.core.protocol.ErrorPayload
import dev.agentnest.core.protocol.PcInfo
import dev.agentnest.core.protocol.SessionState
import dev.agentnest.core.protocol.WelcomePayload
import java.time.Instant

/** A decision that was sent and is waiting for `decision_result` / `approval_resolved`. Blocks re-sending. */
data class InFlightDecision(val messageId: String, val decision: Decision, val sentAt: Instant)

/**
 * One pending approval card. [request] is null while the card is only known by id ("불러오는 중": buttons
 * disabled until the follow-up `approval_request` arrives).
 */
data class ApprovalCard(
    val requestId: String,
    val request: ApprovalRequest?,
    val receivedAt: Instant,
    val inFlight: InFlightDecision? = null,
    val lastResult: DecisionResultPayload? = null,
    /**
     * True when a later frame carried a DIFFERENT binding (nonce / hash / session) for this `request_id`. The original
     * body is kept for display but the card is never actionable again: the user must handle it on the PC.
     */
    val bindingConflict: Boolean = false,
) {
    /** True while only the id is known. */
    val isLoading: Boolean get() = request == null

    /** True once the server clock passes `expires_at` (given the clock [skewMs]). Expired cards are never actionable. */
    fun isExpired(now: Instant, skewMs: Long): Boolean {
        val expiresAt = request?.expiresAt?.instant ?: return false
        return !ClockSkew.toServer(now, skewMs).isBefore(expiresAt)
    }
}

/** Resync bookkeeping (protocol.md 8.4). While [awaitingSnapshot] is true, replayable messages are dropped. */
data class ResyncState(
    val awaitingSnapshot: Boolean = false,
    val since: Instant? = null,
    val lastRequestAt: Instant? = null,
)

/**
 * Everything the UI renders. Produced by [NestReducer]; `snapshot` REPLACES sessions and pending approvals,
 * it never merges.
 */
data class NestState(
    val link: LinkState = LinkState.Unpaired,
    val pc: PcInfo? = null,
    val welcome: WelcomePayload? = null,
    val sessions: Map<String, SessionState> = emptyMap(),
    val approvals: Map<String, ApprovalCard> = emptyMap(),
    val adapters: Map<AgentKind, AdapterStatusPayload> = emptyMap(),
    val recentEvents: List<AgentEvent> = emptyList(),
    val recentErrors: List<AgentEvent> = emptyList(),
    val history: ApprovalHistory = ApprovalHistory(),
    val lastSeq: Long = 0,
    val resync: ResyncState = ResyncState(),
    /** `serverTime - phoneTime` in ms. */
    val clockSkewMs: Long = 0,
    /** Phone time of the last applied server message; drives "마지막 확인 N분 전". */
    val lastSyncAt: Instant? = null,
    /** True when this state was restored from the on-disk snapshot cache and not yet refreshed. */
    val fromCache: Boolean = false,
    val lastDecisionResult: DecisionResultPayload? = null,
    val lastError: ErrorPayload? = null,
    val mood: MoodDecision,
    internal val resolvedIds: List<String> = emptyList(),
) {
    /** Cards that are still pending and not expired (home "승인 필요 N건"). Newest request first. */
    fun pendingCards(now: Instant): List<ApprovalCard> = approvals.values
        .filter { !it.isExpired(now, clockSkewMs) }
        .sortedWith(compareBy<ApprovalCard> { it.request?.createdAt?.instant ?: it.receivedAt }.reversed())

    /** The session the mood is about, if any. */
    val primarySession: SessionState? get() = mood.primarySessionKey?.let(sessions::get)

    /** Server-clock approval TTL cap advertised by the PC, or 120 s. */
    val approvalTtlSeconds: Int get() = welcome?.limits?.approvalTtlS ?: 120

    /** Sessions that have not ended, in focus order. */
    fun activeSessions(): List<SessionState> =
        sessions.values.filter { !it.ended }.sortedWith(
            compareBy<SessionState> { FocusSelector.order(it.state) }
                .thenByDescending { it.lastEventAt?.instant ?: Instant.EPOCH }
                .thenBy { it.sessionKey },
        )
}
