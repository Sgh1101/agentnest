package dev.agentnest.core.nest

import dev.agentnest.core.link.ClockSkew
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.link.SeqTracker
import dev.agentnest.core.link.SeqVerdict
import dev.agentnest.core.protocol.AckMessage
import dev.agentnest.core.protocol.AckPayload
import dev.agentnest.core.protocol.AdapterStatusMessage
import dev.agentnest.core.protocol.AgentEvent
import dev.agentnest.core.protocol.ApprovalBinding
import dev.agentnest.core.protocol.ApprovalOutcome
import dev.agentnest.core.protocol.ApprovalRequest
import dev.agentnest.core.protocol.ApprovalRequestMessage
import dev.agentnest.core.protocol.ApprovalResolvedMessage
import dev.agentnest.core.protocol.ChallengeMessage
import dev.agentnest.core.protocol.ClientMessage
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.DecisionResultMessage
import dev.agentnest.core.protocol.DecisionResultPayload
import dev.agentnest.core.protocol.DecisionResultReason
import dev.agentnest.core.protocol.ErrorMessage
import dev.agentnest.core.protocol.EventMessage
import dev.agentnest.core.protocol.FrameMeta
import dev.agentnest.core.protocol.PongMessage
import dev.agentnest.core.protocol.ResolvedBy
import dev.agentnest.core.protocol.ResyncMode
import dev.agentnest.core.protocol.ServerMessage
import dev.agentnest.core.protocol.SessionStateMessage
import dev.agentnest.core.protocol.Severity
import dev.agentnest.core.protocol.SnapshotMessage
import dev.agentnest.core.protocol.SnapshotRequestMessage
import dev.agentnest.core.protocol.SnapshotRequestPayload
import dev.agentnest.core.protocol.Ts
import dev.agentnest.core.protocol.WelcomeMessage
import dev.agentnest.core.util.Uuid7Generator
import java.time.Duration
import java.time.Instant

/** Result of reducing one input: the new state plus messages the app must send. */
data class ReduceResult(val state: NestState, val outbound: List<ClientMessage> = emptyList())

/**
 * Applies server messages to [NestState] (docs/android.md 1.3, protocol.md 4.6 / 8).
 *
 * Rules implemented here:
 * - `snapshot` REPLACES sessions and pending approvals (never merges), resets `lastSeq` to `snapshot.seq` and clears
 *   any pending resync. Pending approvals missing from `pending_approval_ids_complete` are closed ("처리됨"); ids
 *   listed without a body stay as loading placeholders until the follow-up `approval_request` arrives.
 * - replayable messages go through [SeqTracker]: duplicates are skipped, a gap (or an unknown resync mode) triggers
 *   one `snapshot_request` and everything is dropped until the snapshot arrives.
 * - `approval_request` is acked immediately by id; expired or already-resolved requests are never created.
 * - `event` only feeds the timeline; the three timeline-only kinds never touch state. Session state comes from
 *   `session_state`/`snapshot` only.
 *
 * Messages without a `seq` (welcome, decision_result, pong, ...) are never subject to the sequence check.
 * [ids] generates envelope ids for outbound messages.
 */
class NestReducer(private val ids: () -> String = Uuid7Generator()::next) {

    /** Creates the initial state (no sessions, link [LinkState.Unpaired]). */
    fun initial(now: Instant, link: LinkState = LinkState.Unpaired): NestState {
        val mood = MoodResolver.resolve(MoodInput(link, emptyList()), null, now)
        return NestState(link = link, mood = mood)
    }

    /**
     * Rebuilds a state from a cached snapshot (cold start, docs/android.md 2.1). `lastSeq` is reset to 0 so the
     * next `hello` makes the PC send a fresh snapshot; the state is flagged [NestState.fromCache].
     */
    fun restoreFromCache(snapshot: SnapshotMessage, savedAt: Instant, now: Instant, link: LinkState): NestState {
        val base = initial(now, link)
        val applied = applySnapshot(base, snapshot, now).state
        return refreshMood(applied.copy(lastSeq = 0, resync = ResyncState(), lastSyncAt = savedAt, fromCache = true), now)
    }

    /** Applies one server message at phone time [now]. */
    fun reduce(state: NestState, message: ServerMessage, now: Instant): ReduceResult = when (message) {
        is SnapshotMessage -> applySnapshot(state, message, now)
        is WelcomeMessage -> applyWelcome(state, message, now)
        is ChallengeMessage -> ReduceResult(refreshMood(state.copy(clockSkewMs = ClockSkew.measure(message.payload.serverTime.instant, now)), now))
        is PongMessage -> {
            val server = message.payload.serverTime?.instant
            val updated = if (server != null) state.copy(clockSkewMs = ClockSkew.measure(server, now)) else state
            ReduceResult(updated)
        }
        is DecisionResultMessage -> ReduceResult(applyDecisionResult(state, message, now))
        is ErrorMessage -> ReduceResult(applyError(state, message))
        is EventMessage -> sequenced(state, message.meta, now) { s -> applyEvent(s, message.payload, now) }
        is SessionStateMessage -> sequenced(state, message.meta, now) { s ->
            touch(s.copy(sessions = s.sessions + (message.payload.sessionKey to message.payload)), now)
        }
        is AdapterStatusMessage -> sequenced(state, message.meta, now) { s ->
            touch(s.copy(adapters = s.adapters + (message.payload.agentKind to message.payload)), now)
        }
        is ApprovalRequestMessage -> applyApprovalRequest(state, message, now)
        is ApprovalResolvedMessage -> sequenced(state, message.meta, now) { s -> applyResolved(s, message, now) }
        // Handshake / paging / host list messages are handled by LinkStateMachine, PairingFlow and EventsPager.
        else -> ReduceResult(state)
    }

    /**
     * Applies a new link state (mood and "can respond" depend on it). When the link is not connected, decisions that
     * were still in flight are forgotten: they may or may not have reached the PC, and the next snapshot tells which
     * (a still-pending card means the decision did not apply, so the user may decide again).
     */
    fun onLink(state: NestState, link: LinkState, now: Instant): NestState {
        val approvals = if (link is LinkState.Connected || state.approvals.values.none { it.inFlight != null }) {
            state.approvals
        } else {
            state.approvals.mapValues { (_, card) -> card.copy(inFlight = null) }
        }
        return refreshMood(state.copy(link = link, approvals = approvals), now)
    }

    /**
     * Time-based housekeeping; call about once a second (and before rendering). Closes cards whose TTL has long
     * passed, drops sessions that ended a while ago, re-requests a stuck snapshot and recomputes the mood
     * (celebration end, minimum hold).
     */
    fun tick(state: NestState, now: Instant): ReduceResult {
        val serverNow = ClockSkew.toServer(now, state.clockSkewMs)
        var history = state.history
        val kept = LinkedHashMap<String, ApprovalCard>()
        for ((id, card) in state.approvals) {
            val request = card.request
            val expiresAt = request?.expiresAt?.instant
            if (request != null && expiresAt != null && !serverNow.isBefore(expiresAt.plus(EXPIRED_CARD_GRACE))) {
                history = history.recordClosed(request, ApprovalOutcome.EXPIRED, ResolvedBy.TIMEOUT, serverNow, EXPIRED_MESSAGE_KO)
            } else if (request == null &&
                Duration.between(card.receivedAt, now) > Duration.ofSeconds(state.approvalTtlSeconds.toLong()).plus(EXPIRED_CARD_GRACE)
            ) {
                // A placeholder whose body never arrived cannot outlive the approval TTL.
                continue
            } else {
                kept[id] = card
            }
        }
        val sessions = state.sessions.filterValues { s ->
            val last = s.lastEventAt?.instant
            !(s.ended && last != null && serverNow.isAfter(last.plus(ENDED_SESSION_RETENTION)))
        }
        var next = state.copy(approvals = kept, history = history, sessions = sessions)
        val outbound = ArrayList<ClientMessage>()
        val resync = next.resync
        if (resync.awaitingSnapshot && next.link is LinkState.Connected) {
            val reference = resync.lastRequestAt ?: resync.since
            if (reference != null && Duration.between(reference, now) >= SNAPSHOT_RETRY) {
                outbound += snapshotRequest(now, "resync_retry")
                next = next.copy(resync = resync.copy(lastRequestAt = now))
            }
        }
        return ReduceResult(refreshMood(next, now), outbound)
    }

    /** Records that a decision message was sent for [requestId], blocking a second send until a result arrives. */
    fun markDecisionSent(state: NestState, requestId: String, messageId: String, decision: Decision, now: Instant): NestState {
        val card = state.approvals[requestId] ?: return state
        val updated = card.copy(inFlight = InFlightDecision(messageId, decision, now), lastResult = null)
        return state.copy(approvals = state.approvals + (requestId to updated))
    }

    /** Builds a manual `snapshot_request` (pull to refresh) and marks it as requested. */
    fun requestSnapshot(state: NestState, reason: String, now: Instant): ReduceResult =
        ReduceResult(
            state.copy(resync = state.resync.copy(lastRequestAt = now)),
            listOf(snapshotRequest(now, reason)),
        )

    // ---------------------------------------------------------------------------------------------
    // Sequence handling
    // ---------------------------------------------------------------------------------------------

    /** Runs [apply] for a replayable message according to the sequence rules; mood is refreshed afterwards. */
    private fun sequenced(
        state: NestState,
        meta: FrameMeta,
        now: Instant,
        apply: (NestState) -> NestState,
    ): ReduceResult {
        val seq = meta.seq ?: return ReduceResult(state) // the codec rejects replayable messages without seq
        return when (SeqTracker.classify(state.lastSeq, seq, state.resync.awaitingSnapshot)) {
            SeqVerdict.APPLY -> ReduceResult(refreshMood(apply(state.copy(lastSeq = seq)), now))
            SeqVerdict.DUPLICATE, SeqVerdict.AWAITING_SNAPSHOT -> ReduceResult(state)
            SeqVerdict.GAP -> startResync(state, now, "seq_gap")
        }
    }

    private fun startResync(state: NestState, now: Instant, reason: String): ReduceResult {
        val resync = ResyncState(awaitingSnapshot = true, since = state.resync.since ?: now, lastRequestAt = now)
        return ReduceResult(state.copy(resync = resync), listOf(snapshotRequest(now, reason)))
    }

    private fun snapshotRequest(now: Instant, reason: String): ClientMessage =
        SnapshotRequestMessage(FrameMeta(ids(), Ts.of(now)), SnapshotRequestPayload(reason))

    // ---------------------------------------------------------------------------------------------
    // Welcome / snapshot
    // ---------------------------------------------------------------------------------------------

    private fun applyWelcome(state: NestState, message: WelcomeMessage, now: Instant): ReduceResult {
        val welcome = message.payload
        var next = state.copy(
            welcome = welcome,
            pc = welcome.pc,
            clockSkewMs = ClockSkew.measure(welcome.serverTime.instant, now),
            lastError = null,
        )
        val outbound = ArrayList<ClientMessage>()
        val resync = welcome.resync
        when (resync.mode) {
            ResyncMode.NONE -> next = next.copy(resync = ResyncState())
            ResyncMode.REPLAY -> {
                val from = resync.fromSeq
                if (from != null && from <= next.lastSeq + 1) {
                    next = next.copy(resync = ResyncState())
                } else {
                    // The PC claims to replay from a seq we cannot continue from: do not trust it, ask for a snapshot.
                    val started = startResync(next, now, "replay_mismatch")
                    next = started.state
                    outbound += started.outbound
                }
            }
            // `snapshot` follows right after welcome; an unknown mode is handled the same fail-safe way.
            ResyncMode.SNAPSHOT, ResyncMode.UNKNOWN ->
                next = next.copy(resync = ResyncState(awaitingSnapshot = true, since = now, lastRequestAt = null))
        }
        return ReduceResult(refreshMood(touch(next, now), now), outbound)
    }

    private fun applySnapshot(state: NestState, message: SnapshotMessage, now: Instant): ReduceResult {
        val payload = message.payload
        val seq = message.meta.seq ?: state.lastSeq
        val serverNow = ClockSkew.toServer(now, state.clockSkewMs)

        val bodies = payload.pendingApprovals.associateBy { it.requestId }
        val allIds = LinkedHashSet<String>().apply {
            addAll(payload.pendingApprovalIdsComplete)
            addAll(bodies.keys)
        }
        val cards = LinkedHashMap<String, ApprovalCard>()
        val acked = ArrayList<String>()
        for (id in allIds) {
            val existing = state.approvals[id]
            val incoming = bodies[id]
            val known = existing?.request
            // A different binding for a known request_id is never adopted: keep the old body, lock the card.
            val conflict = existing?.bindingConflict == true ||
                (incoming != null && known != null && ApprovalBinding.of(incoming) != ApprovalBinding.of(known))
            val body = if (conflict && known != null) known else incoming ?: known
            if (body != null && !serverNow.isBefore(body.expiresAt.instant)) continue // never resurrect an expired card
            cards[id] = ApprovalCard(
                requestId = id,
                request = body,
                receivedAt = existing?.receivedAt ?: now,
                inFlight = existing?.inFlight,
                lastResult = existing?.lastResult,
                bindingConflict = conflict,
            )
            if (incoming != null && !conflict) acked += id
        }
        var history = state.history
        for ((id, card) in state.approvals) {
            val request = card.request ?: continue
            if (id !in cards) {
                history = history.recordClosed(request, ApprovalOutcome.UNKNOWN, ResolvedBy.UNKNOWN, serverNow, CLOSED_BY_SNAPSHOT_KO)
            }
        }
        val next = state.copy(
            sessions = payload.sessions.associateBy { it.sessionKey },
            approvals = cards,
            adapters = payload.adapters.associateBy { it.agentKind },
            recentEvents = mergeEvents(state.recentEvents, payload.recentEvents),
            recentErrors = payload.recentErrors.takeLast(MAX_RECENT_ERRORS),
            history = history,
            lastSeq = seq,
            resync = ResyncState(),
            fromCache = false,
        )
        val outbound = if (acked.isEmpty()) emptyList() else listOf<ClientMessage>(ack(now, acked))
        return ReduceResult(refreshMood(touch(next, now), now), outbound)
    }

    // ---------------------------------------------------------------------------------------------
    // Events, sessions, approvals
    // ---------------------------------------------------------------------------------------------

    private fun applyEvent(state: NestState, event: AgentEvent, now: Instant): NestState {
        val errors = if (event.severity == Severity.WARNING || event.severity == Severity.ERROR) {
            (state.recentErrors.filter { it.eventId != event.eventId } + event).takeLast(MAX_RECENT_ERRORS)
        } else {
            state.recentErrors
        }
        return touch(state.copy(recentEvents = mergeEvents(state.recentEvents, listOf(event)), recentErrors = errors), now)
    }

    private fun mergeEvents(existing: List<AgentEvent>, incoming: List<AgentEvent>): List<AgentEvent> {
        val bySeq = LinkedHashMap<Long, AgentEvent>()
        for (e in existing) bySeq[e.seq] = e
        for (e in incoming) bySeq.putIfAbsent(e.seq, e)
        // Timeline-only kinds are also published as dedicated messages: collapse by (kind, request_id).
        val seenKeys = HashSet<String>()
        val merged = bySeq.values.sortedBy { it.seq }.filter { e ->
            !e.kind.isTimelineOnly || seenKeys.add(e.timelineKey)
        }
        return merged.takeLast(MAX_RECENT_EVENTS)
    }

    private fun applyApprovalRequest(state: NestState, message: ApprovalRequestMessage, now: Instant): ReduceResult {
        val request = message.payload
        val seq = message.meta.seq ?: return ReduceResult(state)
        val known = state.approvals[request.requestId]
        val verdict = SeqTracker.classify(state.lastSeq, seq, state.resync.awaitingSnapshot)
        return when (verdict) {
            SeqVerdict.GAP -> startResync(state, now, "seq_gap")
            SeqVerdict.AWAITING_SNAPSHOT -> ReduceResult(state)
            SeqVerdict.DUPLICATE -> when {
                // Follow-up frame for a placeholder (snapshot listed the id without a body): fill it in.
                known != null && known.request == null -> acceptRequest(state, request, now)
                // Re-sent because our ack was lost: ack again, change nothing.
                known != null -> ReduceResult(state, listOf(ack(now, listOf(request.requestId))))
                else -> ReduceResult(state)
            }
            SeqVerdict.APPLY -> acceptRequest(state.copy(lastSeq = seq), request, now)
        }
    }

    private fun acceptRequest(state: NestState, request: ApprovalRequest, now: Instant): ReduceResult {
        val serverNow = ClockSkew.toServer(now, state.clockSkewMs)
        if (request.requestId in state.resolvedIds) return ReduceResult(state)
        if (!serverNow.isBefore(request.expiresAt.instant)) return ReduceResult(state) // expired: never actionable
        val existing = state.approvals[request.requestId]
        val known = existing?.request
        if (existing != null && known != null && ApprovalBinding.of(request) != ApprovalBinding.of(known)) {
            // Same request_id, different nonce / hash / session: drop the new body, lock the card, ask for the truth.
            val locked = existing.copy(bindingConflict = true)
            val next = state.copy(approvals = state.approvals + (request.requestId to locked))
            if (existing.bindingConflict) return ReduceResult(next)
            val resync = startResync(next, now, "binding_conflict")
            return ReduceResult(refreshMood(resync.state, now), resync.outbound)
        }
        val card = ApprovalCard(
            requestId = request.requestId,
            request = request,
            receivedAt = existing?.receivedAt ?: now,
            inFlight = existing?.inFlight,
            lastResult = existing?.lastResult,
            bindingConflict = existing?.bindingConflict == true,
        )
        val next = touch(state.copy(approvals = state.approvals + (request.requestId to card)), now)
        return ReduceResult(refreshMood(next, now), listOf(ack(now, listOf(request.requestId))))
    }

    private fun applyResolved(state: NestState, message: ApprovalResolvedMessage, now: Instant): NestState {
        val payload = message.payload
        val card = state.approvals[payload.requestId]
        val history = state.history.recordResolved(payload, card?.request)
        val resolved = (state.resolvedIds + payload.requestId).distinct().takeLast(MAX_RESOLVED_IDS)
        return refreshMood(
            touch(state.copy(approvals = state.approvals - payload.requestId, history = history, resolvedIds = resolved), now),
            now,
        )
    }

    /**
     * An `error` frame that answers our in-flight decision (`in_reply_to` = the decision's message id) ends that
     * attempt: the card is unblocked (the request is still pending, the user may retry) and the error is recorded.
     */
    private fun applyError(state: NestState, message: ErrorMessage): NestState {
        val replyTo = message.payload.inReplyTo
        val base = state.copy(lastError = message.payload)
        if (replyTo == null) return base
        val entry = base.approvals.entries.firstOrNull { it.value.inFlight?.messageId == replyTo } ?: return base
        val result = DecisionResultPayload(
            requestId = entry.key,
            inReplyTo = replyTo,
            accepted = false,
            reason = DecisionResultReason.UNKNOWN,
            messageKo = message.payload.messageKo ?: ERROR_REPLY_KO,
        )
        return base.copy(approvals = base.approvals + (entry.key to entry.value.copy(inFlight = null, lastResult = result)))
    }

    private fun applyDecisionResult(state: NestState, message: DecisionResultMessage, now: Instant): NestState {
        val result = message.payload
        val card = state.approvals[result.requestId]
        var next = state.copy(lastDecisionResult = result)
        if (card == null) return next
        if (result.accepted) {
            // APPLIED: the PC took it; `approval_resolved` will close the card. Keep it blocked meanwhile.
            return next.copy(approvals = next.approvals + (card.requestId to card.copy(lastResult = result)))
        }
        val closes = result.reason == DecisionResultReason.UNKNOWN_REQUEST ||
            result.reason == DecisionResultReason.EXPIRED ||
            result.reason == DecisionResultReason.DEVICE_REVOKED
        if (closes) {
            val request = card.request
            if (request != null) {
                val outcome = if (result.reason == DecisionResultReason.EXPIRED) ApprovalOutcome.EXPIRED else ApprovalOutcome.UNKNOWN
                val by = if (result.reason == DecisionResultReason.EXPIRED) ResolvedBy.TIMEOUT else ResolvedBy.UNKNOWN
                val serverNow = ClockSkew.toServer(now, state.clockSkewMs)
                next = next.copy(
                    history = next.history.recordClosed(request, outcome, by, serverNow, result.messageKo ?: EXPIRED_MESSAGE_KO),
                )
            }
            return refreshMood(next.copy(approvals = next.approvals - card.requestId), now)
        }
        // Not applied (auth missing, binding mismatch, paused, ...): the request stays pending and the user may retry.
        return next.copy(approvals = next.approvals + (card.requestId to card.copy(inFlight = null, lastResult = result)))
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------

    private fun ack(now: Instant, approvalIds: List<String>): ClientMessage =
        AckMessage(FrameMeta(ids(), Ts.of(now)), AckPayload(throughSeq = null, approvalIds = approvalIds))

    private fun touch(state: NestState, now: Instant): NestState = state.copy(lastSyncAt = now)

    private fun refreshMood(state: NestState, now: Instant): NestState {
        val mood = MoodResolver.resolve(MoodInput(state.link, state.sessions.values, state.clockSkewMs), state.mood, now)
        return if (mood == state.mood) state else state.copy(mood = mood)
    }

    companion object {
        const val MAX_RECENT_EVENTS = 200
        const val MAX_RECENT_ERRORS = 5
        const val MAX_RESOLVED_IDS = 200
        private val SNAPSHOT_RETRY: Duration = Duration.ofSeconds(10)
        private val EXPIRED_CARD_GRACE: Duration = Duration.ofSeconds(10)
        private val ENDED_SESSION_RETENTION: Duration = Duration.ofMinutes(10)
        private const val EXPIRED_MESSAGE_KO = "시간이 지나 PC에서 직접 처리하도록 넘겼어요"
        private const val ERROR_REPLY_KO = "PC가 결정을 받지 못했어요. 다시 시도해 주세요"
        private const val CLOSED_BY_SNAPSHOT_KO = "PC에서 처리됐거나 시간이 지났어요"
    }
}
