package dev.agentnest.core

import dev.agentnest.core.link.LinkState
import dev.agentnest.core.protocol.AdapterMode
import dev.agentnest.core.protocol.AdapterStatusKind
import dev.agentnest.core.protocol.AdapterStatusMessage
import dev.agentnest.core.protocol.AdapterStatusPayload
import dev.agentnest.core.protocol.AgentEvent
import dev.agentnest.core.protocol.AgentKind
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.ApprovalDetails
import dev.agentnest.core.protocol.ApprovalOutcome
import dev.agentnest.core.protocol.ApprovalRequest
import dev.agentnest.core.protocol.ApprovalRequestMessage
import dev.agentnest.core.protocol.ApprovalResolvedMessage
import dev.agentnest.core.protocol.ApprovalResolvedPayload
import dev.agentnest.core.protocol.Counters
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.DecisionResultMessage
import dev.agentnest.core.protocol.DecisionResultPayload
import dev.agentnest.core.protocol.DecisionResultReason
import dev.agentnest.core.protocol.Delivery
import dev.agentnest.core.protocol.EventCategory
import dev.agentnest.core.protocol.EventKind
import dev.agentnest.core.protocol.EventMessage
import dev.agentnest.core.protocol.EventSource
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.FrameMeta
import dev.agentnest.core.protocol.Limits
import dev.agentnest.core.protocol.ObservedResult
import dev.agentnest.core.protocol.PcInfo
import dev.agentnest.core.protocol.Policy
import dev.agentnest.core.protocol.Project
import dev.agentnest.core.protocol.RemoteApproval
import dev.agentnest.core.protocol.ResolvedBy
import dev.agentnest.core.protocol.Resync
import dev.agentnest.core.protocol.ResyncMode
import dev.agentnest.core.protocol.RiskInfo
import dev.agentnest.core.protocol.RiskLevel
import dev.agentnest.core.protocol.SessionState
import dev.agentnest.core.protocol.SessionStateMessage
import dev.agentnest.core.protocol.Severity
import dev.agentnest.core.protocol.SnapshotMessage
import dev.agentnest.core.protocol.SnapshotPayload
import dev.agentnest.core.protocol.SnapshotTruncated
import dev.agentnest.core.protocol.Summary
import dev.agentnest.core.protocol.Ts
import dev.agentnest.core.protocol.WelcomeMessage
import dev.agentnest.core.protocol.WelcomePayload
import dev.agentnest.core.util.Uuid7Generator
import java.time.Duration
import java.time.Instant
import java.util.Random

/** Deterministic builders shared by the unit tests. */
object T {
    val T0: Instant = Instant.parse("2026-10-15T12:00:00.000Z")
    val PC = PcInfo(pcId = "pc_8252e6280a3d81d1", name = "DESKTOP-HOME", appVersion = "0.1.0", os = "windows")

    private val uuid = Uuid7Generator({ 1_700_000_000_000L }, Random(7))
    fun id(): String = uuid.next()

    fun connected(now: Instant = T0) = LinkState.Connected(PC, now, null)

    fun meta(seq: Long? = null, at: Instant = T0) = FrameMeta(id(), Ts.of(at), seq)

    fun ts(at: Instant) = Ts.of(at)

    fun session(
        key: String,
        state: AgentState,
        agent: AgentKind = AgentKind.CLAUDE_CODE,
        since: Instant = T0.minusSeconds(60),
        lastEvent: Instant = since,
        ended: Boolean = false,
        pending: List<String> = emptyList(),
        remote: RemoteApproval = RemoteApproval.AVAILABLE,
        headline: String = "헤드라인 $key",
    ) = SessionState(
        sessionKey = key,
        agentKind = agent,
        agentLabel = agent.shortName,
        project = Project("p", "proj"),
        state = state,
        stateSince = Ts.of(since),
        headline = headline,
        remoteApproval = remote,
        pendingApprovalIds = pending,
        counters = Counters(),
        lastEventAt = Ts.of(lastEvent),
        ended = ended,
    )

    fun request(
        id: String = "ar_" + id(),
        sessionKey: String = "claude_code:s1",
        created: Instant = T0,
        ttlSeconds: Long = 120,
        level: RiskLevel = RiskLevel.HIGH,
        extra: ExtraConfirmationLevel = ExtraConfirmationLevel.HOLD,
        allowed: List<Decision> = listOf(Decision.ALLOW, Decision.DENY, Decision.DENY_AND_STOP),
        authRequired: List<Decision> = listOf(Decision.ALLOW, Decision.DENY_AND_STOP),
        origin: String = "claude_code.hook.http",
        command: String = "rm -rf node_modules && pnpm install",
    ) = ApprovalRequest(
        requestId = id,
        nonceB64 = "nj8VYyTULw6ktvT86B1W+w==",
        sessionKey = sessionKey,
        agentKind = AgentKind.CLAUDE_CODE,
        agentLabel = "Claude Code",
        project = Project("p", "agentnest"),
        origin = origin,
        createdAt = Ts.of(created),
        expiresAt = Ts.of(created.plus(Duration.ofSeconds(ttlSeconds))),
        ttlSeconds = ttlSeconds.toInt(),
        toolName = "Bash",
        title = "명령을 실행하려고 해요",
        purpose = "agent says",
        details = ApprovalDetails(command = command),
        toolInputSha256 = "940519b4cf559666e1068256e714a63ef4b8df29e78fc02b9b75079bbeae4032",
        risk = RiskInfo(level, listOf("r"), listOf("이유"), extra),
        allowedDecisions = allowed,
        authRequiredFor = authRequired,
    )

    fun welcome(
        seq: Long? = null,
        resync: Resync = Resync(ResyncMode.SNAPSHOT),
        at: Instant = T0,
        serverTime: Instant = at,
        policy: Policy = Policy(),
    ) = WelcomeMessage(
        meta(seq, at),
        WelcomePayload(
            pc = PC,
            capabilities = listOf("events", "approvals"),
            serverTime = Ts.of(serverTime),
            resync = resync,
            limits = Limits(),
            policy = policy,
        ),
    )

    fun snapshot(
        seq: Long,
        sessions: List<SessionState> = emptyList(),
        approvals: List<ApprovalRequest> = emptyList(),
        ids: List<String> = approvals.map { it.requestId },
        events: List<AgentEvent> = emptyList(),
        at: Instant = T0,
    ) = SnapshotMessage(
        meta(seq, at),
        SnapshotPayload(
            sessions = sessions,
            pendingApprovals = approvals,
            recentEvents = events,
            adapters = listOf(AdapterStatusPayload(AgentKind.CLAUDE_CODE, AdapterStatusKind.CONNECTED, AdapterMode.HOOKS_HTTP)),
            pendingApprovalIdsComplete = ids,
            truncated = SnapshotTruncated(),
        ),
    )

    fun sessionMsg(seq: Long, session: SessionState, at: Instant = T0) = SessionStateMessage(meta(seq, at), session)

    fun approvalMsg(seq: Long, request: ApprovalRequest, at: Instant = T0) = ApprovalRequestMessage(meta(seq, at), request)

    fun resolvedMsg(
        seq: Long,
        requestId: String,
        outcome: ApprovalOutcome = ApprovalOutcome.ALLOWED,
        observed: ObservedResult = ObservedResult.NOT_YET_KNOWN,
        at: Instant = T0,
    ) = ApprovalResolvedMessage(
        meta(seq, at),
        ApprovalResolvedPayload(
            requestId = requestId,
            sessionKey = "claude_code:s1",
            outcome = outcome,
            resolvedBy = ResolvedBy.PHONE,
            resolvedAt = Ts.of(at),
            delivery = Delivery.DELIVERED,
            observedResult = observed,
            messageKo = "허용했어요",
        ),
    )

    fun decisionResult(requestId: String, accepted: Boolean, reason: DecisionResultReason, at: Instant = T0, inReplyTo: String? = null) =
        DecisionResultMessage(meta(null, at), DecisionResultPayload(requestId, inReplyTo, accepted, reason, "메시지"))

    fun event(
        seq: Long,
        kind: EventKind = EventKind.COMMAND_STARTED,
        severity: Severity = Severity.INFO,
        sessionKey: String = "claude_code:s1",
        nativeIds: Map<String, String> = emptyMap(),
        at: Instant = T0,
    ) = AgentEvent(
        eventId = id(),
        seq = seq,
        ts = Ts.of(at),
        agentKind = AgentKind.CLAUDE_CODE,
        sessionKey = sessionKey,
        kind = kind,
        category = EventCategory.COMMAND,
        severity = severity,
        summary = Summary("헤드라인"),
        source = EventSource("claude_code.hook.http", null, nativeIds),
    )

    fun eventMsg(event: AgentEvent) = EventMessage(meta(event.seq, event.ts.instant), event)

    fun adapterMsg(seq: Long, status: AdapterStatusKind) =
        AdapterStatusMessage(meta(seq), AdapterStatusPayload(AgentKind.CODEX, status, AdapterMode.HOOKS_CLI))

}
