package dev.agentnest.app

import dev.agentnest.core.link.LinkState
import dev.agentnest.core.protocol.AdapterMode
import dev.agentnest.core.protocol.AdapterStatusKind
import dev.agentnest.core.protocol.AdapterStatusPayload
import dev.agentnest.core.protocol.AgentEvent
import dev.agentnest.core.protocol.AgentKind
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.ApprovalDetails
import dev.agentnest.core.protocol.ApprovalRequest
import dev.agentnest.core.protocol.Counters
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.EventCategory
import dev.agentnest.core.protocol.EventKind
import dev.agentnest.core.protocol.EventMessage
import dev.agentnest.core.protocol.EventSource
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.FrameMeta
import dev.agentnest.core.protocol.Limits
import dev.agentnest.core.protocol.PcInfo
import dev.agentnest.core.protocol.Policy
import dev.agentnest.core.protocol.Project
import dev.agentnest.core.protocol.RemoteApproval
import dev.agentnest.core.protocol.Resync
import dev.agentnest.core.protocol.ResyncMode
import dev.agentnest.core.protocol.RiskInfo
import dev.agentnest.core.protocol.RiskLevel
import dev.agentnest.core.protocol.SessionState
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

/** Deterministic builders shared by the app's JVM unit tests (a trimmed copy of the core test fixtures). */
object TD {
    val T0: Instant = Instant.parse("2026-10-15T12:00:00.000Z")
    val PC = PcInfo(pcId = "pc_8252e6280a3d81d1", name = "DESKTOP-HOME", appVersion = "0.1.0", os = "windows")
    const val REQUEST_ID = "ar_01929f1a-6c2e-7b3c-9e4d-00000000001a"

    private val uuid = Uuid7Generator({ 1_700_000_000_000L }, Random(11))
    fun id(): String = uuid.next()

    fun connected(now: Instant = T0) = LinkState.Connected(PC, now, null)

    fun meta(seq: Long? = null, at: Instant = T0) = FrameMeta(id(), Ts.of(at), seq)

    fun session(
        key: String,
        state: AgentState,
        agent: AgentKind = AgentKind.CLAUDE_CODE,
        remote: RemoteApproval = RemoteApproval.AVAILABLE,
        pending: List<String> = emptyList(),
        ended: Boolean = false,
        projectKey: String = "p",
        projectName: String = "agentnest",
        lastEvent: Instant = T0,
    ) = SessionState(
        sessionKey = key,
        agentKind = agent,
        agentLabel = agent.shortName,
        project = Project(projectKey, projectName, branch = "main"),
        state = state,
        stateSince = Ts.of(T0.minusSeconds(60)),
        headline = "헤드라인 $key",
        remoteApproval = remote,
        pendingApprovalIds = pending,
        counters = Counters(),
        lastEventAt = Ts.of(lastEvent),
        ended = ended,
    )

    fun request(
        id: String = REQUEST_ID,
        sessionKey: String = "claude_code:s1",
        created: Instant = T0,
        ttlSeconds: Long = 120,
        level: RiskLevel = RiskLevel.HIGH,
        extra: ExtraConfirmationLevel = ExtraConfirmationLevel.HOLD,
        allowed: List<Decision> = listOf(Decision.ALLOW, Decision.DENY, Decision.DENY_AND_STOP),
        command: String = "rm -rf node_modules && pnpm install",
        purpose: String? = "agent says: reinstall",
        origin: String = "claude_code.hook.http",
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
        purpose = purpose,
        details = ApprovalDetails(command = command, filePaths = listOf("node_modules")),
        toolInputSha256 = "940519b4cf559666e1068256e714a63ef4b8df29e78fc02b9b75079bbeae4032",
        risk = RiskInfo(level, listOf("r"), listOf("폴더를 통째로 지우는 명령"), extra),
        allowedDecisions = allowed,
        authRequiredFor = listOf(Decision.ALLOW, Decision.DENY_AND_STOP),
    )

    fun welcome(at: Instant = T0, policy: Policy = Policy()) = WelcomeMessage(
        meta(null, at),
        WelcomePayload(
            pc = PC,
            capabilities = listOf("events", "approvals", "events_history"),
            serverTime = Ts.of(at),
            resync = Resync(ResyncMode.SNAPSHOT),
            limits = Limits(),
            policy = policy,
        ),
    )

    fun snapshot(
        seq: Long,
        sessions: List<SessionState> = emptyList(),
        approvals: List<ApprovalRequest> = emptyList(),
        events: List<AgentEvent> = emptyList(),
        at: Instant = T0,
    ) = SnapshotMessage(
        meta(seq, at),
        SnapshotPayload(
            sessions = sessions,
            pendingApprovals = approvals,
            recentEvents = events,
            adapters = listOf(AdapterStatusPayload(AgentKind.CLAUDE_CODE, AdapterStatusKind.CONNECTED, AdapterMode.HOOKS_HTTP)),
            pendingApprovalIdsComplete = approvals.map { it.requestId },
            truncated = SnapshotTruncated(),
        ),
    )

    fun event(
        seq: Long,
        kind: EventKind = EventKind.COMMAND_STARTED,
        severity: Severity = Severity.INFO,
        sessionKey: String = "claude_code:s1",
        at: Instant = T0,
        headline: String = "헤드라인",
    ) = AgentEvent(
        eventId = id(),
        seq = seq,
        ts = Ts.of(at),
        agentKind = AgentKind.CLAUDE_CODE,
        sessionKey = sessionKey,
        kind = kind,
        category = EventCategory.COMMAND,
        severity = severity,
        summary = Summary(headline),
        source = EventSource("claude_code.hook.http", null, emptyMap()),
    )

    fun eventMsg(event: AgentEvent) = EventMessage(meta(event.seq, event.ts.instant), event)
}
