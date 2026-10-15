package dev.agentnest.app.ui

import dev.agentnest.core.link.LinkState
import dev.agentnest.core.protocol.AgentEvent
import dev.agentnest.core.protocol.AgentKind
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.ApprovalOutcome
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.EventKind
import dev.agentnest.core.protocol.ObservedResult
import dev.agentnest.core.protocol.RemoteApproval
import dev.agentnest.core.protocol.ReviewState
import dev.agentnest.core.protocol.RiskLevel
import dev.agentnest.core.protocol.Severity
import dev.agentnest.core.protocol.TestStatus
import dev.agentnest.core.text.Fallbacks

/**
 * Korean labels for protocol enums (pure, unit-tested). Text about agents, sessions and approvals comes from the PC
 * (protocol.md 5.2); these cover only fixed vocabulary such as chips and badges.
 */
object Labels {
    /** Risk chip text. Unknown levels read as the strictest known one (high), like the validator does. */
    fun risk(level: RiskLevel): String = when (level.effective) {
        RiskLevel.LOW -> "위험 낮음"
        RiskLevel.MEDIUM -> "위험 보통"
        RiskLevel.HIGH -> "위험 높음"
        RiskLevel.CRITICAL -> "위험 매우 높음"
        RiskLevel.UNKNOWN -> "위험 높음"
    }

    /** Colour token of a risk level. */
    fun riskTone(level: RiskLevel): Tone = when (level.effective) {
        RiskLevel.LOW -> Tone.NEUTRAL
        RiskLevel.MEDIUM -> Tone.INFO
        RiskLevel.HIGH -> Tone.WARNING
        RiskLevel.CRITICAL, RiskLevel.UNKNOWN -> Tone.DANGER
    }

    /** Session state chip text. Unknown states read as "작업 중" (protocol.md 10). */
    fun state(state: AgentState): String = when (state.effective) {
        AgentState.IDLE -> "대기 중"
        AgentState.WORKING, AgentState.UNKNOWN -> "작업 중"
        AgentState.WRITING_CODE -> "코드 작성 중"
        AgentState.REVIEWING -> "검토 중"
        AgentState.TESTING -> "테스트 중"
        AgentState.AWAITING_APPROVAL -> "승인 필요"
        AgentState.AWAITING_INPUT -> "입력 필요"
        AgentState.ERROR -> "오류"
        AgentState.COMPLETED -> "완료"
        AgentState.DISCONNECTED -> "연결 끊김"
    }

    /** Colour token of a session state chip. */
    fun stateTone(state: AgentState): Tone = when (state.effective) {
        AgentState.IDLE -> Tone.NEUTRAL
        AgentState.WORKING, AgentState.WRITING_CODE, AgentState.UNKNOWN -> Tone.ACCENT
        AgentState.REVIEWING, AgentState.TESTING -> Tone.INFO
        AgentState.AWAITING_APPROVAL, AgentState.AWAITING_INPUT -> Tone.WARNING
        AgentState.ERROR -> Tone.DANGER
        AgentState.COMPLETED -> Tone.SUCCESS
        AgentState.DISCONNECTED -> Tone.MUTED
    }

    /** Product name for an agent kind. */
    fun agent(kind: AgentKind, label: String): String = label.ifBlank { kind.shortName }

    /** What happened to a finished approval. Unknown outcomes read as "처리됨". */
    fun outcome(outcome: ApprovalOutcome): String = when (outcome) {
        ApprovalOutcome.ALLOWED -> "허용했어요"
        ApprovalOutcome.DENIED -> "거부했어요"
        ApprovalOutcome.DENIED_AND_STOPPED -> "거부하고 멈췄어요"
        ApprovalOutcome.EXPIRED -> "시간이 지나 PC에서 직접 처리하도록 넘겼어요"
        ApprovalOutcome.HANDED_OFF_LOCAL -> "PC에서 처리하기로 했어요"
        ApprovalOutcome.SUPERSEDED -> "PC에서 이미 처리됐어요"
        ApprovalOutcome.FAILED -> "처리하지 못했어요"
        ApprovalOutcome.UNKNOWN -> Fallbacks.UNKNOWN_OUTCOME
    }

    /** Colour token of an outcome. */
    fun outcomeTone(outcome: ApprovalOutcome): Tone = when (outcome) {
        ApprovalOutcome.ALLOWED -> Tone.SUCCESS
        ApprovalOutcome.DENIED, ApprovalOutcome.DENIED_AND_STOPPED -> Tone.NEUTRAL
        ApprovalOutcome.FAILED -> Tone.DANGER
        ApprovalOutcome.EXPIRED, ApprovalOutcome.HANDED_OFF_LOCAL, ApprovalOutcome.SUPERSEDED -> Tone.MUTED
        ApprovalOutcome.UNKNOWN -> Tone.MUTED
    }

    /** The agent-side result learnt after a decision; empty while it is not known yet. [agent] is e.g. "Claude". */
    fun observed(result: ObservedResult, agent: String): String = when (result) {
        ObservedResult.EXECUTED -> "${agent}가 실행했어요"
        ObservedResult.DECLINED -> "${agent}에서 실행되지 않았어요"
        ObservedResult.NOT_YET_KNOWN, ObservedResult.UNKNOWN -> ""
    }

    /** Short label of a decision, used on buttons and confirmations. */
    fun decision(decision: Decision): String = when (decision) {
        Decision.ALLOW -> "허용"
        Decision.DENY -> "거부"
        Decision.DENY_AND_STOP -> "거부하고 멈추기"
        Decision.UNKNOWN -> ""
    }

    /** Badge on a session card for remote-approval availability; null when nothing needs to be said. */
    fun remoteApproval(value: RemoteApproval): String? = when (value) {
        RemoteApproval.AVAILABLE -> null
        RemoteApproval.PAUSED -> "원격 승인 일시정지"
        RemoteApproval.UNAVAILABLE, RemoteApproval.UNKNOWN -> "원격 승인 불가"
    }

    /** Codex review chip; null when the session has no review info. */
    fun review(p0: Int, p1: Int, state: ReviewState, detail: String?): String? = when (state.effective) {
        ReviewState.NONE -> null
        ReviewState.RUNNING -> "리뷰 중"
        ReviewState.COMPLETED -> "리뷰 P0 ${p0} · P1 ${p1}"
        ReviewState.UNAVAILABLE, ReviewState.UNKNOWN -> detail?.takeIf { it.isNotBlank() } ?: "리뷰 정보 없음 (hooks 모드)"
    }

    /** Last test chip. */
    fun test(status: TestStatus): String? = when (status) {
        TestStatus.RUNNING -> "테스트 실행 중"
        TestStatus.PASSED -> "테스트 통과"
        TestStatus.FAILED -> "테스트 실패"
        TestStatus.UNKNOWN -> null
    }

    /** Colour token of a test chip. */
    fun testTone(status: TestStatus): Tone = when (status) {
        TestStatus.PASSED -> Tone.SUCCESS
        TestStatus.FAILED -> Tone.DANGER
        TestStatus.RUNNING -> Tone.INFO
        TestStatus.UNKNOWN -> Tone.NEUTRAL
    }

    /** True for link states in which decisions can never be sent. */
    fun linkBlocksDecisions(link: LinkState): Boolean = link !is LinkState.Connected

    /** Timeline row chip for an event kind (unknown kinds show "기타"). */
    fun eventKind(kind: EventKind): String = when (kind) {
        EventKind.SESSION_STARTED -> "세션 시작"
        EventKind.SESSION_ENDED -> "세션 종료"
        EventKind.PROMPT_SUBMITTED -> "요청"
        EventKind.TURN_STARTED -> "작업 시작"
        EventKind.TURN_COMPLETED -> "작업 완료"
        EventKind.TURN_FAILED -> "작업 실패"
        EventKind.TURN_INTERRUPTED -> "작업 중단"
        EventKind.TOOL_STARTED, EventKind.TOOL_COMPLETED -> "도구"
        EventKind.TOOL_FAILED -> "도구 실패"
        EventKind.FILE_READ -> "파일 읽기"
        EventKind.FILE_MODIFIED -> "파일 수정"
        EventKind.COMMAND_STARTED, EventKind.COMMAND_COMPLETED -> "명령"
        EventKind.COMMAND_FAILED -> "명령 실패"
        EventKind.TEST_RUN -> "테스트"
        EventKind.TEST_PASSED -> "테스트 통과"
        EventKind.TEST_FAILED -> "테스트 실패"
        EventKind.SUBAGENT_STARTED, EventKind.SUBAGENT_STOPPED -> "하위 에이전트"
        EventKind.TASK_CREATED, EventKind.TASK_COMPLETED -> "작업 항목"
        EventKind.APPROVAL_REQUESTED -> "승인 요청"
        EventKind.APPROVAL_RESOLVED -> "승인 처리"
        EventKind.PERMISSION_DENIED_AUTO -> "자동 거부"
        EventKind.NOTIFICATION -> "알림"
        EventKind.IDLE -> "대기"
        EventKind.CONTEXT_COMPACTED -> "컨텍스트 정리"
        EventKind.REVIEW_STARTED, EventKind.REVIEW_COMPLETED, EventKind.REVIEW_FINDING -> "리뷰"
        EventKind.TOKEN_USAGE_UPDATED, EventKind.SESSION_META_UPDATED -> "정보 갱신"
        EventKind.AGENT_ERROR -> "에이전트 오류"
        EventKind.ADAPTER_STATUS -> "연동 상태"
        EventKind.UNKNOWN -> "기타"
    }

    /** Colour token of a timeline row. */
    fun eventTone(event: AgentEvent): Tone = when (event.severity) {
        Severity.ERROR -> Tone.DANGER
        Severity.WARNING -> Tone.WARNING
        else -> when (event.kind) {
            EventKind.TURN_COMPLETED, EventKind.TEST_PASSED, EventKind.TASK_COMPLETED -> Tone.SUCCESS
            EventKind.APPROVAL_REQUESTED, EventKind.APPROVAL_RESOLVED -> Tone.WARNING
            else -> Tone.NEUTRAL
        }
    }
}
