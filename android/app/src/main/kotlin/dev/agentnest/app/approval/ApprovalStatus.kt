package dev.agentnest.app.approval

import dev.agentnest.app.ui.Labels
import dev.agentnest.core.nest.ApprovalCard
import dev.agentnest.core.nest.ApprovalHistoryEntry
import dev.agentnest.core.protocol.ApprovalOutcome
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.Delivery
import dev.agentnest.core.protocol.ResolvedBy
import java.time.Duration
import java.time.Instant

/** Pure wording of the decision progress and result lines (docs/android.md 2.2). Unit-tested. */
object ApprovalStatus {
    /** After this long without `decision_result` the line reads "확인 중…" (the decision is never re-sent). */
    const val SLOW_AFTER_SECONDS: Long = 5

    /** The progress line of a card whose decision was sent, or the failure of the last attempt; null when idle. */
    fun progress(card: ApprovalCard, now: Instant): String? {
        val inFlight = card.inFlight
        val result = card.lastResult
        if (inFlight == null) {
            // A rejected decision leaves the card pending; show why so the user can try again.
            return if (result != null && !result.accepted) result.messageKo ?: "PC가 이 결정을 받아들이지 않았어요" else null
        }
        return when {
            result != null && result.accepted -> "PC가 받았어요 · 처리 결과를 기다리는 중이에요"
            Duration.between(inFlight.sentAt, now).seconds >= SLOW_AFTER_SECONDS -> "확인 중…"
            else -> "PC에 전달 중…"
        }
    }

    /** Result lines of a finished approval: outcome (+ delivery), then what the agent did with it. */
    fun resolved(entry: ApprovalHistoryEntry): List<String> {
        val lines = ArrayList<String>(2)
        val delivered = entry.delivery == Delivery.DELIVERED &&
            (entry.outcome == ApprovalOutcome.ALLOWED ||
                entry.outcome == ApprovalOutcome.DENIED ||
                entry.outcome == ApprovalOutcome.DENIED_AND_STOPPED)
        val agent = shortAgent(entry.agentLabel)
        lines += if (delivered && agent.isNotEmpty()) "${Labels.outcome(entry.outcome)} · ${agent}에 전달했어요" else Labels.outcome(entry.outcome)
        val observed = Labels.observed(entry.observedResult, agent.ifEmpty { "에이전트" })
        if (observed.isNotEmpty()) lines += observed
        entry.messageKo?.takeIf { it.isNotBlank() && it != lines.first() }?.let { lines += it }
        return lines
    }

    /** "Claude Code" -> "Claude" (first word), so "Claude가 실행했어요" reads naturally. */
    fun shortAgent(label: String): String = label.trim().substringBefore(' ')

    /** Who resolved a card, for the history list. Empty when unknown. */
    fun resolvedBy(by: ResolvedBy): String = when (by) {
        ResolvedBy.PHONE -> "휴대폰"
        ResolvedBy.DESKTOP -> "PC"
        ResolvedBy.TIMEOUT -> "시간 초과"
        ResolvedBy.AGENT -> "에이전트"
        ResolvedBy.SYSTEM -> "시스템"
        ResolvedBy.UNKNOWN -> ""
    }

    /** The Korean text for what [outcome] means to the user right after pressing a button. */
    fun submitted(outcome: SubmitOutcome, decision: Decision): String? = when (outcome) {
        SubmitOutcome.Sent -> "${Labels.decision(decision)} 결정을 PC에 전달 중…"
        is SubmitOutcome.Blocked -> outcome.reason.messageKo
        is SubmitOutcome.AuthFailed -> outcome.messageKo
        SubmitOutcome.AuthCancelled -> "인증을 취소했어요. 아무 것도 전달하지 않았어요"
        SubmitOutcome.NotSent -> "전달하지 못했어요. PC와 연결되어 있는지 확인해 주세요"
    }
}
