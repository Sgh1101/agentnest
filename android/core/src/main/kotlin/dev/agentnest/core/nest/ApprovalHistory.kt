package dev.agentnest.core.nest

import dev.agentnest.core.protocol.ApprovalOutcome
import dev.agentnest.core.protocol.ApprovalRequest
import dev.agentnest.core.protocol.ApprovalResolvedPayload
import dev.agentnest.core.protocol.Delivery
import dev.agentnest.core.protocol.ObservedResult
import dev.agentnest.core.protocol.ResolvedBy
import dev.agentnest.core.protocol.RiskLevel
import java.time.Instant

/**
 * One finished approval as shown in "승인 기록" (docs/android.md 2.3). Deliberately contains NO command text, diff
 * or file content: only the card title, risk level and the outcome.
 */
data class ApprovalHistoryEntry(
    val requestId: String,
    val sessionKey: String,
    val title: String,
    val toolName: String,
    val agentLabel: String,
    val projectName: String,
    val riskLevel: RiskLevel?,
    val outcome: ApprovalOutcome,
    val resolvedBy: ResolvedBy,
    val resolvedAt: Instant?,
    val delivery: Delivery,
    val observedResult: ObservedResult,
    val messageKo: String?,
)

/** The most recent [MAX_ENTRIES] approvals, newest first. Immutable. */
data class ApprovalHistory(val entries: List<ApprovalHistoryEntry> = emptyList()) {

    /** The entry for [requestId], if present. */
    fun find(requestId: String): ApprovalHistoryEntry? = entries.firstOrNull { it.requestId == requestId }

    /**
     * Records an `approval_resolved`. A repeated message for the same `request_id` (the PC re-sends it when
     * `observed_result` is learned later) updates the existing entry in place instead of adding a new one.
     * [card] supplies title/risk when the card is still known; otherwise the existing entry (or blanks) is used.
     */
    fun recordResolved(payload: ApprovalResolvedPayload, card: ApprovalRequest?): ApprovalHistory {
        val existing = find(payload.requestId)
        val entry = ApprovalHistoryEntry(
            requestId = payload.requestId,
            sessionKey = payload.sessionKey.ifEmpty { existing?.sessionKey ?: card?.sessionKey ?: "" },
            title = card?.title ?: existing?.title ?: "",
            toolName = card?.toolName ?: existing?.toolName ?: "",
            agentLabel = card?.agentLabel ?: existing?.agentLabel ?: "",
            projectName = card?.project?.name ?: existing?.projectName ?: "",
            riskLevel = card?.risk?.level ?: existing?.riskLevel,
            outcome = payload.outcome,
            resolvedBy = payload.resolvedBy,
            resolvedAt = payload.resolvedAt?.instant ?: existing?.resolvedAt,
            delivery = payload.delivery,
            observedResult = payload.observedResult,
            messageKo = payload.messageKo ?: existing?.messageKo,
        )
        return put(entry)
    }

    /** Records a card that was closed locally or by a snapshot (no `approval_resolved` was received). */
    fun recordClosed(
        card: ApprovalRequest,
        outcome: ApprovalOutcome,
        resolvedBy: ResolvedBy,
        at: Instant,
        messageKo: String,
    ): ApprovalHistory {
        if (find(card.requestId) != null) return this
        return put(
            ApprovalHistoryEntry(
                requestId = card.requestId,
                sessionKey = card.sessionKey,
                title = card.title,
                toolName = card.toolName,
                agentLabel = card.agentLabel,
                projectName = card.project.name,
                riskLevel = card.risk.level,
                outcome = outcome,
                resolvedBy = resolvedBy,
                resolvedAt = at,
                delivery = Delivery.NOT_DELIVERED,
                observedResult = ObservedResult.NOT_YET_KNOWN,
                messageKo = messageKo,
            ),
        )
    }

    private fun put(entry: ApprovalHistoryEntry): ApprovalHistory {
        val index = entries.indexOfFirst { it.requestId == entry.requestId }
        val updated = if (index >= 0) entries.toMutableList().also { it[index] = entry } else listOf(entry) + entries
        return ApprovalHistory(updated.take(MAX_ENTRIES))
    }

    companion object {
        const val MAX_ENTRIES = 50
    }
}
