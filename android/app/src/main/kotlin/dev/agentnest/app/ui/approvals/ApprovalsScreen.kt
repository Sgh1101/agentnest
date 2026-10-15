package dev.agentnest.app.ui.approvals

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.agentnest.app.approval.ApprovalStatus
import dev.agentnest.app.ui.Format
import dev.agentnest.app.ui.Labels
import dev.agentnest.app.ui.S
import dev.agentnest.app.ui.common.EmptyHint
import dev.agentnest.app.ui.common.InfoCard
import dev.agentnest.app.ui.common.ScreenHeader
import dev.agentnest.app.ui.common.SectionLabel
import dev.agentnest.app.ui.common.ToneChip
import dev.agentnest.core.nest.ApprovalHistoryEntry
import dev.agentnest.core.nest.NestState
import java.time.Instant

/** Approval centre: pending cards first, the latest finished ones below, link to the full history. */
@Composable
fun ApprovalsScreen(
    nest: NestState,
    now: Instant,
    onOpenApproval: (String) -> Unit,
    onOpenHistory: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val pending = nest.pendingCards(now)
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(bottom = 16.dp),
    ) {
        item { ScreenHeader(title = S.APPROVAL_CENTER, onBack = onBack) }
        if (pending.isEmpty()) {
            item { EmptyHint(S.NO_PENDING_APPROVALS) }
        } else {
            item { SectionLabel(S.PENDING) }
            items(pending, key = { it.requestId }) { card ->
                ApprovalSummaryCard(
                    card = card,
                    nest = nest,
                    now = now,
                    onClick = { onOpenApproval(card.requestId) },
                    modifier = Modifier.padding(horizontal = 16.dp),
                )
            }
        }
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SectionLabel(S.RECENT_APPROVALS, modifier = Modifier.weight(1f))
                TextButton(onClick = onOpenHistory) { Text(S.SEE_ALL) }
            }
        }
        val recent = nest.history.entries.take(3)
        if (recent.isEmpty()) {
            item { EmptyHint(S.NO_HISTORY) }
        } else {
            items(recent, key = { it.requestId }) { entry ->
                HistoryRow(entry, nest.clockSkewMs, modifier = Modifier.padding(horizontal = 16.dp))
            }
        }
    }
}

/** Full list of the last 50 resolved approvals (docs/android.md 2.3). Never shows command text. */
@Composable
fun ApprovalHistoryScreen(nest: NestState, onBack: () -> Unit, modifier: Modifier = Modifier) {
    val entries = nest.history.entries
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(bottom = 16.dp),
    ) {
        item { ScreenHeader(title = S.APPROVAL_HISTORY, onBack = onBack) }
        if (entries.isEmpty()) item { EmptyHint(S.NO_HISTORY) }
        items(entries, key = { it.requestId }) { entry ->
            HistoryRow(entry, nest.clockSkewMs, modifier = Modifier.padding(horizontal = 16.dp))
        }
    }
}

@Composable
private fun HistoryRow(entry: ApprovalHistoryEntry, skewMs: Long, modifier: Modifier = Modifier) {
    val lines = ApprovalStatus.resolved(entry)
    InfoCard(modifier = modifier) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = dev.agentnest.core.text.DisplaySanitizer.display(entry.title).ifBlank { S.UNTITLED_APPROVAL },
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.weight(1f),
            )
            entry.riskLevel?.let { ToneChip(Labels.risk(it), Labels.riskTone(it)) }
        }
        ToneChip(Labels.outcome(entry.outcome), Labels.outcomeTone(entry.outcome))
        lines.drop(1).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        val by = ApprovalStatus.resolvedBy(entry.resolvedBy)
        val at = entry.resolvedAt?.let { Format.clock(dev.agentnest.core.protocol.Ts.of(it), skewMs) }
        val meta = listOfNotNull(by.takeIf { it.isNotEmpty() }, at, entry.agentLabel.takeIf { it.isNotBlank() }, entry.projectName.takeIf { it.isNotBlank() })
        if (meta.isNotEmpty()) {
            Text(
                meta.joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
