package dev.agentnest.app.ui.approvals

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.agentnest.app.ui.Labels
import dev.agentnest.app.ui.S
import dev.agentnest.app.ui.Tone
import dev.agentnest.app.ui.common.InfoCard
import dev.agentnest.app.ui.common.ToneChip
import dev.agentnest.core.approval.DecisionValidator
import dev.agentnest.core.nest.ApprovalCard
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.text.RelativeTime
import java.time.Instant

/** Compact approval card for the approval centre list. Tapping opens the detail screen. */
@Composable
fun ApprovalSummaryCard(
    card: ApprovalCard,
    nest: NestState,
    now: Instant,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val request = card.request
    InfoCard(modifier = modifier, onClick = onClick) {
        if (request == null) {
            Text(S.APPROVAL_LOADING, style = MaterialTheme.typography.bodyMedium)
            return@InfoCard
        }
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = Labels.agent(request.agentKind, request.agentLabel),
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.weight(1f),
            )
            Text(
                text = "${RelativeTime.countdown(DecisionValidator.secondsLeft(request, now, nest.clockSkewMs))} ${S.REMAINING}",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Text(request.title, style = MaterialTheme.typography.bodyLarge)
        request.details.command?.let { command ->
            Text(
                text = command,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            ToneChip(Labels.risk(request.risk.level), Labels.riskTone(request.risk.level))
            val project = request.project.name
            if (project.isNotBlank()) {
                Text(
                    project,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        if (card.inFlight != null) ToneChip(S.SENDING, Tone.INFO)
    }
}
