package dev.agentnest.app.ui.agents

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.background
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.agentnest.app.ui.Format
import dev.agentnest.app.ui.Labels
import dev.agentnest.app.ui.S
import dev.agentnest.app.ui.Tone
import dev.agentnest.app.ui.common.InfoCard
import dev.agentnest.app.ui.common.ToneChip
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.protocol.SessionState
import java.time.Instant

/**
 * One session: agent, project, state chip, PC-written headline and a few facts. [expanded] adds recent files and
 * commands (AI tab / session detail). Ended sessions are dimmed (docs/android.md 2.1).
 */
@Composable
fun SessionCard(
    session: SessionState,
    nest: NestState,
    now: Instant,
    expanded: Boolean,
    onClick: (() -> Unit)?,
    modifier: Modifier = Modifier,
) {
    val skew = nest.clockSkewMs
    val dim = if (session.ended) 0.5f else 1f
    InfoCard(modifier = modifier.alpha(dim), onClick = onClick) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = Labels.agent(session.agentKind, session.agentLabel),
                    style = MaterialTheme.typography.titleSmall,
                )
                val where = listOfNotNull(
                    session.project.name.takeIf { it.isNotBlank() },
                    session.project.branch?.takeIf { it.isNotBlank() },
                ).joinToString(" · ")
                if (where.isNotEmpty()) {
                    Text(
                        text = where,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            ToneChip(
                text = if (session.ended) S.SESSION_ENDED else Labels.state(session.state),
                tone = if (session.ended) Tone.MUTED else Labels.stateTone(session.state),
            )
        }
        if (session.headline.isNotBlank()) {
            Text(session.headline, style = MaterialTheme.typography.bodyMedium)
        }
        BadgeRow(session, nest)
        val last = Format.ago(session.lastEventAt, now, skew)
        if (last != null) {
            Text(
                text = "${S.LAST_ACTIVITY} $last",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (expanded) Details(session, nest, now)
    }
}

@Composable
private fun BadgeRow(session: SessionState, nest: NestState) {
    val remote = Labels.remoteApproval(session.remoteApproval)
    val review = session.meta.review?.let {
        Labels.review(it.p0, it.p1, it.state, nest.adapters[session.agentKind]?.detail)
    }
    val testChip: Pair<String, Tone>? = session.lastTest?.let { t ->
        Labels.test(t.status)?.let { label -> label to Labels.testTone(t.status) }
    }
    if (remote == null && review == null && testChip == null) return
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        if (remote != null) ToneChip(remote, Tone.WARNING)
        if (review != null) ToneChip(review, Tone.INFO)
        if (testChip != null) ToneChip(testChip.first, testChip.second)
    }
}

@Composable
private fun Details(session: SessionState, nest: NestState, now: Instant) {
    val skew = nest.clockSkewMs
    val started = Format.ago(session.startedAt, now, skew)
    val completed = session.turn.completedAt?.let { Format.clock(it, skew) }
    if (started != null || completed != null) {
        val parts = ArrayList<String>(2)
        if (started != null) parts += "${S.STARTED} $started"
        if (completed != null) parts += "${S.TURN_DONE} $completed"
        Text(
            parts.joinToString(" · "),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    if (session.recentFiles.isNotEmpty()) {
        Text(S.RECENT_FILES, style = MaterialTheme.typography.labelMedium)
        for (file in session.recentFiles.take(5)) {
            MonoLine("${opLabel(file.op)}  ${file.pathHint}")
        }
    }
    if (session.recentCommands.isNotEmpty()) {
        Text(S.RECENT_COMMANDS, style = MaterialTheme.typography.labelMedium)
        for (command in session.recentCommands.take(3)) {
            val exit = command.exitCode?.let { if (it == 0) "" else "  (코드 $it)" } ?: ""
            MonoLine(command.commandPreview + exit)
        }
    }
}

@Composable
private fun MonoLine(text: String) {
    Row(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = text,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

private fun opLabel(op: String): String = when (op) {
    "read" -> "읽음"
    "create" -> "새 파일"
    "update", "edit" -> "수정"
    "delete" -> "삭제"
    else -> op
}

/** A coloured dot used in status rows. */
@Composable
fun StatusDot(color: Color, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .size(10.dp)
            .background(color, CircleShape),
    )
}
