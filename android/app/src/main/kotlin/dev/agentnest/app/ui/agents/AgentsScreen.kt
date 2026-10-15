package dev.agentnest.app.ui.agents

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.agentnest.app.ui.Labels
import dev.agentnest.app.ui.S
import dev.agentnest.app.ui.common.EmptyHint
import dev.agentnest.app.ui.common.ScreenHeader
import dev.agentnest.app.ui.common.SectionLabel
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.protocol.AdapterStatusKind
import dev.agentnest.core.protocol.AgentKind
import dev.agentnest.core.protocol.SessionState
import java.time.Instant

/** The AI tab: sessions grouped by agent (Claude Code, Codex, others) with the facts the PRD lists (section 3.B). */
@Composable
fun AgentsScreen(
    nest: NestState,
    now: Instant,
    onOpenSession: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val sessions = nest.sessions.values.filter { !it.ended }
    val groups = AgentGroups.of(sessions)
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(bottom = 16.dp),
    ) {
        item { ScreenHeader(title = S.TAB_AGENTS, onBack = null) }
        if (sessions.isEmpty()) {
            item { EmptyHint(S.NO_SESSIONS) }
        }
        for (group in groups) {
            item(key = "head-${group.kind.wire}") {
                SectionLabel(Labels.agent(group.kind, group.label))
                val adapter = nest.adapters[group.kind]
                if (adapter != null && adapter.status != AdapterStatusKind.CONNECTED && !adapter.detail.isNullOrBlank()) {
                    Text(
                        text = adapter.detail.orEmpty(),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 16.dp),
                    )
                }
            }
            items(group.sessions, key = { it.sessionKey }) { session ->
                SessionCard(
                    session = session,
                    nest = nest,
                    now = now,
                    expanded = true,
                    onClick = { onOpenSession(session.sessionKey) },
                    modifier = Modifier.padding(horizontal = 16.dp),
                )
            }
        }
    }
}

/** Sessions of one agent kind. */
data class AgentGroup(val kind: AgentKind, val label: String, val sessions: List<SessionState>)

/** Pure grouping of sessions by agent kind: Claude Code first, Codex second, then the rest. Unit-tested. */
object AgentGroups {
    private val ORDER = listOf(AgentKind.CLAUDE_CODE, AgentKind.CODEX, AgentKind.GEMINI_CLI, AgentKind.OPENCODE, AgentKind.OTHER, AgentKind.UNKNOWN)

    fun of(sessions: List<SessionState>): List<AgentGroup> {
        val byKind = sessions.groupBy { it.agentKind }
        return ORDER.mapNotNull { kind ->
            val list = byKind[kind] ?: return@mapNotNull null
            AgentGroup(kind, list.firstOrNull()?.agentLabel.orEmpty(), list.sortedWith(compareByDescending<SessionState> { it.lastEventAt?.instant }.thenBy { it.sessionKey }))
        }
    }
}
