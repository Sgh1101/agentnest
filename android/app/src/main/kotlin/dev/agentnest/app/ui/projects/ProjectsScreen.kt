package dev.agentnest.app.ui.projects

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.agentnest.app.ui.Format
import dev.agentnest.app.ui.Labels
import dev.agentnest.app.ui.S
import dev.agentnest.app.ui.common.EmptyHint
import dev.agentnest.app.ui.common.InfoCard
import dev.agentnest.app.ui.common.ScreenHeader
import dev.agentnest.app.ui.common.ToneChip
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.protocol.SessionState
import java.time.Instant

/** One project as far as the phone can infer it from sessions (Phase 1, docs/android.md 2.3). */
data class ProjectSummary(
    val key: String,
    val name: String,
    val pathHint: String?,
    val branch: String?,
    val agents: List<String>,
    val lastActivity: dev.agentnest.core.protocol.Ts?,
)

/** Pure derivation of the project list from sessions: one card per `project_key`. Unit-tested. */
object ProjectList {
    fun of(sessions: Collection<SessionState>): List<ProjectSummary> =
        sessions.groupBy { it.project.projectKey.ifBlank { it.project.name } }
            .map { (key, list) ->
                val newest = list.maxByOrNull { it.lastEventAt?.instant ?: Instant.EPOCH } ?: list.first()
                ProjectSummary(
                    key = key,
                    name = newest.project.name.ifBlank { key },
                    pathHint = newest.project.pathHint?.takeIf { it.isNotBlank() },
                    branch = newest.project.branch?.takeIf { it.isNotBlank() },
                    agents = list.map { Labels.agent(it.agentKind, it.agentLabel) }.distinct(),
                    lastActivity = newest.lastEventAt,
                )
            }
            .sortedWith(compareByDescending<ProjectSummary> { it.lastActivity?.instant }.thenBy { it.name })
}

/** Projects tab. Phase 1: only what sessions reveal; PRs, tests and history are placeholders (docs/android.md 2.3). */
@Composable
fun ProjectsScreen(nest: NestState, now: Instant, modifier: Modifier = Modifier) {
    val projects = ProjectList.of(nest.sessions.values)
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(bottom = 16.dp),
    ) {
        item { ScreenHeader(title = S.TAB_PROJECTS, onBack = null) }
        if (projects.isEmpty()) item { EmptyHint(S.NO_PROJECTS) }
        items(projects, key = { it.key }) { project ->
            InfoCard(modifier = Modifier.padding(horizontal = 16.dp)) {
                Text(project.name, style = MaterialTheme.typography.titleMedium)
                project.pathHint?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                project.branch?.let { ToneChip(it, dev.agentnest.app.ui.Tone.NEUTRAL) }
                Text(
                    "${S.CONNECTED_AGENTS}: ${project.agents.joinToString(", ")}",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Format.ago(project.lastActivity, now, nest.clockSkewMs)?.let {
                    Text("${S.LAST_ACTIVITY} $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        item {
            Text(
                S.PROJECTS_PLACEHOLDER,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp),
            )
        }
    }
}
