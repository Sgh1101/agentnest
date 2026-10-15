package dev.agentnest.app.ui.agents

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.agentnest.app.ui.AppController
import dev.agentnest.app.ui.Format
import dev.agentnest.app.ui.Labels
import dev.agentnest.app.ui.S
import dev.agentnest.app.ui.common.EmptyHint
import dev.agentnest.app.ui.common.InfoCard
import dev.agentnest.app.ui.common.ScreenHeader
import dev.agentnest.app.ui.common.ToneChip
import dev.agentnest.core.link.EventsPager
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.protocol.AgentEvent
import dev.agentnest.core.protocol.EventsPageMessage
import kotlinx.coroutines.launch
import java.time.Instant

/**
 * Timeline of one session: a pinned "지금" card (the session card) and the events from the local cache; scrolling to
 * the end offers "더 불러오기", which asks the PC for older events (`events_request`, only when the PC advertises
 * `events_history`).
 */
@Composable
fun SessionDetailScreen(
    sessionKey: String,
    nest: NestState,
    now: Instant,
    controller: AppController,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val session = nest.sessions[sessionKey]
    val scope = rememberCoroutineScope()
    var pager by remember(sessionKey) { mutableStateOf(EventsPager(sessionKey = sessionKey)) }

    // A request that was in flight when the link dropped will never be answered: allow asking again.
    val connected = nest.link is LinkState.Connected
    LaunchedEffect(connected) {
        if (!connected) pager = pager.cancelPending()
    }
    LaunchedEffect(sessionKey) {
        controller.incoming.collect { message ->
            if (message is EventsPageMessage) pager = pager.onPage(message)
        }
    }

    val cached = nest.recentEvents.filter { it.sessionKey == sessionKey }
    val events: List<AgentEvent> = (cached + pager.events).associateBy { it.seq }.values.sortedByDescending { it.seq }
    val canLoadMore = nest.link is LinkState.Connected &&
        nest.welcome?.has("events_history") == true && pager.hasMore && !pager.loading

    Column(modifier = modifier.fillMaxSize()) {
        ScreenHeader(title = session?.let { Labels.agent(it.agentKind, it.agentLabel) } ?: S.SESSION, onBack = onBack)
        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(8.dp),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 16.dp, vertical = 8.dp),
        ) {
            if (session != null) {
                item { SessionCard(session, nest, now, expanded = true, onClick = null) }
            }
            if (events.isEmpty()) {
                item { EmptyHint(S.NO_EVENTS) }
            }
            items(events, key = { it.eventId }) { event -> EventRow(event, nest.clockSkewMs) }
            item {
                if (nest.welcome?.has("events_history") == true) {
                    OutlinedButton(
                        enabled = canLoadMore,
                        onClick = { scope.launch { pager = controller.requestEvents(pager) } },
                    ) { Text(if (pager.loading) S.LOADING else S.LOAD_MORE) }
                }
            }
        }
    }
}

/** One timeline row: time, kind chip and the PC-written headline (detail on a second line). */
@Composable
fun EventRow(event: AgentEvent, skewMs: Long, modifier: Modifier = Modifier, showSession: Boolean = false) {
    InfoCard(modifier = modifier) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = Format.clock(event.ts, skewMs),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            ToneChip(Labels.eventKind(event.kind), Labels.eventTone(event))
            if (showSession) {
                val project = event.project?.name.orEmpty()
                if (project.isNotBlank()) {
                    Text(project, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        if (event.summary.headline.isNotBlank()) Text(event.summary.headline, style = MaterialTheme.typography.bodyMedium)
        event.summary.detail?.takeIf { it.isNotBlank() }?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
