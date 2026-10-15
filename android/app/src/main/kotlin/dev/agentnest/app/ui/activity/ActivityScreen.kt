package dev.agentnest.app.ui.activity

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import dev.agentnest.app.ui.AppController
import dev.agentnest.app.ui.Format
import dev.agentnest.app.ui.S
import dev.agentnest.app.ui.agents.EventRow
import dev.agentnest.app.ui.common.EmptyHint
import dev.agentnest.app.ui.common.ScreenHeader
import dev.agentnest.core.link.EventsPager
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.protocol.AgentEvent
import dev.agentnest.core.protocol.EventsPageMessage
import kotlinx.coroutines.launch

/**
 * The whole timeline: local cache (last 200 events) plus `events_request` paging, filter chips and date dividers
 * (docs/android.md 2.3). Offline only the cache is shown and "더 불러오기" is disabled.
 */
@Composable
fun ActivityScreen(nest: NestState, controller: AppController, modifier: Modifier = Modifier) {
    val scope = rememberCoroutineScope()
    var filter by remember { mutableStateOf(EventFilter.ALL) }
    var pager by remember { mutableStateOf(EventsPager()) }

    // A request that was in flight when the link dropped will never be answered: allow asking again.
    val connected = nest.link is LinkState.Connected
    LaunchedEffect(connected) {
        if (!connected) pager = pager.cancelPending()
    }
    LaunchedEffect(Unit) {
        controller.incoming.collect { message ->
            if (message is EventsPageMessage) pager = pager.onPage(message)
        }
    }

    val all: List<AgentEvent> = (nest.recentEvents + pager.events).associateBy { it.seq }.values.sortedByDescending { it.seq }
    val shown = all.filter { filter.matches(it) }
    val canLoadMore = nest.link is LinkState.Connected && nest.welcome?.has("events_history") == true && pager.hasMore && !pager.loading

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(start = 16.dp, end = 16.dp, bottom = 16.dp),
    ) {
        item { ScreenHeader(title = S.TAB_ACTIVITY, onBack = null, modifier = Modifier.padding(horizontal = 0.dp)) }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                for (option in EventFilter.entries) {
                    FilterPill(option.labelKo, selected = option == filter, onClick = { filter = option })
                }
            }
        }
        if (shown.isEmpty()) item { EmptyHint(S.NO_EVENTS) }
        var lastDay = ""
        for (event in shown) {
            val day = Format.dayKey(event.ts, nest.clockSkewMs)
            if (day != lastDay) {
                lastDay = day
                item(key = "day-$day") {
                    Text(
                        Format.day(event.ts, nest.clockSkewMs),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }
            }
            item(key = event.eventId) { EventRow(event, nest.clockSkewMs, showSession = true) }
        }
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

@Composable
private fun FilterPill(label: String, selected: Boolean, onClick: () -> Unit) {
    val shape = RoundedCornerShape(50)
    val bg = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant
    val fg = if (selected) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurfaceVariant
    Column(
        modifier = Modifier
            .clip(shape)
            .background(bg, shape)
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 8.dp),
    ) {
        Text(label, color = fg, style = MaterialTheme.typography.labelLarge)
    }
}
