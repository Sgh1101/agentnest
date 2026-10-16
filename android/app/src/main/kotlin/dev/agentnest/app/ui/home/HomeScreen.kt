package dev.agentnest.app.ui.home

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.agentnest.app.approval.ApprovalLogic
import dev.agentnest.app.approval.AuthAvailability
import dev.agentnest.app.approval.ApprovalStatus
import dev.agentnest.app.approval.SubmitOutcome
import dev.agentnest.app.character.KongiCanvas
import dev.agentnest.app.character.KongiSpec
import dev.agentnest.app.character.MotionLevel
import dev.agentnest.app.data.PairedInfo
import dev.agentnest.app.ui.AppController
import dev.agentnest.app.ui.Format
import dev.agentnest.app.ui.Labels
import dev.agentnest.app.ui.S
import dev.agentnest.app.ui.keepWords
import dev.agentnest.app.ui.Tone
import dev.agentnest.app.ui.agents.SessionCard
import dev.agentnest.app.ui.agents.StatusDot
import dev.agentnest.app.ui.common.HiddenCharsChip
import dev.agentnest.app.ui.common.InfoCard
import dev.agentnest.app.ui.common.LinkBanner
import dev.agentnest.app.ui.common.LinkBannerActions
import dev.agentnest.app.ui.common.ToneChip
import dev.agentnest.app.ui.theme.ToneTheme
import dev.agentnest.app.ui.theme.isDarkTheme
import dev.agentnest.core.approval.ApprovalDisplay
import dev.agentnest.core.approval.DecisionValidator
import dev.agentnest.core.approval.Enablement
import dev.agentnest.core.link.ClockSkew
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.nest.ApprovalCard
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.SessionState
import dev.agentnest.core.text.DisplaySanitizer
import dev.agentnest.core.text.RelativeTime
import kotlinx.coroutines.launch
import java.time.Duration
import java.time.Instant

/** Everything [HomeScreen] shows besides the state itself. */
data class HomeInputs(
    val paired: PairedInfo?,
    val paused: Boolean,
    val keyResetNotice: Boolean,
    val motion: MotionLevel,
    val animationActive: Boolean,
)

/** Navigation and link callbacks of the home screen. */
data class HomeActions(
    val link: LinkBannerActions,
    val onOpenApproval: (String) -> Unit,
    val onOpenApprovals: () -> Unit,
    val onOpenHistory: () -> Unit,
    val onOpenSession: (String) -> Unit,
    val onStartPairing: () -> Unit,
)

/**
 * Home in three layers (docs/android.md 2.1): 0 = the character with one headline (already on the phone, no round
 * trip), 1 = what needs the user now (pending approval, recent error), 2 = the session cards.
 */
@Composable
fun HomeScreen(
    nest: NestState,
    now: Instant,
    inputs: HomeInputs,
    controller: AppController,
    actions: HomeActions,
    modifier: Modifier = Modifier,
) {
    val pending = nest.pendingCards(now)
    val unpaired = nest.link is LinkState.Unpaired && inputs.paired == null
    val authReady = remember(now.epochSecond / 10) { controller.authAvailability() == AuthAvailability.READY }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(vertical = 8.dp),
    ) {
        item { StatusRow(nest, now, inputs, onRefresh = controller::refresh) }
        item {
            LinkBanner(
                link = nest.link,
                paused = inputs.paused,
                now = now,
                actions = actions.link,
            )
        }
        item { KongiHeader(nest, now, inputs, unpaired, actions.onStartPairing) }
        if (!authReady && inputs.paired != null) {
            item {
                InfoCard(modifier = Modifier.padding(horizontal = 16.dp), container = ToneTheme.colors(Tone.WARNING, isDarkTheme()).container) {
                    Text(S.DEVICE_LOCK_WARNING.keepWords())
                }
            }
        }
        if (inputs.keyResetNotice && unpaired) {
            item {
                InfoCard(modifier = Modifier.padding(horizontal = 16.dp), container = ToneTheme.colors(Tone.DANGER, isDarkTheme()).container) {
                    Text(S.KEY_RESET_NOTICE.keepWords())
                }
            }
        }
        if (pending.isNotEmpty()) {
            item {
                ActionCard(
                    card = pending.first(),
                    extraCount = pending.size - 1,
                    nest = nest,
                    now = now,
                    controller = controller,
                    onOpen = { actions.onOpenApproval(pending.first().requestId) },
                    onOpenAll = actions.onOpenApprovals,
                )
            }
        }
        val lastError = nest.recentErrors.lastOrNull()
        val lastTest = nest.primarySession?.lastTest
        if (lastError != null || (lastTest != null && Labels.test(lastTest.status) != null)) {
            item { RecentResults(nest, now) }
        }
        // Nothing to review before a PC is paired: the links would only open empty screens.
        if (!unpaired) {
            item {
                Row(modifier = Modifier.padding(horizontal = 8.dp)) {
                    TextButton(onClick = actions.onOpenApprovals) { Text(S.APPROVAL_CENTER) }
                    TextButton(onClick = actions.onOpenHistory) { Text(S.APPROVAL_HISTORY_LINK) }
                }
            }
        }
        val sessions = visibleSessions(nest, now)
        items(sessions, key = { it.sessionKey }) { session ->
            SessionCard(
                session = session,
                nest = nest,
                now = now,
                expanded = false,
                onClick = { actions.onOpenSession(session.sessionKey) },
                modifier = Modifier.padding(horizontal = 16.dp),
            )
        }
    }
}

/** Active sessions in focus order, then sessions that ended within the last five minutes (shown dimmed). */
internal fun visibleSessions(nest: NestState, now: Instant): List<SessionState> {
    val active = nest.activeSessions()
    val serverNow = ClockSkew.toServer(now, nest.clockSkewMs)
    val recentlyEnded = nest.sessions.values.filter { s ->
        val last = s.lastEventAt?.instant
        s.ended && last != null && Duration.between(last, serverNow) < Duration.ofMinutes(5)
    }
    return active + recentlyEnded.sortedBy { it.sessionKey }
}

@Composable
private fun StatusRow(nest: NestState, now: Instant, inputs: HomeInputs, onRefresh: () -> Unit) {
    val dark = isDarkTheme()
    val connected = nest.link is LinkState.Connected && !inputs.paused
    val tone = when {
        connected -> Tone.SUCCESS
        nest.link is LinkState.Unpaired -> Tone.NEUTRAL
        nest.link is LinkState.Reconnecting || nest.link is LinkState.Connecting -> Tone.WARNING
        else -> Tone.MUTED
    }
    val pcName = inputs.paired?.pcName ?: nest.pc?.name
    val text = when {
        nest.link is LinkState.Unpaired -> S.NOT_PAIRED
        inputs.paused -> S.LINK_PAUSED_SHORT
        connected -> if (pcName.isNullOrBlank()) S.CONNECTED else "${S.CONNECTED} · $pcName"
        else -> S.NOT_CONNECTED
    }
    Column {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 16.dp, end = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            StatusDot(ToneTheme.solid(tone, dark), modifier = Modifier.padding(end = 8.dp))
            Text(text, style = MaterialTheme.typography.labelLarge, modifier = Modifier.weight(1f))
            if (nest.link is LinkState.Connected) {
                IconButton(onClick = onRefresh) { Icon(Icons.Filled.Refresh, contentDescription = S.REFRESH) }
            }
        }
        val lastSync = nest.lastSyncAt
        if (nest.fromCache && lastSync != null) {
            Text(
                text = "${S.LAST_CHECKED} ${RelativeTime.ago(lastSync, now)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp),
            )
        }
    }
}

/** Layer 0: the character and one sentence. */
@Composable
private fun KongiHeader(nest: NestState, now: Instant, inputs: HomeInputs, unpaired: Boolean, onStartPairing: () -> Unit) {
    val mood = nest.mood
    val spec = remember(mood.mood, mood.typingVariant, mood.badge) {
        KongiSpec.of(mood.mood, mood.typingVariant, mood.badge)
    }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        KongiCanvas(spec = spec, motion = inputs.motion, active = inputs.animationActive)
        Text(
            text = mood.headline.keepWords(),
            style = MaterialTheme.typography.titleMedium,
            textAlign = TextAlign.Center,
            maxLines = 3,
            overflow = TextOverflow.Ellipsis,
        )
        if (mood.badgeCount > 0 && mood.badge.symbol.isNotEmpty()) {
            val label = if (mood.badge.symbol == "?") S.NEEDS_INPUT_COUNT else S.NEEDS_APPROVAL_COUNT
            ToneChip("$label ${mood.badgeCount}${S.COUNT_SUFFIX}", Tone.WARNING)
        }
        if (unpaired) {
            Button(onClick = onStartPairing) { Text(S.PAIR_PC) }
        }
    }
}

/** Layer 1: the first pending approval, expanded, with "+N" for the rest. */
@Composable
private fun ActionCard(
    card: ApprovalCard,
    extraCount: Int,
    nest: NestState,
    now: Instant,
    controller: AppController,
    onOpen: () -> Unit,
    onOpenAll: () -> Unit,
) {
    val request = card.request
    val scope = rememberCoroutineScope()
    var busy by remember(card.requestId) { mutableStateOf(false) }
    var message by remember(card.requestId) { mutableStateOf<String?>(null) }

    InfoCard(
        modifier = Modifier.padding(horizontal = 16.dp),
        container = MaterialTheme.colorScheme.primaryContainer,
        onClick = onOpen,
    ) {
        if (request == null) {
            Text(S.APPROVAL_LOADING, style = MaterialTheme.typography.bodyMedium)
            return@InfoCard
        }
        val left = DecisionValidator.secondsLeft(request, now, nest.clockSkewMs)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = if (extraCount > 0) "${S.APPROVAL_NEEDED} ${extraCount + 1}${S.COUNT_SUFFIX}" else "${S.APPROVAL_NEEDED} 1${S.COUNT_SUFFIX}",
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.weight(1f),
            )
            Text("${RelativeTime.countdown(left)} ${S.REMAINING}", style = MaterialTheme.typography.labelLarge)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(DisplaySanitizer.display(request.title), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            ToneChip(Labels.risk(request.risk.level), Labels.riskTone(request.risk.level))
        }
        HiddenCharsChip(ApprovalDisplay.hiddenCharCount(request))
        request.details.command?.let {
            Text(
                text = DisplaySanitizer.display(it),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
        val progress = ApprovalStatus.progress(card, now)
        val line = message ?: progress
        if (line != null) Text(line, style = MaterialTheme.typography.bodySmall)

        val deny = ApprovalLogic.enablement(nest, card, Decision.DENY, now)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            if (Decision.DENY in request.allowedDecisions) {
                OutlinedButton(
                    onClick = {
                        if (!busy) {
                            busy = true
                            message = null
                            scope.launch {
                                val outcome = controller.decide(card.requestId, Decision.DENY, ExtraConfirmationLevel.NONE)
                                message = if (outcome is SubmitOutcome.Sent) null else ApprovalStatus.submitted(outcome, Decision.DENY)
                                busy = false
                            }
                        }
                    },
                    enabled = deny is Enablement.Enabled && !busy && card.inFlight == null,
                ) { Text(S.DENY) }
            }
            Button(onClick = onOpen) { Text(S.VIEW) }
            if (extraCount > 0) {
                TextButton(onClick = onOpenAll) { Text("+${extraCount}${S.COUNT_SUFFIX}") }
            }
        }
        if (deny is Enablement.Disabled && card.inFlight == null) {
            Text(deny.reason.messageKo, style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** Layer 1: latest error and last test result of the focused session. */
@Composable
private fun RecentResults(nest: NestState, now: Instant) {
    val error = nest.recentErrors.lastOrNull()
    val test = nest.primarySession?.lastTest
    InfoCard(modifier = Modifier.padding(horizontal = 16.dp)) {
        Text(S.RECENT_RESULTS, style = MaterialTheme.typography.titleSmall)
        if (test != null) {
            val label = Labels.test(test.status)
            if (label != null) ToneChip(label, Labels.testTone(test.status))
        }
        if (error != null) {
            val ago = Format.ago(error.ts, now, nest.clockSkewMs)
            Text(
                text = DisplaySanitizer.display(error.summary.headline).let { if (ago != null) "$it · $ago" else it },
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}
