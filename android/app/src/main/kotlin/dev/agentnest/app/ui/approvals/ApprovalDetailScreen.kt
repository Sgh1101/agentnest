package dev.agentnest.app.ui.approvals

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.agentnest.app.approval.ApprovalLogic
import dev.agentnest.app.approval.ApprovalStatus
import dev.agentnest.app.approval.AuthAvailability
import dev.agentnest.app.ui.AppController
import dev.agentnest.app.ui.Labels
import dev.agentnest.app.ui.S
import dev.agentnest.app.ui.Tone
import dev.agentnest.app.ui.common.EmptyHint
import dev.agentnest.app.ui.common.InfoCard
import dev.agentnest.app.ui.common.ScreenHeader
import dev.agentnest.app.ui.common.ToneChip
import dev.agentnest.core.approval.ApprovalGate
import dev.agentnest.core.approval.DecisionBlock
import dev.agentnest.core.approval.DecisionValidator
import dev.agentnest.core.approval.Enablement
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.protocol.ApprovalRequest
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.text.RelativeTime
import kotlinx.coroutines.launch
import java.time.Instant

/**
 * Approval detail (docs/android.md 2.2). Buttons are driven by `DecisionValidator.enablement`; high risk needs a long
 * press, critical adds the re-confirm dialog; every allow-type decision goes through `controller.decide`, which runs
 * the system authentication before anything is built or sent.
 */
@Composable
fun ApprovalDetailScreen(
    requestId: String,
    nest: NestState,
    now: Instant,
    controller: AppController,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val card = nest.approvals[requestId]
    val request = card?.request
    val history = nest.history.find(requestId)

    LaunchedEffect(requestId, request != null) {
        if (request != null) controller.markSeen(requestId)
    }

    Column(modifier = modifier.fillMaxSize()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            ScreenHeader(title = S.APPROVAL_TITLE, onBack = onBack, modifier = Modifier.weight(1f))
            if (request != null && card?.inFlight == null) {
                val left = DecisionValidator.secondsLeft(request, now, nest.clockSkewMs)
                Text(
                    text = "${RelativeTime.countdown(left)} ${S.REMAINING}",
                    style = MaterialTheme.typography.labelLarge,
                    modifier = Modifier.padding(end = 16.dp),
                )
            }
        }
        when {
            card != null && request != null -> ApprovalBody(requestId, request, nest, now, controller)
            card != null -> EmptyHint(S.APPROVAL_LOADING)
            history != null -> ResolvedBody(history.title, ApprovalStatus.resolved(history), history.outcome)
            else -> EmptyHint(S.APPROVAL_GONE)
        }
    }
}

@Composable
private fun ResolvedBody(title: String, lines: List<String>, outcome: dev.agentnest.core.protocol.ApprovalOutcome) {
    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (title.isNotBlank()) Text(title, style = MaterialTheme.typography.titleMedium)
        InfoCard {
            ToneChip(Labels.outcome(outcome), Labels.outcomeTone(outcome))
            lines.drop(1).forEach { Text(it, style = MaterialTheme.typography.bodyMedium) }
        }
    }
}

@Composable
private fun ApprovalBody(
    requestId: String,
    request: ApprovalRequest,
    nest: NestState,
    now: Instant,
    controller: AppController,
) {
    val card = nest.approvals[requestId] ?: return
    val scope = rememberCoroutineScope()
    var busy by remember(requestId) { mutableStateOf(false) }
    var message by remember(requestId) { mutableStateOf<String?>(null) }
    var reconfirm by remember(requestId) { mutableStateOf(false) }
    var stopDialog by remember(requestId) { mutableStateOf(false) }
    var menuOpen by remember(requestId) { mutableStateOf(false) }
    val authState = remember(requestId, busy) { controller.authAvailability() }

    fun run(decision: Decision, extra: ExtraConfirmationLevel) {
        if (busy) return
        busy = true
        message = null
        scope.launch {
            val outcome = controller.decide(requestId, decision, extra)
            message = ApprovalStatus.submitted(outcome, decision)
            busy = false
        }
    }

    val allow = ApprovalLogic.enablement(nest, card, Decision.ALLOW, now)
    val deny = ApprovalLogic.enablement(nest, card, Decision.DENY, now)
    val stop = ApprovalLogic.enablement(nest, card, Decision.DENY_AND_STOP, now)
    val canStopAtAll = Decision.DENY_AND_STOP in request.allowedDecisions && !request.isCodexHooksOrigin
    val inFlight = card.inFlight != null
    val authReady = authState == AuthAvailability.READY

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        val where = listOfNotNull(
            Labels.agent(request.agentKind, request.agentLabel),
            request.project.name.takeIf { it.isNotBlank() },
            request.project.branch?.takeIf { it.isNotBlank() },
        ).joinToString(" · ")
        Text(where, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)

        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(request.title, style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            ToneChip(Labels.risk(request.risk.level), Labels.riskTone(request.risk.level))
        }

        CommandBlock(request)
        FactsBlock(request)
        RiskBlock(request)
        PurposeBlock(request)

        val progress = ApprovalStatus.progress(card, now)
        val line = message ?: progress
        if (line != null) {
            InfoCard(container = MaterialTheme.colorScheme.primaryContainer) {
                Text(line, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onPrimaryContainer)
            }
        }

        // --- actions ------------------------------------------------------------------------------------------
        val allowDisabled = allow is Enablement.Disabled || busy || inFlight || !authReady
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (Decision.DENY in request.allowedDecisions) {
                OutlinedButton(
                    onClick = { run(Decision.DENY, ExtraConfirmationLevel.NONE) },
                    enabled = deny is Enablement.Enabled && !busy && !inFlight,
                    modifier = Modifier.weight(1f),
                ) { Text(S.DENY) }
            }
            if (Decision.ALLOW in request.allowedDecisions) {
                val gate: ApprovalGate? = (allow as? Enablement.Enabled)?.gate
                val level = gate?.extraConfirmation ?: ExtraConfirmationLevel.NONE
                if (level == ExtraConfirmationLevel.NONE) {
                    Button(
                        onClick = { run(Decision.ALLOW, ExtraConfirmationLevel.NONE) },
                        enabled = !allowDisabled,
                        modifier = Modifier.weight(1f),
                    ) { Text(S.ALLOW) }
                } else {
                    HoldToConfirmButton(
                        label = S.HOLD_TO_ALLOW,
                        enabled = !allowDisabled,
                        onConfirmed = {
                            if (level == ExtraConfirmationLevel.HOLD_AND_RECONFIRM) {
                                reconfirm = true
                            } else {
                                run(Decision.ALLOW, ExtraConfirmationLevel.HOLD)
                            }
                        },
                        modifier = Modifier.weight(1f),
                    )
                }
            }
            if (canStopAtAll) {
                Box {
                    IconButton(onClick = { menuOpen = true }, enabled = !busy && !inFlight) {
                        Icon(Icons.Filled.MoreVert, contentDescription = S.MORE)
                    }
                    DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                        DropdownMenuItem(
                            text = { Text(S.DENY_AND_STOP) },
                            enabled = stop is Enablement.Enabled && authReady,
                            onClick = {
                                menuOpen = false
                                val gate = (stop as? Enablement.Enabled)?.gate
                                if (gate != null) {
                                    if (gate.extraConfirmation == ExtraConfirmationLevel.NONE) {
                                        run(Decision.DENY_AND_STOP, ExtraConfirmationLevel.NONE)
                                    } else {
                                        stopDialog = true
                                    }
                                }
                            },
                        )
                    }
                }
            }
        }
        if (request.isCodexHooksOrigin) {
            Text(S.CODEX_HOOKS_DENY_ONLY, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        val blocked = (allow as? Enablement.Disabled)?.reason
        if (!authReady && Decision.ALLOW in request.allowedDecisions) {
            Text(S.AUTH_SETUP_NEEDED, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        } else if (blocked != null && blocked != DecisionBlock.IN_FLIGHT) {
            Text(blocked.messageKo, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
    }

    if (reconfirm) {
        ExtraConfirmDialog(
            request = request,
            needHold = false,
            needCheckbox = true,
            onConfirmed = {
                reconfirm = false
                run(Decision.ALLOW, ExtraConfirmationLevel.HOLD_AND_RECONFIRM)
            },
            onDismiss = { reconfirm = false },
        )
    }
    if (stopDialog) {
        val level = (stop as? Enablement.Enabled)?.gate?.extraConfirmation ?: ExtraConfirmationLevel.HOLD_AND_RECONFIRM
        ExtraConfirmDialog(
            request = request,
            needHold = true,
            needCheckbox = level == ExtraConfirmationLevel.HOLD_AND_RECONFIRM,
            onConfirmed = {
                stopDialog = false
                run(Decision.DENY_AND_STOP, level)
            },
            onDismiss = { stopDialog = false },
        )
    }
}

@Composable
private fun CommandBlock(request: ApprovalRequest) {
    val command = request.details.command
    val preview = request.details.diffPreview ?: request.details.contentPreview
    val text = command ?: preview ?: return
    var expanded by remember(request.requestId) { mutableStateOf(false) }
    val long = text.length > 160 || text.count { it == '\n' } >= 4
    InfoCard(container = MaterialTheme.colorScheme.surfaceVariant) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = if (command != null) S.COMMAND_LABEL else S.CHANGE_LABEL,
                style = MaterialTheme.typography.labelLarge,
                modifier = Modifier.weight(1f),
            )
            if (long) {
                TextButton(onClick = { expanded = !expanded }) { Text(if (expanded) S.COLLAPSE else S.EXPAND) }
            }
        }
        Text(
            text = text,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            maxLines = if (expanded) Int.MAX_VALUE else 4,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.horizontalScroll(rememberScrollState()),
            softWrap = false,
        )
        if (request.details.truncated) {
            Text(S.TRUNCATED, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun FactsBlock(request: ApprovalRequest) {
    val details = request.details
    val cwd = details.cwdHint?.takeIf { it.isNotBlank() }
    val mcp = details.mcpServer?.takeIf { it.isNotBlank() }
    if (cwd == null && details.filePaths.isEmpty() && mcp == null) return
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        if (cwd != null) FactLine(S.WHERE, cwd)
        if (mcp != null) FactLine(S.MCP_SERVER, mcp)
        if (details.filePaths.isNotEmpty()) {
            val shown = details.filePaths.take(5).joinToString("\n")
            val more = details.filePaths.size - 5
            FactLine(S.AFFECTED, if (more > 0) "$shown\n+${more}개" else shown)
        }
    }
}

@Composable
private fun FactLine(label: String, value: String) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace, modifier = Modifier.weight(1f))
    }
}

@Composable
private fun RiskBlock(request: ApprovalRequest) {
    val reasons = request.risk.reasonsKo.filter { it.isNotBlank() }
    val level = request.risk.level
    if (reasons.isEmpty() && level.effective != dev.agentnest.core.protocol.RiskLevel.HIGH &&
        level.effective != dev.agentnest.core.protocol.RiskLevel.CRITICAL
    ) {
        return
    }
    val tone = Labels.riskTone(level)
    val colors = dev.agentnest.app.ui.theme.ToneTheme.colors(tone, dev.agentnest.app.ui.theme.isDarkTheme())
    InfoCard(container = colors.container) {
        Text(
            text = if (reasons.isEmpty()) Labels.risk(level) else "${Labels.risk(level)} — ${reasons.joinToString(", ")}",
            style = MaterialTheme.typography.bodyMedium,
            color = colors.content,
        )
    }
}

/** The agent's own explanation: small, dim and below the facts that matter; never a reason to approve. */
@Composable
private fun PurposeBlock(request: ApprovalRequest) {
    val purpose = request.purpose?.takeIf { it.isNotBlank() } ?: return
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(
            text = S.AGENT_SAYS_UNVERIFIED,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.8f),
        )
        Text(
            text = "“$purpose”",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.8f),
        )
    }
}
