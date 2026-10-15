package dev.agentnest.app.ui.common

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import dev.agentnest.app.ui.S
import dev.agentnest.app.ui.Tone
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.text.Fallbacks
import java.time.Instant

/** What the user can do about a link problem. */
data class LinkBannerActions(
    val onReconnect: () -> Unit,
    /** Called after the user confirmed '다시 페어링' in the dialog (the caller wipes and navigates). */
    val onRepair: () -> Unit,
    /** Returns false when the text is not a valid host. */
    val onManualHost: (String) -> Boolean,
    val onRescanQr: () -> Unit,
)

/** The tone and text of the banner for [link]; null when the link is fine. Pure, so it can be tested. */
data class LinkBannerModel(val text: String, val tone: Tone, val canReconnect: Boolean, val needsRepair: Boolean, val unreachable: Boolean)

/** Chooses what the banner says (docs/android.md 2.1 / 3.2). */
object LinkBannerLogic {
    /** Null for a healthy, running link (and for an unpaired app, which has its own call to action). */
    fun model(link: LinkState, paused: Boolean, now: Instant): LinkBannerModel? {
        if (paused) return LinkBannerModel(S.LINK_PAUSED, Tone.MUTED, canReconnect = true, needsRepair = false, unreachable = false)
        return when (link) {
            is LinkState.Connected, LinkState.Unpaired -> null
            is LinkState.Connecting, LinkState.Challenged ->
                LinkBannerModel(Fallbacks.linkHeadline(link, now), Tone.INFO, canReconnect = false, needsRepair = false, unreachable = false)
            is LinkState.Reconnecting ->
                LinkBannerModel(Fallbacks.linkHeadline(link, now), Tone.WARNING, canReconnect = true, needsRepair = false, unreachable = false)
            LinkState.Offline ->
                LinkBannerModel(Fallbacks.linkHeadline(link, now), Tone.MUTED, canReconnect = false, needsRepair = false, unreachable = false)
            is LinkState.PcUnreachable ->
                LinkBannerModel(Fallbacks.linkHeadline(link, now), Tone.WARNING, canReconnect = true, needsRepair = false, unreachable = true)
            is LinkState.NeedsRepair, is LinkState.Revoked, is LinkState.Suspended ->
                LinkBannerModel(Fallbacks.linkHeadline(link, now), Tone.DANGER, canReconnect = false, needsRepair = true, unreachable = false)
            LinkState.Incompatible ->
                LinkBannerModel(Fallbacks.linkHeadline(link, now), Tone.DANGER, canReconnect = false, needsRepair = false, unreachable = false)
        }
    }
}

/** Banner under the home status row for every non-connected link state; shows the recovery actions that apply. */
@Composable
fun LinkBanner(
    link: LinkState,
    paused: Boolean,
    now: Instant,
    actions: LinkBannerActions,
    modifier: Modifier = Modifier,
) {
    val model = LinkBannerLogic.model(link, paused, now) ?: return
    var showManual by remember { mutableStateOf(false) }
    var showRepair by remember { mutableStateOf(false) }

    InfoCard(modifier = modifier.padding(horizontal = 16.dp), container = bannerColor(model.tone)) {
        Text(model.text)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (model.canReconnect) {
                OutlinedButton(onClick = actions.onReconnect) { Text(S.RECONNECT) }
            }
            if (model.unreachable) {
                OutlinedButton(onClick = { showManual = true }) { Text(S.MANUAL_HOST) }
                OutlinedButton(onClick = actions.onRescanQr) { Text(S.RESCAN_QR) }
            }
            if (model.needsRepair) {
                Button(onClick = { showRepair = true }) { Text(S.REPAIR) }
            }
        }
    }

    if (showManual) {
        ManualHostDialog(onSubmit = actions.onManualHost, onDismiss = { showManual = false })
    }
    if (showRepair) {
        RepairDialog(onConfirm = {
            showRepair = false
            actions.onRepair()
        }, onDismiss = { showRepair = false })
    }
}

@Composable
private fun bannerColor(tone: Tone): androidx.compose.ui.graphics.Color =
    dev.agentnest.app.ui.theme.ToneTheme.colors(tone, dev.agentnest.app.ui.theme.isDarkTheme()).container

/** Text field for an IP address or host name; closes itself when the address was accepted. */
@Composable
fun ManualHostDialog(onSubmit: (String) -> Boolean, onDismiss: () -> Unit) {
    var text by remember { mutableStateOf("") }
    var invalid by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(S.MANUAL_HOST) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(S.MANUAL_HOST_HELP)
                OutlinedTextField(
                    value = text,
                    onValueChange = {
                        text = it
                        invalid = false
                    },
                    singleLine = true,
                    isError = invalid,
                    label = { Text(S.MANUAL_HOST_LABEL) },
                    supportingText = { if (invalid) Text(S.MANUAL_HOST_INVALID) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                if (onSubmit(text)) onDismiss() else invalid = true
            }) { Text(S.ADD) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(S.CANCEL) } },
    )
}

/** The warning shown before the local pairing is erased (docs/android.md 3.2). */
@Composable
fun RepairDialog(onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(S.REPAIR) },
        text = { Text(S.REPAIR_WARNING) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(S.REPAIR) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(S.CANCEL) } },
    )
}
