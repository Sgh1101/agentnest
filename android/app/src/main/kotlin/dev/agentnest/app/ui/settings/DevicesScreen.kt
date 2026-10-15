package dev.agentnest.app.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.agentnest.app.data.PairedInfo
import dev.agentnest.app.ui.AppController
import dev.agentnest.app.ui.S
import dev.agentnest.app.ui.common.InfoCard
import dev.agentnest.app.ui.common.KeyValueRow
import dev.agentnest.app.ui.common.ManualHostDialog
import dev.agentnest.app.ui.common.RepairDialog
import dev.agentnest.app.ui.common.ScreenHeader
import dev.agentnest.app.ui.common.SectionLabel
import kotlinx.coroutines.launch

/**
 * Devices (docs/android.md 2.3): the paired PC, its stored addresses, "IP 직접 입력", an address refresh by QR rescan,
 * disconnect (`unpair`) and re-pairing. Nothing here shows the pin or any token.
 */
@Composable
fun DevicesScreen(
    paired: PairedInfo?,
    controller: AppController,
    onBack: () -> Unit,
    onUnpaired: () -> Unit,
    onRepaired: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    var showManual by remember { mutableStateOf(false) }
    var showUnpair by remember { mutableStateOf(false) }
    var showRepair by remember { mutableStateOf(false) }
    var notice by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(bottom = 16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        ScreenHeader(title = S.DEVICES, onBack = onBack)
        if (paired == null) {
            Text(S.NOT_PAIRED, modifier = Modifier.padding(16.dp))
            return@Column
        }
        SectionLabel(S.THIS_DEVICE)
        InfoCard(modifier = Modifier.padding(horizontal = 16.dp)) {
            Text(paired.pcName.ifBlank { paired.pcId }, style = MaterialTheme.typography.titleMedium)
            KeyValueRow(S.PC_ID, paired.pcId)
            KeyValueRow(S.DEVICE_ID, paired.deviceId)
        }
        SectionLabel(S.SAVED_ADDRESSES)
        InfoCard(modifier = Modifier.padding(horizontal = 16.dp)) {
            if (paired.hosts.isEmpty()) Text(S.NO_ADDRESSES)
            paired.hosts.forEach { Text(it, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium) }
            OutlinedButton(onClick = { showManual = true }) { Text(S.MANUAL_HOST) }
            OutlinedButton(onClick = {
                scope.launch { notice = controller.rescanAddresses() }
            }) { Text(S.RESCAN_QR) }
            notice?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
        SectionLabel(S.DANGER_ZONE)
        InfoCard(modifier = Modifier.padding(horizontal = 16.dp)) {
            Button(onClick = { showUnpair = true }) { Text(S.UNPAIR) }
            OutlinedButton(onClick = { showRepair = true }) { Text(S.REPAIR) }
        }
    }

    if (showManual) {
        ManualHostDialog(onSubmit = controller::addManualHost, onDismiss = { showManual = false })
    }
    if (showUnpair) {
        AlertDialog(
            onDismissRequest = { showUnpair = false },
            title = { Text(S.UNPAIR) },
            text = { Text(S.UNPAIR_WARNING) },
            confirmButton = {
                TextButton(onClick = {
                    showUnpair = false
                    controller.unpair()
                    onUnpaired()
                }) { Text(S.UNPAIR) }
            },
            dismissButton = { TextButton(onClick = { showUnpair = false }) { Text(S.CANCEL) } },
        )
    }
    if (showRepair) {
        RepairDialog(
            onConfirm = {
                showRepair = false
                controller.repair()
                onRepaired()
            },
            onDismiss = { showRepair = false },
        )
    }
}
