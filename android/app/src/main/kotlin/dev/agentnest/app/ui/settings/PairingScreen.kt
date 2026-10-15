package dev.agentnest.app.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.agentnest.app.pairing.PairingUiState
import dev.agentnest.app.ui.AppController
import dev.agentnest.app.ui.S
import dev.agentnest.app.ui.common.InfoCard
import dev.agentnest.app.ui.common.ScreenHeader
import dev.agentnest.app.ui.common.SecureScreen

/** Formats the six SAS digits as "482 915". */
fun formatSas(sas: String): String = sas.chunked(3).joinToString(" ")

/**
 * Pairing flow (docs/android.md 2.3): intro -> QR scan -> "192.168.0.10 시도 중…" -> the phone-computed SAS plus
 * "PC에서 승인을 눌러 주세요" -> done (notification permission is requested right after, a user-initiated moment).
 * Leaving the screen cancels a pairing that is still running.
 */
@Composable
fun PairingScreen(
    state: PairingUiState,
    controller: AppController,
    onBack: () -> Unit,
    onDone: () -> Unit,
    modifier: Modifier = Modifier,
) {
    // The confirmation digits on this screen must not be screenshotted or recorded.
    SecureScreen(controller)
    DisposableEffect(Unit) {
        controller.resetPairing()
        onDispose { controller.cancelPairing() }
    }
    LaunchedEffect(state is PairingUiState.Done) {
        if (state is PairingUiState.Done && !controller.notificationsAllowed()) controller.requestNotificationPermission()
    }

    Column(modifier = modifier.fillMaxSize()) {
        ScreenHeader(title = S.PAIRING_TITLE, onBack = onBack)
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            when (state) {
                PairingUiState.Idle -> Intro(onScan = controller::startPairingScan)
                PairingUiState.Scanning -> Progress(S.PAIRING_SCANNING)
                is PairingUiState.ScanError -> Problem(state.messageKo, S.PAIRING_RETRY_SCAN, controller::startPairingScan)
                is PairingUiState.Connecting -> {
                    Progress("${state.host} ${S.PAIRING_TRYING}")
                    OutlinedButton(onClick = controller::cancelPairing) { Text(S.CANCEL) }
                }
                is PairingUiState.ShowingSas -> ShowSas(state.sas, onCancel = controller::cancelPairing)
                PairingUiState.Saving -> Progress(S.PAIRING_SAVING)
                PairingUiState.Done -> {
                    Text(S.PAIRING_DONE, style = MaterialTheme.typography.titleLarge)
                    Text(S.PAIRING_DONE_HELP, textAlign = TextAlign.Center)
                    Button(onClick = onDone) { Text(S.GO_HOME) }
                }
                is PairingUiState.Failed -> Problem(state.messageKo, S.PAIRING_RETRY_SCAN, controller::startPairingScan)
            }
        }
    }
}

@Composable
private fun Intro(onScan: () -> Unit) {
    InfoCard {
        Text(S.PAIRING_STEP_1, style = MaterialTheme.typography.bodyLarge)
        Text(S.PAIRING_STEP_2, style = MaterialTheme.typography.bodyLarge)
        Text(S.PAIRING_WARNING, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    Button(onClick = onScan) { Text(S.PAIRING_SCAN) }
}

@Composable
private fun Progress(text: String) {
    CircularProgressIndicator()
    Text(text, style = MaterialTheme.typography.bodyLarge, textAlign = TextAlign.Center)
}

@Composable
private fun Problem(message: String, action: String, onAction: () -> Unit) {
    Text(message, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.error, textAlign = TextAlign.Center)
    Button(onClick = onAction) { Text(action) }
}

@Composable
private fun ShowSas(sas: String, onCancel: () -> Unit) {
    Text(S.PAIRING_SAS_LABEL, style = MaterialTheme.typography.titleMedium)
    Text(
        text = formatSas(sas),
        fontSize = 44.sp,
        fontWeight = FontWeight.Bold,
        fontFamily = FontFamily.Monospace,
        textAlign = TextAlign.Center,
    )
    Text(S.PAIRING_SAS_HELP, textAlign = TextAlign.Center, style = MaterialTheme.typography.bodyLarge)
    CircularProgressIndicator()
    OutlinedButton(onClick = onCancel) { Text(S.CANCEL) }
}
