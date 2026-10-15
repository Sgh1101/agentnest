package dev.agentnest.app.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.agentnest.app.approval.AuthAvailability
import dev.agentnest.app.data.PairedInfo
import dev.agentnest.app.data.SettingsState
import dev.agentnest.app.ui.AppController
import dev.agentnest.app.ui.S
import dev.agentnest.app.ui.Tone
import dev.agentnest.app.ui.common.InfoCard
import dev.agentnest.app.ui.common.KeyValueRow
import dev.agentnest.app.ui.common.ScreenHeader
import dev.agentnest.app.ui.common.SectionLabel
import dev.agentnest.app.ui.common.ToneChip
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.text.Fallbacks
import java.time.Instant

/** Navigation callbacks of the settings tab. */
data class SettingsActions(
    val onOpenDevices: () -> Unit,
    val onOpenDiagnostics: () -> Unit,
    val onStartPairing: () -> Unit,
)

/** Settings tab: connection, notifications, the character, read-only PC security policy, battery advice, about. */
@Composable
fun SettingsScreen(
    nest: NestState,
    now: Instant,
    settings: SettingsState,
    paired: PairedInfo?,
    controller: AppController,
    actions: SettingsActions,
    modifier: Modifier = Modifier,
) {
    // System queries are cheap but not free: refresh them every ten seconds instead of on every clock tick.
    val refreshKey = now.epochSecond / 10
    val notificationsAllowed = remember(refreshKey) { controller.notificationsAllowed() }
    val authReady = remember(refreshKey) { controller.authAvailability() == AuthAvailability.READY }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(bottom = 16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        ScreenHeader(title = S.TAB_SETTINGS, onBack = null)

        SectionLabel(S.SECTION_CONNECTION)
        InfoCard(modifier = Modifier.padding(horizontal = 16.dp)) {
            if (paired == null) {
                Text(S.NOT_PAIRED, style = MaterialTheme.typography.bodyLarge)
                Button(onClick = actions.onStartPairing) { Text(S.PAIR_PC) }
            } else {
                Text(paired.pcName.ifBlank { paired.pcId }, style = MaterialTheme.typography.titleMedium)
                Text(
                    Fallbacks.linkHeadline(nest.link, now).ifBlank { S.CONNECTED },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (nest.link is LinkState.Connected) ToneChip(S.CONNECTED, Tone.SUCCESS)
                OutlinedButton(onClick = actions.onOpenDevices) { Text(S.MANAGE_DEVICE) }
            }
        }

        SectionLabel(S.SECTION_NOTIFICATIONS)
        InfoCard(modifier = Modifier.padding(horizontal = 16.dp)) {
            if (!notificationsAllowed) {
                Text(S.NOTIFICATIONS_OFF_WARNING, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
                Button(onClick = controller::requestNotificationPermission) { Text(S.ALLOW_NOTIFICATIONS) }
            }
            OutlinedButton(onClick = controller::openNotificationSettings) { Text(S.OPEN_NOTIFICATION_SETTINGS) }
            SwitchRow(S.AUTO_START, S.AUTO_START_HELP, settings.autoStartOnBoot, controller::setAutoStartOnBoot)
        }

        SectionLabel(S.SECTION_KONGI)
        InfoCard(modifier = Modifier.padding(horizontal = 16.dp)) {
            SwitchRow(S.ANIMATIONS, S.ANIMATIONS_HELP, settings.animationsEnabled, controller::setAnimationsEnabled)
            SwitchRow(S.SOUND, S.SOUND_HELP, settings.soundEnabled, controller::setSoundEnabled)
            SwitchRow(S.REDUCED_MOTION, S.REDUCED_MOTION_HELP, settings.reducedMotion, controller::setReducedMotion)
        }

        SectionLabel(S.SECTION_SECURITY)
        InfoCard(modifier = Modifier.padding(horizontal = 16.dp)) {
            Text(S.SECURITY_READONLY, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            val policy = nest.welcome?.policy
            KeyValueRow(
                S.DENY_REQUIRES_AUTH,
                when {
                    policy == null -> S.UNKNOWN
                    policy.denyRequiresAuth -> S.ON
                    else -> S.OFF
                },
            )
            KeyValueRow(
                S.DEVICE_LOCK,
                if (authReady) S.AVAILABLE else S.SETUP_DEVICE_LOCK,
            )
        }

        SectionLabel(S.SECTION_BATTERY)
        InfoCard(modifier = Modifier.padding(horizontal = 16.dp)) {
            Text(S.BATTERY_HELP, style = MaterialTheme.typography.bodyMedium)
            OutlinedButton(onClick = controller::openBatterySettings) { Text(S.OPEN_BATTERY_SETTINGS) }
        }

        SectionLabel(S.SECTION_ABOUT)
        InfoCard(modifier = Modifier.padding(horizontal = 16.dp)) {
            KeyValueRow(S.APP_VERSION, S.APP_VERSION_VALUE)
            OutlinedButton(onClick = actions.onOpenDiagnostics) { Text(S.DIAGNOSTICS) }
        }
    }
}

@Composable
private fun SwitchRow(title: String, help: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(help, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}
