package dev.agentnest.app.shots

import dev.agentnest.app.approval.AuthAvailability
import dev.agentnest.app.approval.SubmitOutcome
import dev.agentnest.app.character.SystemMotion
import dev.agentnest.app.data.PairedInfo
import dev.agentnest.app.data.SettingsState
import dev.agentnest.app.pairing.PairingUiState
import dev.agentnest.app.ui.AppController
import dev.agentnest.core.link.EventsPager
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.ServerMessage
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.emptyFlow

/**
 * A controller that only serves fixed state. Every action is a no-op, so a screenshot test can never send a decision
 * or touch the real link. Lives in androidTest only.
 */
class FakeAppController(
    nest: NestState,
    settings: SettingsState = SettingsState(animationsEnabled = false),
    paired: PairedInfo? = SD.PAIRED,
    pairing: PairingUiState = PairingUiState.Idle,
    paused: Boolean = false,
    keyReset: Boolean = false,
    private val auth: AuthAvailability = AuthAvailability.READY,
    private val notifications: Boolean = true,
) : AppController {
    override val nest: StateFlow<NestState> = MutableStateFlow(nest)
    override val settings: StateFlow<SettingsState> = MutableStateFlow(settings)
    override val paired: StateFlow<PairedInfo?> = MutableStateFlow(paired)
    override val pairing: StateFlow<PairingUiState> = MutableStateFlow(pairing)
    override val paused: StateFlow<Boolean> = MutableStateFlow(paused)

    /** False keeps the one-second clock and the character frame loop stopped (still frames). */
    override val appVisible: StateFlow<Boolean> = MutableStateFlow(false)
    override val keyResetNotice: StateFlow<Boolean> = MutableStateFlow(keyReset)
    override val incoming: SharedFlow<ServerMessage> = MutableSharedFlow()
    override val approvalLinks: Flow<String> = emptyFlow()
    override val ready: StateFlow<Boolean> = MutableStateFlow(true)

    override fun authAvailability(): AuthAvailability = auth
    override fun notificationsAllowed(): Boolean = notifications
    override fun systemMotion(): SystemMotion = SystemMotion.NORMAL

    override fun reconnect() = Unit
    override fun refresh() = Unit
    override fun repair() = Unit
    override fun unpair() = Unit
    override fun addManualHost(address: String): Boolean = true
    override suspend fun rescanAddresses(): String = ""

    override fun startPairingScan() = Unit
    override fun cancelPairing() = Unit
    override fun resetPairing() = Unit

    override suspend fun decide(requestId: String, decision: Decision, extra: ExtraConfirmationLevel, reason: String?): SubmitOutcome =
        SubmitOutcome.NotSent

    override fun markSeen(requestId: String) = Unit
    override fun setScreenSecure(secure: Boolean) = Unit
    override suspend fun requestEvents(pager: EventsPager): EventsPager = pager

    override fun setAnimationsEnabled(enabled: Boolean) = Unit
    override fun setSoundEnabled(enabled: Boolean) = Unit
    override fun setReducedMotion(enabled: Boolean) = Unit
    override fun setAutoStartOnBoot(enabled: Boolean) = Unit
    override fun requestNotificationPermission() = Unit
    override fun openNotificationSettings() = Unit
    override fun openBatterySettings() = Unit
}
