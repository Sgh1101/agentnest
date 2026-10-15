package dev.agentnest.app

import android.app.Application
import android.content.Intent
import android.os.PowerManager
import android.provider.Settings
import androidx.core.app.NotificationManagerCompat
import dev.agentnest.app.approval.AuthAvailability
import dev.agentnest.app.approval.DecisionSubmitter
import dev.agentnest.app.approval.SubmitOutcome
import dev.agentnest.app.character.SystemMotion
import dev.agentnest.app.data.PairedInfo
import dev.agentnest.app.data.SettingsState
import dev.agentnest.app.pairing.PairingUiState
import dev.agentnest.app.qr.QrScanResult
import dev.agentnest.app.service.LinkService
import dev.agentnest.app.ui.AppController
import dev.agentnest.core.approval.DecisionBuilder
import dev.agentnest.core.link.EventsPager
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.QrParseResult
import dev.agentnest.core.protocol.QrPayload
import dev.agentnest.core.protocol.ServerMessage
import dev.agentnest.core.util.HostAddress
import dev.agentnest.core.util.Uuid7Generator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant

/**
 * The Android side of [AppController]: wires the screens to the repository, the stores, the vault, the link service
 * and the Activity-bound pieces (authentication prompt, QR scanner). `MainActivity` attaches itself as [ActivityHost]
 * while it exists. This class contains no protocol or validation logic; that lives in `android/core`.
 */
class AndroidAppController(
    private val app: Application,
    private val container: AppContainer,
) : AppController {
    @Volatile
    private var host: ActivityHost? = null
    private val ids = Uuid7Generator()

    /** Scanner and prompt callbacks must start on the main thread. */
    private val uiScope = MainScope()
    private val repository = container.repository

    /** Called by the Activity in onCreate. */
    fun attach(newHost: ActivityHost) {
        host = newHost
        newHost.setSecure(secureCount > 0)
    }

    /** Called by the Activity in onDestroy. */
    fun detach(oldHost: ActivityHost) {
        if (host === oldHost) host = null
    }

    /** Number of visible screens that need a secure window (approval detail, pairing). Main thread only. */
    private var secureCount = 0

    // --- state ---------------------------------------------------------------------------------

    override val nest: StateFlow<NestState> get() = repository.nest
    override val settings: StateFlow<SettingsState> get() = container.settings.state
    override val paired: StateFlow<PairedInfo?> get() = container.paired
    override val pairing: StateFlow<PairingUiState> get() = container.pairingController.state
    override val paused: StateFlow<Boolean> get() = repository.paused
    override val appVisible: StateFlow<Boolean> get() = repository.appVisible
    override val keyResetNotice: StateFlow<Boolean> get() = container.settings.keyResetNotice
    override val incoming: SharedFlow<ServerMessage> get() = repository.incoming
    override val approvalLinks: Flow<String> get() = container.approvalLinks.receiveAsFlow()
    override val ready: StateFlow<Boolean> get() = container.ready

    // --- system queries ------------------------------------------------------------------------

    override fun authAvailability(): AuthAvailability = host?.authenticator?.availability() ?: AuthAvailability.UNAVAILABLE

    override fun notificationsAllowed(): Boolean = NotificationManagerCompat.from(app).areNotificationsEnabled()

    override fun systemMotion(): SystemMotion {
        val scale = try {
            Settings.Global.getFloat(app.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f)
        } catch (e: Exception) {
            1f
        }
        if (scale == 0f) return SystemMotion.DISABLED
        val power = app.getSystemService(PowerManager::class.java)
        return if (power != null && power.isPowerSaveMode) SystemMotion.POWER_SAVE else SystemMotion.NORMAL
    }

    // --- link ----------------------------------------------------------------------------------

    override fun reconnect() {
        if (repository.connectedToService) repository.connectNow() else container.startLinkService()
    }

    override fun refresh() {
        repository.refresh()
    }

    override fun repair() {
        if (repository.connectedToService) {
            repository.repair()
        } else {
            wipeWithoutService()
        }
    }

    override fun unpair() {
        if (repository.connectedToService) {
            repository.unpair()
        } else {
            wipeWithoutService()
        }
    }

    /** No client is running (revoked earlier, service paused): erase the local pairing directly. */
    private fun wipeWithoutService() {
        container.scope.launch(container.storeDispatcher) {
            container.wipePairingLocal()
            repository.restore(null, null, paired = false)
        }
    }

    override fun addManualHost(address: String): Boolean {
        val trimmed = address.trim()
        if (!HostAddress.isValidHost(trimmed)) return false
        val running = repository.hostBook()
        if (running != null) {
            val updated = running.withManual(trimmed)
            repository.onHostsChanged(updated)
            container.scope.launch(container.storeDispatcher) { container.pairingStore.saveHosts(updated) }
        } else {
            container.scope.launch(container.storeDispatcher) {
                val data = container.pairingStore.load() ?: return@launch
                container.pairingStore.saveHosts(data.hosts.withManual(trimmed))
                container.startLinkService()
            }
        }
        return true
    }

    override suspend fun rescanAddresses(): String {
        val current = host ?: return MSG_TRY_LATER
        val text = when (val result = current.qrScanner.scan()) {
            QrScanResult.Cancelled -> return MSG_SCAN_CANCELLED
            QrScanResult.Failed -> return MSG_SCAN_FAILED
            is QrScanResult.Scanned -> result.text
        }
        val qr: QrPayload = when (val parsed = QrPayload.parse(text, Instant.now())) {
            is QrParseResult.Failure -> return parsed.error.messageKo
            is QrParseResult.Success -> parsed.payload
        }
        try {
            val data = container.pairingStore.load()
            val samePc = data != null && qr.pcId == data.pcId && qr.pin.toPinString() == data.pinString
            if (data == null || !samePc) return MSG_OTHER_PC
            // Only addresses and the port are taken over; the identity (pin, pc_id) must match what is stored.
            val updated = data.hosts.copy(
                port = qr.port,
                welcome = emptyList(),
                qr = qr.hosts.take(dev.agentnest.core.link.HostBookState.MAX_STORED),
                lastSuccess = null,
            )
            container.pairingStore.saveHosts(updated)
            if (repository.connectedToService) repository.onHostsChanged(updated) else container.startLinkService()
            return MSG_ADDRESSES_UPDATED
        } finally {
            qr.wipe()
        }
    }

    // --- pairing -------------------------------------------------------------------------------

    override fun startPairingScan() {
        val current = host ?: return
        val controller = container.pairingController
        if (controller.busy) return
        controller.onScanStarted()
        uiScope.launch {
            when (val result = current.qrScanner.scan()) {
                QrScanResult.Cancelled -> controller.onScanCancelled()
                QrScanResult.Failed -> controller.onScanFailed(MSG_SCAN_FAILED)
                is QrScanResult.Scanned -> when (val parsed = QrPayload.parse(result.text, Instant.now())) {
                    is QrParseResult.Failure -> controller.onScanFailed(parsed.error.messageKo)
                    is QrParseResult.Success -> {
                        // Keystore work (the first call generates an EC key, which can take hundreds of ms) stays off the main thread.
                        val spki = withContext(Dispatchers.Default) { container.deviceKey.publicKeySpki() }
                        if (spki == null) {
                            parsed.payload.wipe()
                            controller.onScanFailed(MSG_NO_DEVICE_KEY)
                        } else {
                            controller.begin(parsed.payload, spki)
                        }
                    }
                }
            }
        }
    }

    override fun cancelPairing() {
        container.pairingController.cancel()
    }

    override fun resetPairing() {
        container.pairingController.reset()
    }

    // --- approvals -----------------------------------------------------------------------------

    override suspend fun decide(
        requestId: String,
        decision: Decision,
        extra: ExtraConfirmationLevel,
        reason: String?,
    ): SubmitOutcome {
        val current = host ?: return SubmitOutcome.AuthFailed(MSG_REOPEN)
        return DecisionSubmitter(repository, current.authenticator).submit(requestId, decision, extra, reason)
    }

    override fun markSeen(requestId: String) {
        container.approvalNotifier.cancel(requestId)
        container.scope.launch {
            repository.send(DecisionBuilder().seen(requestId, Instant.now()))
        }
    }

    override fun setScreenSecure(secure: Boolean) {
        secureCount = (secureCount + if (secure) 1 else -1).coerceAtLeast(0)
        host?.setSecure(secureCount > 0)
    }

    // --- history -------------------------------------------------------------------------------

    override suspend fun requestEvents(pager: EventsPager): EventsPager {
        val state = repository.nest.value
        // The first request starts right before the oldest cached event (before_seq is exclusive).
        val firstPageBeforeSeq = state.recentEvents.minOfOrNull { it.seq } ?: (state.lastSeq + 1)
        val started = pager.next(firstPageBeforeSeq, PAGE_SIZE, ids.next(), Instant.now())
        val message = started.message ?: return pager
        return if (repository.send(message)) started.pager else pager
    }

    // --- settings / system screens -------------------------------------------------------------

    override fun setAnimationsEnabled(enabled: Boolean) {
        container.scope.launch { container.settings.setAnimationsEnabled(enabled) }
    }

    override fun setSoundEnabled(enabled: Boolean) {
        container.scope.launch { container.settings.setSoundEnabled(enabled) }
    }

    override fun setReducedMotion(enabled: Boolean) {
        container.scope.launch { container.settings.setReducedMotion(enabled) }
    }

    override fun setAutoStartOnBoot(enabled: Boolean) {
        container.scope.launch { container.settings.setAutoStartOnBoot(enabled) }
    }

    override fun requestNotificationPermission() {
        host?.requestNotificationPermission()
    }

    override fun openNotificationSettings() {
        val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, app.packageName)
        host?.launchSafely(intent)
    }

    override fun openBatterySettings() {
        host?.launchSafely(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
    }

    private companion object {
        const val PAGE_SIZE = 50
        const val MSG_TRY_LATER = "잠시 뒤에 다시 시도해 주세요"
        const val MSG_REOPEN = "앱 화면을 다시 열고 시도해 주세요"
        const val MSG_SCAN_CANCELLED = "스캔을 취소했어요"
        const val MSG_SCAN_FAILED = "QR을 읽지 못했어요. 다시 시도해 주세요"
        const val MSG_OTHER_PC = "다른 PC의 QR이에요. 연결된 PC의 QR만 쓸 수 있어요"
        const val MSG_ADDRESSES_UPDATED = "PC 주소를 갱신했어요"
        const val MSG_NO_DEVICE_KEY = "이 기기의 보안 키를 만들 수 없어요. 기기 잠금이 설정되어 있는지 확인해 주세요"
    }
}
