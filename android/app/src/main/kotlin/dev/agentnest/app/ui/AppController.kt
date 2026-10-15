package dev.agentnest.app.ui

import dev.agentnest.app.approval.AuthAvailability
import dev.agentnest.app.character.SystemMotion
import dev.agentnest.app.approval.SubmitOutcome
import dev.agentnest.app.data.PairedInfo
import dev.agentnest.app.data.SettingsState
import dev.agentnest.app.pairing.PairingUiState
import dev.agentnest.core.link.EventsPager
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.ServerMessage
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Everything the Compose screens need from the rest of the app. The screens are stateless apart from view state and
 * talk only to this interface; the Android implementation lives in `AndroidAppController`. Nothing here can create an
 * approval decision without a user action (see `DecisionSubmitter`).
 */
interface AppController {
    // --- state ---------------------------------------------------------------------------------

    /** Sessions, approvals, link state, mood ... (docs/android.md 1.3). */
    val nest: StateFlow<NestState>

    /** User preferences. */
    val settings: StateFlow<SettingsState>

    /** The stored pairing (non-secret summary); null while unpaired. */
    val paired: StateFlow<PairedInfo?>

    /** Pairing screen state. */
    val pairing: StateFlow<PairingUiState>

    /** Paired but the link service is stopped. */
    val paused: StateFlow<Boolean>

    /** An Activity is started. */
    val appVisible: StateFlow<Boolean>

    /** True after the Keystore refused to open the stored token: pairing was wiped, show "다시 페어링" once. */
    val keyResetNotice: StateFlow<Boolean>

    /** Accepted server messages (for `events_page`). */
    val incoming: SharedFlow<ServerMessage>

    /** Notification deep links: request ids to open (each is delivered once). */
    val approvalLinks: Flow<String>

    /** False until the stored pairing was read; the UI shows an empty background until then. */
    val ready: StateFlow<Boolean>

    // --- system queries ------------------------------------------------------------------------

    /** Whether the device can authenticate the user (screen lock or biometric enrolled). */
    fun authAvailability(): AuthAvailability

    /** POST_NOTIFICATIONS granted and notifications not blocked. */
    fun notificationsAllowed(): Boolean

    /** System animation scale / battery saver state (re-read each time it is called). */
    fun systemMotion(): SystemMotion

    // --- link ----------------------------------------------------------------------------------

    /** "다시 연결": restart the service if it is stopped, otherwise reset the backoff. */
    fun reconnect()

    /** Pull to refresh (`snapshot_request`). */
    fun refresh()

    /** '다시 페어링' was confirmed: wipe everything stored and return to the unpaired state. */
    fun repair()

    /** Disconnect from the PC (`unpair`) and wipe the local pairing. */
    fun unpair()

    /** Adds a manually entered PC address; false when the text is not a valid host. */
    fun addManualHost(address: String): Boolean

    /** Scans the PC's "add device" QR again and, only for the same PC identity, refreshes its addresses. Returns a user message. */
    suspend fun rescanAddresses(): String

    // --- pairing -------------------------------------------------------------------------------

    /** Opens the scanner and starts pairing with the scanned QR. */
    fun startPairingScan()

    /** Aborts a pairing in progress. */
    fun cancelPairing()

    /** Clears an old pairing result/error so the screen starts at the intro. */
    fun resetPairing()

    // --- approvals -----------------------------------------------------------------------------

    /**
     * Runs the full decision flow for a card: validation, authentication when required, build, send.
     * [extra] is what the user completed in the UI (hold / re-confirm). Never queues.
     */
    suspend fun decide(requestId: String, decision: Decision, extra: ExtraConfirmationLevel, reason: String? = null): SubmitOutcome

    /** The card was shown: best-effort `approval_seen` and cancel the notification. */
    fun markSeen(requestId: String)

    // --- history -------------------------------------------------------------------------------

    /** Requests the next page of events and returns the pager with the request marked pending. */
    suspend fun requestEvents(pager: EventsPager): EventsPager

    // --- settings / system screens -------------------------------------------------------------

    fun setAnimationsEnabled(enabled: Boolean)
    fun setSoundEnabled(enabled: Boolean)
    fun setReducedMotion(enabled: Boolean)
    fun setAutoStartOnBoot(enabled: Boolean)

    /** Asks for POST_NOTIFICATIONS (Android 13+); opens the app notification settings when it was denied for good. */
    fun requestNotificationPermission()

    /** Opens the system notification settings of this app (channel toggles, quiet hours). */
    fun openNotificationSettings()

    /** Opens the system battery optimisation settings (never requested automatically). */
    fun openBatterySettings()
}
