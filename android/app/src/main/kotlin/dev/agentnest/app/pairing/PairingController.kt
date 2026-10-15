package dev.agentnest.app.pairing

import dev.agentnest.core.crypto.SpkiPin
import dev.agentnest.core.link.DeviceDescriptor
import dev.agentnest.core.link.PairingResult
import dev.agentnest.core.link.WsTransport
import dev.agentnest.core.protocol.QrPayload
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Owns the (at most one) running [PairingSession] and turns its state into [PairingUiState]. It lives as long as the
 * process, so a rotation or a short app switch does not lose a pairing in progress.
 *
 * [persist] must seal the device token into the Keystore vault and write the pairing data; it runs before the screen
 * can reach [PairingUiState.Done], and it is NOT cancellable: once the PC accepted the pairing, leaving the screen
 * cannot leave half of a pairing on disk (a [cancel] during [PairingUiState.Saving] is ignored). If it fails,
 * [rollback] erases every trace (stored pairing and both Keystore entries) and the screen shows an error; the PC still
 * lists the device and the user removes it there. [onPersisted] starts the link service.
 *
 * Every pairing owns one transport (an OkHttp client with threads); [transportShutdown] releases it on EVERY terminal
 * path (failure, completion, cancel), after a short grace period so a queued `unpair` / close frame can still leave.
 */
class PairingController(
    private val scope: CoroutineScope,
    private val transportFactory: (SpkiPin) -> WsTransport,
    private val devicePublicKey: () -> ByteArray?,
    private val device: () -> DeviceDescriptor,
    private val persist: suspend (PairingResult) -> Unit,
    private val onPersisted: () -> Unit,
    private val rollback: suspend () -> Unit = {},
    private val transportShutdown: (WsTransport) -> Unit = {},
    private val shutdownGraceMs: Long = TRANSPORT_GRACE_MS,
) {
    private val stateFlow = MutableStateFlow<PairingUiState>(PairingUiState.Idle)
    private var session: PairingSession? = null
    private var watcher: Job? = null
    private var transport: WsTransport? = null

    /** The pairing screen state. */
    val state: StateFlow<PairingUiState> get() = stateFlow

    /** True while a scan or a pairing is in progress (the screen must not start another). */
    val busy: Boolean
        get() = when (stateFlow.value) {
            PairingUiState.Scanning, is PairingUiState.Connecting, is PairingUiState.ShowingSas, PairingUiState.Saving -> true
            else -> false
        }

    /** The scanner opened. */
    fun onScanStarted() {
        if (!busy) stateFlow.value = PairingUiState.Scanning
    }

    /** The scan ended without a usable QR. */
    fun onScanFailed(messageKo: String) {
        stateFlow.value = PairingUiState.ScanError(messageKo)
    }

    /** The user closed the scanner. */
    fun onScanCancelled() {
        if (stateFlow.value == PairingUiState.Scanning) stateFlow.value = PairingUiState.Idle
    }

    /** A valid QR was scanned: start pairing with it. The QR's secret is wiped by the session on every end. */
    fun begin(qr: QrPayload, spki: ByteArray? = devicePublicKey()) {
        cancel()
        val newTransport = transportFactory(qr.pin)
        transport = newTransport
        val newSession = PairingSession(qr, device(), spki, newTransport, scope)
        session = newSession
        stateFlow.value = PairingUiState.Connecting(qr.hosts.firstOrNull() ?: "")
        watcher = scope.launch {
            newSession.state.collect { onSessionState(it) }
        }
        newSession.start()
    }

    /** The user left the screen or pressed cancel. */
    fun cancel() {
        // The token is being stored: this must finish (or roll back) on its own, never stop halfway.
        if (stateFlow.value == PairingUiState.Saving) return
        val running = session
        session = null
        watcher?.cancel()
        watcher = null
        running?.cancel()
        releaseTransport()
        if (busy) stateFlow.value = PairingUiState.Idle
    }

    /** Back to the intro (after [PairingUiState.Done] or an error). */
    fun reset() {
        if (!busy) stateFlow.value = PairingUiState.Idle
    }

    private suspend fun onSessionState(s: PairingSessionState) {
        when (s) {
            is PairingSessionState.Connecting -> stateFlow.value = PairingUiState.Connecting(s.host)
            is PairingSessionState.ShowingSas -> stateFlow.value = PairingUiState.ShowingSas(s.sas)
            is PairingSessionState.Failed -> {
                stateFlow.value = PairingUiState.Failed(s.messageKo)
                releaseTransport()
            }
            is PairingSessionState.Completed -> {
                stateFlow.value = PairingUiState.Saving
                val saved = withContext(NonCancellable) {
                    try {
                        persist(s.result)
                        true
                    } catch (e: Exception) {
                        // Half a pairing is worse than none: erase the stored pairing and both Keystore entries.
                        try {
                            rollback()
                        } catch (rollbackFailure: Exception) {
                            // Nothing more can be done; the next start finds no usable token and asks to pair again.
                        }
                        false
                    }
                }
                releaseTransport()
                if (saved) {
                    stateFlow.value = PairingUiState.Done
                    onPersisted()
                } else {
                    stateFlow.value = PairingUiState.Failed(SAVE_FAILED)
                }
            }
        }
    }

    /** Shuts the current pairing's transport down once, after the grace period (queued close / unpair frames leave first). */
    private fun releaseTransport() {
        val old = transport ?: return
        transport = null
        scope.launch {
            delay(shutdownGraceMs)
            transportShutdown(old)
        }
    }

    companion object {
        /** How long a finished pairing's sockets may still flush `unpair` / close frames before the client is shut down. */
        const val TRANSPORT_GRACE_MS: Long = 2_000
        private const val SAVE_FAILED = "페어링 정보를 안전하게 저장하지 못했어요. 다시 시도해 주세요"
    }
}
