package dev.agentnest.app.pairing

import dev.agentnest.core.crypto.SpkiPin
import dev.agentnest.core.link.DeviceDescriptor
import dev.agentnest.core.link.PairingResult
import dev.agentnest.core.link.WsTransport
import dev.agentnest.core.protocol.QrPayload
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

/**
 * Owns the (at most one) running [PairingSession] and turns its state into [PairingUiState]. It lives as long as the
 * process, so a rotation or a short app switch does not lose a pairing in progress.
 *
 * [persist] must seal the device token into the Keystore vault and write the pairing data; it runs before the screen
 * can reach [PairingUiState.Done]. [onPersisted] starts the link service.
 */
class PairingController(
    private val scope: CoroutineScope,
    private val transportFactory: (SpkiPin) -> WsTransport,
    private val devicePublicKey: () -> ByteArray?,
    private val device: () -> DeviceDescriptor,
    private val persist: suspend (PairingResult) -> Unit,
    private val onPersisted: () -> Unit,
) {
    private val stateFlow = MutableStateFlow<PairingUiState>(PairingUiState.Idle)
    private var session: PairingSession? = null
    private var watcher: Job? = null

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
    fun begin(qr: QrPayload) {
        cancel()
        val spki = devicePublicKey()
        val newSession = PairingSession(qr, device(), spki, transportFactory(qr.pin), scope)
        session = newSession
        stateFlow.value = PairingUiState.Connecting(qr.hosts.firstOrNull() ?: "")
        watcher = scope.launch {
            newSession.state.collect { onSessionState(it) }
        }
        newSession.start()
    }

    /** The user left the screen or pressed cancel. */
    fun cancel() {
        val running = session
        session = null
        watcher?.cancel()
        watcher = null
        running?.cancel()
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
            is PairingSessionState.Failed -> stateFlow.value = PairingUiState.Failed(s.messageKo)
            is PairingSessionState.Completed -> {
                stateFlow.value = PairingUiState.Saving
                try {
                    persist(s.result)
                    stateFlow.value = PairingUiState.Done
                    onPersisted()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    stateFlow.value = PairingUiState.Failed(SAVE_FAILED)
                }
            }
        }
    }

    private companion object {
        const val SAVE_FAILED = "페어링 정보를 안전하게 저장하지 못했어요. 다시 시도해 주세요"
    }
}
