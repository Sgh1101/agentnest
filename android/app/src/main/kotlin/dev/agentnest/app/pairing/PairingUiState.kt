package dev.agentnest.app.pairing

/** State of the pairing flow as the screens see it (docs/android.md 2.3, security.md 4.2). */
sealed interface PairingUiState {
    /** Nothing in progress: show the intro and the scan button. */
    data object Idle : PairingUiState

    /** The Google code scanner is open. */
    data object Scanning : PairingUiState

    /** The scan produced no usable QR. [messageKo] is user-facing. */
    data class ScanError(val messageKo: String) : PairingUiState

    /** Trying PC address [host]. */
    data class Connecting(val host: String) : PairingUiState

    /** The phone-computed SAS; the user must press approve on the PC. */
    data class ShowingSas(val sas: String) : PairingUiState

    /** The PC accepted; the token is being sealed into the Keystore vault. */
    data object Saving : PairingUiState

    /** Paired and stored; the link service has been started. */
    data object Done : PairingUiState

    data class Failed(val messageKo: String) : PairingUiState
}
