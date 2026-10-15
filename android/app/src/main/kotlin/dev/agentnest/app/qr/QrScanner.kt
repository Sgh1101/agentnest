package dev.agentnest.app.qr

/** Outcome of one scan. The scanned text contains the pairing secret: never log or persist it. */
sealed interface QrScanResult {
    data class Scanned(val text: String) : QrScanResult {
        override fun toString(): String = "Scanned(<redacted>)"
    }

    data object Cancelled : QrScanResult
    data object Failed : QrScanResult
}

/** Reads one QR code. Implementations are swappable (Google code scanner now, a camera/zxing fallback possible later). */
interface QrScanner {
    /** Opens the scanner UI and suspends until the user scans, cancels or it fails. */
    suspend fun scan(): QrScanResult
}
