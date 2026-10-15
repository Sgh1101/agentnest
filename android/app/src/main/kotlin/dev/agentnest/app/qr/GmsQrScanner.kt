package dev.agentnest.app.qr

import android.app.Activity
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * QR scanning through the Google Play services code scanner (docs/android.md 4.3): Google provides the scanner UI and
 * the model, so the app needs no CAMERA permission and ships no camera code. Restricted to QR codes.
 *
 * UNVERIFIED (Phase 0) P3: the dependency version (play-services-code-scanner 16.1.0) comes from Google's sample build
 * file; Google Maven could not be reached when this was written. The API shape used here matches that sample. The whole
 * dependency stays behind [QrScanner], so a camera/zxing implementation can replace it without touching any screen.
 */
class GmsQrScanner(private val activity: Activity) : QrScanner {
    override suspend fun scan(): QrScanResult = suspendCancellableCoroutine { continuation ->
        val options = GmsBarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .build()
        val scanner = GmsBarcodeScanning.getClient(activity, options)
        scanner.startScan()
            .addOnSuccessListener { barcode: Barcode ->
                val text = barcode.rawValue
                if (continuation.isActive) continuation.resume(if (text.isNullOrEmpty()) QrScanResult.Failed else QrScanResult.Scanned(text))
            }
            .addOnCanceledListener {
                if (continuation.isActive) continuation.resume(QrScanResult.Cancelled)
            }
            .addOnFailureListener { _: Exception ->
                if (continuation.isActive) continuation.resume(QrScanResult.Failed)
            }
    }
}
