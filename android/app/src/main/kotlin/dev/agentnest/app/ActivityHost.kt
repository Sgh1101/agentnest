package dev.agentnest.app

import android.content.Intent
import dev.agentnest.app.approval.UserAuthenticator
import dev.agentnest.app.qr.QrScanner

/**
 * What only an Activity can do: show the system authentication prompt, open the QR scanner, ask for the notification
 * permission, start system settings screens. `MainActivity` registers itself with the controller while it exists.
 */
interface ActivityHost {
    val authenticator: UserAuthenticator
    val qrScanner: QrScanner

    /** Asks for POST_NOTIFICATIONS on Android 13+ (no-op earlier). */
    fun requestNotificationPermission()

    /** Starts [intent]; silently ignores a missing handler. */
    fun launchSafely(intent: Intent)
}
