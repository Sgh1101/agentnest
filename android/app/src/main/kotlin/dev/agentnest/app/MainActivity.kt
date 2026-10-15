package dev.agentnest.app

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.FragmentActivity
import dev.agentnest.app.approval.UserAuthenticator
import dev.agentnest.app.auth.BiometricGate
import dev.agentnest.app.nav.DeepLink
import dev.agentnest.app.qr.GmsQrScanner
import dev.agentnest.app.qr.QrScanner
import dev.agentnest.app.ui.AgentNestRoot

/**
 * The single Activity. It extends `FragmentActivity` because `BiometricPrompt` needs one (androidx.biometric 1.1.0).
 * It is also the [ActivityHost]: the system prompt, the QR scanner and the permission request all need an Activity.
 */
class MainActivity : FragmentActivity(), ActivityHost {
    private val container: AppContainer get() = (application as AgentNestApp).container

    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* the settings screen shows the result */ }

    override val authenticator: UserAuthenticator by lazy { BiometricGate(this) }
    override val qrScanner: QrScanner by lazy { GmsQrScanner(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        container.controller.attach(this)
        handleIntent(intent)
        setContent { AgentNestRoot(container.controller) }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    override fun onStart() {
        super.onStart()
        container.onAppStarted()
    }

    override fun onStop() {
        container.repository.setAppVisible(false)
        super.onStop()
    }

    override fun onDestroy() {
        container.controller.detach(this)
        super.onDestroy()
    }

    override fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    override fun launchSafely(intent: Intent) {
        try {
            startActivity(intent)
        } catch (e: ActivityNotFoundException) {
            // No handler for this settings screen on this device: nothing to do.
        }
    }

    /** `agentnest://approval/{request_id}` from a notification opens the detail screen. It never decides anything. */
    private fun handleIntent(intent: Intent?) {
        val id = DeepLink.approvalId(intent?.dataString) ?: return
        container.emitApprovalLink(id)
    }
}
