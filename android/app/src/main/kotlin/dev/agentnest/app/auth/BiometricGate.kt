package dev.agentnest.app.auth

import android.app.KeyguardManager
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import dev.agentnest.app.approval.AuthAvailability
import dev.agentnest.app.approval.AuthOutcome
import dev.agentnest.app.approval.AuthRequest
import dev.agentnest.app.approval.UserAuthenticator
import dev.agentnest.core.protocol.AuthMethod
import kotlinx.coroutines.suspendCancellableCoroutine
import java.time.Instant
import kotlin.coroutines.resume

/**
 * System authentication before an allow-type decision (docs/android.md 4.2): `BIOMETRIC_STRONG or DEVICE_CREDENTIAL`
 * with no negative button, so the device PIN/pattern is always the fallback. On API 26-29 the strong+credential combination
 * is not supported and `BIOMETRIC_WEAK or DEVICE_CREDENTIAL` is used after checking that a screen lock exists.
 * `setConfirmationRequired` is never used as a security control (the hold gate and re-confirm dialog are).
 *
 * Results are not turned into tokens: the caller gets the method and the phone time and must use them once.
 */
class BiometricGate(private val activity: FragmentActivity) : UserAuthenticator {

    private fun authenticators(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        } else {
            BiometricManager.Authenticators.BIOMETRIC_WEAK or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        }

    override fun availability(): AuthAvailability {
        val keyguard = activity.getSystemService(KeyguardManager::class.java)
        if (keyguard != null && !keyguard.isDeviceSecure) return AuthAvailability.NOT_ENROLLED
        return when (BiometricManager.from(activity).canAuthenticate(authenticators())) {
            BiometricManager.BIOMETRIC_SUCCESS -> AuthAvailability.READY
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> AuthAvailability.NOT_ENROLLED
            else -> AuthAvailability.UNAVAILABLE
        }
    }

    override suspend fun authenticate(request: AuthRequest): AuthOutcome = suspendCancellableCoroutine { continuation ->
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val method = if (result.authenticationType == BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC) {
                    AuthMethod.BIOMETRIC
                } else {
                    AuthMethod.DEVICE_CREDENTIAL
                }
                if (continuation.isActive) continuation.resume(AuthOutcome.Success(method, Instant.now()))
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (!continuation.isActive) return
                val outcome: AuthOutcome = when (errorCode) {
                    BiometricPrompt.ERROR_USER_CANCELED,
                    BiometricPrompt.ERROR_CANCELED,
                    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                    -> AuthOutcome.Cancelled
                    BiometricPrompt.ERROR_LOCKOUT,
                    BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
                    -> AuthOutcome.Failed("인증 시도가 너무 많아요. 잠시 뒤에 다시 시도해 주세요")
                    BiometricPrompt.ERROR_NO_BIOMETRICS,
                    BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
                    -> AuthOutcome.Failed("기기 잠금을 먼저 설정해 주세요")
                    else -> AuthOutcome.Failed("인증하지 못했어요. 다시 시도해 주세요")
                }
                continuation.resume(outcome)
            }

            // A wrong finger: the system prompt stays open and lets the user retry, nothing to do here.
            override fun onAuthenticationFailed() = Unit
        }
        val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(request.title)
            .setSubtitle(request.subtitle)
            .setDescription(request.description)
            .setAllowedAuthenticators(authenticators())
            .build()
        continuation.invokeOnCancellation { prompt.cancelAuthentication() }
        prompt.authenticate(info)
    }
}
