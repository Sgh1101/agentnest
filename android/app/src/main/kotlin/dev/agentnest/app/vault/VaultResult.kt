package dev.agentnest.app.vault

import javax.crypto.AEADBadTagException

/** Outcome of [TokenVault.open]: the token, a permanent loss, or a failure that may go away. */
sealed interface VaultResult {
    /** The decrypted token bytes; the caller wipes them after use. */
    class Ok(val plain: ByteArray) : VaultResult

    /** The key is permanently unusable or the data does not authenticate: wipe the pairing and re-pair. */
    data object Invalid : VaultResult

    /** A Keystore failure that is not proof of loss: retry with backoff, never wipe. */
    data object Transient : VaultResult

    companion object {
        private const val KEY_INVALIDATED = "android.security.keystore.KeyPermanentlyInvalidatedException"

        /**
         * Only these two failures prove the sealed token is gone for good (docs/android.md 4.1). The Android exception
         * is matched by name so this stays a pure JVM function (unit tests run without the Android runtime).
         */
        fun isPermanent(failure: Throwable): Boolean =
            failure is AEADBadTagException || failure.javaClass.name == KEY_INVALIDATED

        /** Maps a decryption failure to [Invalid] (permanent) or [Transient]. */
        fun fromFailure(failure: Throwable): VaultResult = if (isPermanent(failure)) Invalid else Transient
    }
}

/** What the link service does with a [VaultResult] (pure, unit-tested). */
enum class VaultAction { CONNECT, WIPE_PAIRING, RETRY, GIVE_UP }

/**
 * Retry policy for transient Keystore failures: a few quick attempts (the Keystore daemon usually recovers in
 * seconds), then the service stops WITHOUT wiping and tells the user to reconnect.
 */
object VaultRetry {
    /** Waits before retry 1, 2, 3 ... Then the service gives up (the pairing stays untouched). */
    val DELAYS_MS: List<Long> = listOf(1_000, 2_000, 4_000, 8_000, 16_000, 30_000)

    /** The action for [result] after [attempt] failed tries so far (0 on the first call). */
    fun action(result: VaultResult, attempt: Int): VaultAction = when (result) {
        is VaultResult.Ok -> VaultAction.CONNECT
        VaultResult.Invalid -> VaultAction.WIPE_PAIRING
        VaultResult.Transient -> if (attempt < DELAYS_MS.size) VaultAction.RETRY else VaultAction.GIVE_UP
    }

    /** The delay before the retry that follows [attempt] failed tries. */
    fun delayMs(attempt: Int): Long = DELAYS_MS[attempt.coerceIn(0, DELAYS_MS.lastIndex)]
}
