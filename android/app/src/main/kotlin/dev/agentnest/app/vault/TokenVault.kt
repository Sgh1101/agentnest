package dev.agentnest.app.vault

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Wraps the device token with an Android Keystore AES-256-GCM key (docs/android.md 4.1, security.md 5).
 *
 * The key is deliberately NOT bound to user authentication and NOT `setUnlockedDeviceRequired`: the foreground service
 * must reconnect while the phone is locked. Biometrics guard approvals, not the connection. StrongBox is tried first and
 * silently skipped when the hardware is not there. Blob layout: `[iv(12) | ciphertext+tag]`.
 *
 * Nothing in here logs; plaintext arrays are the caller's to wipe.
 */
class TokenVault {
    /** Encrypts [plain]. Creates the key on first use. */
    fun seal(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, existingKey() ?: generateKey())
        return cipher.iv + cipher.doFinal(plain)
    }

    /**
     * Decrypts [blob]. Null when the key is gone or invalidated or the data does not authenticate
     * (`KeyPermanentlyInvalidatedException` / `AEADBadTagException`): the caller then wipes the pairing and asks the
     * user to pair again. A missing key is never recreated here (that would hide the loss).
     */
    fun open(blob: ByteArray): ByteArray? {
        if (blob.size <= IV_BYTES) return null
        val key = existingKey() ?: return null
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, blob, 0, IV_BYTES))
            cipher.doFinal(blob, IV_BYTES, blob.size - IV_BYTES)
        } catch (e: KeyPermanentlyInvalidatedException) {
            null
        } catch (e: AEADBadTagException) {
            null
        } catch (e: GeneralSecurityException) {
            null
        } catch (e: ProviderException) {
            null
        }
    }

    /** Deletes the key (unpair, re-pair, revoked device). Never throws. */
    fun deleteKey() {
        try {
            keyStore().deleteEntry(ALIAS)
        } catch (e: Exception) {
            // Nothing left to protect if the entry cannot even be found.
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun existingKey(): SecretKey? = try {
        keyStore().getKey(ALIAS, null) as? SecretKey
    } catch (e: Exception) {
        null
    }

    private fun generateKey(): SecretKey {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                return generate(strongBox = true)
            } catch (e: ProviderException) {
                // StrongBoxUnavailableException extends ProviderException: fall back to the TEE-backed key.
            }
        }
        return generate(strongBox = false)
    }

    private fun generate(strongBox: Boolean): SecretKey {
        val builder = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_BITS)
            .setUserAuthenticationRequired(false)
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(builder.build())
        return generator.generateKey()
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "agentnest.device_token.v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
        const val TAG_BITS = 128
        const val KEY_BITS = 256
    }
}
