package dev.agentnest.app.vault

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.GeneralSecurityException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.ProviderException
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec

/**
 * The phone's EC P-256 signing key pair (docs/android.md 4.1): generated inside the Keystore, never exportable.
 * Phase 1 only sends the public key (SPKI DER) in `pair` so the PC can register it; signing decisions with it is
 * a Phase 3 item. The key is not bound to user authentication (it must exist for pairing without a prompt).
 */
class DeviceKey {
    /** The SPKI DER of the public key; creates the key pair on first use. Null when the Keystore refuses. */
    fun publicKeySpki(): ByteArray? = try {
        val existing = keyStore().getCertificate(ALIAS)?.publicKey
        (existing ?: generate()).encoded
    } catch (e: GeneralSecurityException) {
        null
    } catch (e: ProviderException) {
        null
    } catch (e: java.io.IOException) {
        null
    }

    /** Deletes the key pair (unpair / re-pair). Never throws. */
    fun delete() {
        try {
            keyStore().deleteEntry(ALIAS)
        } catch (e: Exception) {
            // Already gone.
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun generate(): PublicKey {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                return generate(strongBox = true)
            } catch (e: ProviderException) {
                // StrongBox missing: use the TEE.
            }
        }
        return generate(strongBox = false)
    }

    private fun generate(strongBox: Boolean): PublicKey {
        val builder = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        generator.initialize(builder.build())
        return generator.generateKeyPair().public
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "agentnest.device.v1"
    }
}
