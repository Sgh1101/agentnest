package dev.agentnest.core.crypto

/**
 * The QR `pairing_secret` (32 random bytes). Lives only in memory; [wipe] zeroes it. Its `toString` never
 * prints the value.
 */
class PairingSecret(bytes: ByteArray) : AutoCloseable {
    private val secret: ByteArray = bytes.copyOf()

    init {
        require(secret.size == SECRET_BYTES) { "pairing secret must be 32 bytes" }
    }

    /** Runs [block] with the raw secret bytes. The array must not be retained. */
    fun <T> use(block: (ByteArray) -> T): T = block(secret)

    /** Overwrites the secret with zeros (docs/android.md 4.3: `fill(0)` when pairing ends). */
    fun wipe() = secret.fill(0)

    override fun close() = wipe()

    override fun toString(): String = "PairingSecret(<redacted>)"

    companion object {
        private const val SECRET_BYTES = 32

        /** Decodes the base64url QR value; null when it is malformed or not 32 bytes. */
        fun fromBase64Url(text: String): PairingSecret? {
            val bytes = B64.decodeUrl(text) ?: return null
            if (bytes.size != SECRET_BYTES) return null
            return PairingSecret(bytes).also { bytes.fill(0) }
        }
    }
}

/** HMAC possession proof and SAS (protocol.md 4.2 / 4.3). */
object PairingCrypto {
    private val SAS_TAG = "sas".toByteArray(Charsets.US_ASCII)

    /** `proof = HMAC-SHA256(pairing_secret, canonical_pair_bytes)`. */
    fun proof(
        secret: PairingSecret,
        pcId: String,
        pairingId: String,
        challenge: ByteArray,
        deviceName: String,
        spkiDer: ByteArray?,
    ): ByteArray {
        val message = Canonical.pairBytes(pcId, pairingId, challenge, deviceName, spkiDer)
        return secret.use { HmacSha256.mac(it, message) }
    }

    /**
     * Six-digit SAS: first 4 bytes (big endian, unsigned) of `HMAC-SHA256(secret, "sas" || challenge || spki)`
     * modulo 1,000,000, zero-padded. The phone computes this locally and never displays the PC-sent value.
     */
    fun sas(secret: PairingSecret, challenge: ByteArray, spkiDer: ByteArray?): String {
        require(challenge.size == Canonical.CHALLENGE_BYTES) { "challenge must be 16 bytes" }
        val message = SAS_TAG + challenge + (spkiDer ?: ByteArray(0))
        val mac = secret.use { HmacSha256.mac(it, message) }
        val value = ((mac[0].toLong() and 0xFF) shl 24) or
            ((mac[1].toLong() and 0xFF) shl 16) or
            ((mac[2].toLong() and 0xFF) shl 8) or
            (mac[3].toLong() and 0xFF)
        return (value % 1_000_000L).toString().padStart(6, '0')
    }

    /** Constant-time comparison of two SAS strings. */
    fun sasEquals(a: String, b: String): Boolean =
        HmacSha256.constantTimeEquals(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))
}
