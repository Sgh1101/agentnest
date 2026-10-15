package dev.agentnest.core.crypto

import java.security.MessageDigest
import java.security.cert.X509Certificate

/**
 * A SHA-256 pin of a certificate's SubjectPublicKeyInfo (security.md 3). Textual form is OkHttp's
 * `sha256/<base64>` (44 base64 characters).
 */
class SpkiPin private constructor(private val hash: ByteArray) {
    init {
        require(hash.size == HASH_BYTES) { "SPKI pin must be 32 bytes" }
    }

    /** A copy of the 32 raw hash bytes. */
    fun hashBytes(): ByteArray = hash.copyOf()

    /** `sha256/<base64>` form, identical to OkHttp's CertificatePinner format. */
    fun toPinString(): String = PREFIX + B64.encode(hash)

    /** Plain base64 form without the `sha256/` prefix. */
    fun toBase64(): String = B64.encode(hash)

    /** The PC id derived from this pin: `pc_` + hex of the first 8 hash bytes (security.md 4.1). */
    fun derivedPcId(): String = "pc_" + Sha256.hex(hash.copyOfRange(0, 8))

    /** Constant-time check of an SPKI DER encoding against this pin. */
    fun matchesSpki(spkiDer: ByteArray): Boolean = MessageDigest.isEqual(hash, Sha256.digest(spkiDer))

    /** Constant-time check of a certificate's public key (X.509 SPKI) against this pin. */
    fun matches(certificate: X509Certificate): Boolean = matchesSpki(certificate.publicKey.encoded)

    override fun equals(other: Any?): Boolean = other is SpkiPin && MessageDigest.isEqual(hash, other.hash)
    override fun hashCode(): Int = hash.contentHashCode()

    // A pin is public (it is in the QR), but keep log lines short and uniform.
    override fun toString(): String = "SpkiPin(${toPinString().take(14)}...)"

    companion object {
        private const val HASH_BYTES = 32
        private const val PREFIX = "sha256/"

        /** Parses `sha256/<44 base64 chars>`; null when the format or length is wrong. */
        fun parse(text: String): SpkiPin? {
            if (!text.startsWith(PREFIX)) return null
            val b64 = text.substring(PREFIX.length)
            if (b64.length != 44) return null
            val bytes = B64.decode(b64) ?: return null
            if (bytes.size != HASH_BYTES) return null
            return SpkiPin(bytes)
        }

        /** Computes the pin of an SPKI DER encoding. */
        fun ofSpki(spkiDer: ByteArray): SpkiPin = SpkiPin(Sha256.digest(spkiDer))

        /** Computes the pin of a certificate's public key. */
        fun of(certificate: X509Certificate): SpkiPin = ofSpki(certificate.publicKey.encoded)
    }
}
