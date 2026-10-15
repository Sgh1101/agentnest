package dev.agentnest.core.crypto

import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** SHA-256 helpers (java.security only). */
object Sha256 {
    /** Returns the 32-byte SHA-256 digest of [data]. */
    fun digest(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    /** Lowercase hexadecimal encoding of [bytes]. */
    fun hex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            sb.append(HEX[(b.toInt() ushr 4) and 0xF]).append(HEX[b.toInt() and 0xF])
        }
        return sb.toString()
    }

    /** Parses a hexadecimal string (either case) into bytes, or null when it is malformed. */
    fun unhex(text: String): ByteArray? {
        if (text.length % 2 != 0) return null
        val out = ByteArray(text.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(text[2 * i], 16)
            val lo = Character.digit(text[2 * i + 1], 16)
            if (hi < 0 || lo < 0) return null
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    private val HEX = "0123456789abcdef".toCharArray()
}

/** HMAC-SHA256 via javax.crypto.Mac. */
object HmacSha256 {
    private const val ALGORITHM = "HmacSHA256"

    /** Computes HMAC-SHA256([data]) under [key]. */
    fun mac(key: ByteArray, data: ByteArray): ByteArray {
        require(key.isNotEmpty()) { "empty HMAC key" }
        val mac = Mac.getInstance(ALGORITHM)
        mac.init(SecretKeySpec(key, ALGORITHM))
        return mac.doFinal(data)
    }

    /** Constant-time comparison of [expected] and [actual]. */
    fun constantTimeEquals(expected: ByteArray, actual: ByteArray): Boolean = MessageDigest.isEqual(expected, actual)
}

/** Base64 helpers: the protocol uses standard padded base64 for `*_b64` fields and base64url for secrets/tokens. */
object B64 {
    /** Standard base64 with padding. */
    fun encode(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    /** Decodes standard base64 (padded); null when malformed. */
    fun decode(text: String): ByteArray? = try {
        Base64.getDecoder().decode(text)
    } catch (_: IllegalArgumentException) {
        null
    }

    /** base64url without padding. */
    fun encodeUrl(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    /** Decodes base64url (padding optional); null when malformed. */
    fun decodeUrl(text: String): ByteArray? = try {
        Base64.getUrlDecoder().decode(text)
    } catch (_: IllegalArgumentException) {
        null
    }
}
