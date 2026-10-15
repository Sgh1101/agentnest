package dev.agentnest.core.crypto

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.ByteArrayOutputStream
import java.math.BigDecimal
import java.math.MathContext
import java.math.RoundingMode
import java.text.Normalizer

/**
 * Byte-exact encoders shared with the Rust side (`agentnest-protocol::canonical`).
 *
 * - [pairBytes]: `canonical_pair_bytes` of protocol.md 4.2.
 * - [json] / [toolInputSha256]: canonical JSON (keys sorted by UTF-8 byte order, no whitespace) and its SHA-256.
 *   The PC is the only party that computes `tool_input_sha256`; the phone only echoes it. This implementation
 *   exists to prove byte equality with the Rust encoder through `protocol/vectors`.
 */
object Canonical {
    private const val PAIR_TAG = "agentnest-pair-v1"
    private const val MAX_DEVICE_NAME_BYTES = 64
    private const val MAX_FIELD_BYTES = 0xFFFF

    /** Size of the server challenge in raw bytes. */
    const val CHALLENGE_BYTES = 16

    /**
     * Builds `canonical_pair_bytes`:
     * `"agentnest-pair-v1" || L(pc_id) pc_id || L(pairing_id) pairing_id || L(challenge) challenge ||
     *  L(device_name) device_name || L(spki) spki`, every variable field with a u16 big-endian length prefix.
     * The fixed tag has no length prefix. `deviceName` is NFC-normalised and must be at most 64 UTF-8 bytes
     * after normalisation (use [fitDeviceName] first). A missing SPKI is encoded as length 0.
     */
    fun pairBytes(
        pcId: String,
        pairingId: String,
        challenge: ByteArray,
        deviceName: String,
        spkiDer: ByteArray?,
    ): ByteArray {
        require(challenge.size == CHALLENGE_BYTES) { "challenge must be 16 bytes" }
        val name = Normalizer.normalize(deviceName, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)
        require(name.size <= MAX_DEVICE_NAME_BYTES) { "device name exceeds 64 bytes" }
        val out = ByteArrayOutputStream()
        out.write(PAIR_TAG.toByteArray(Charsets.US_ASCII))
        writeField(out, pcId.toByteArray(Charsets.UTF_8))
        writeField(out, pairingId.toByteArray(Charsets.UTF_8))
        writeField(out, challenge)
        writeField(out, name)
        writeField(out, spkiDer ?: ByteArray(0))
        return out.toByteArray()
    }

    /** NFC-normalises [name] and truncates it at a code point boundary so it is at most 64 UTF-8 bytes. */
    fun fitDeviceName(name: String): String {
        val normalized = Normalizer.normalize(name, Normalizer.Form.NFC)
        if (normalized.toByteArray(Charsets.UTF_8).size <= MAX_DEVICE_NAME_BYTES) return normalized
        val sb = StringBuilder()
        var bytes = 0
        var i = 0
        while (i < normalized.length) {
            val cp = normalized.codePointAt(i)
            val len = String(Character.toChars(cp)).toByteArray(Charsets.UTF_8).size
            if (bytes + len > MAX_DEVICE_NAME_BYTES) break
            sb.appendCodePoint(cp)
            bytes += len
            i += Character.charCount(cp)
        }
        return sb.toString()
    }

    private fun writeField(out: ByteArrayOutputStream, bytes: ByteArray) {
        require(bytes.size <= MAX_FIELD_BYTES) { "field too long" }
        out.write(bytes.size ushr 8)
        out.write(bytes.size and 0xFF)
        out.write(bytes)
    }

    // ---------------------------------------------------------------------------------------------
    // Canonical JSON (RFC 8785 / JCS)
    // ---------------------------------------------------------------------------------------------

    /** Thrown for numbers JCS cannot represent (NaN / infinity / not a JSON number). */
    class UnsupportedNumberException(message: String) : IllegalArgumentException(message)

    /**
     * Canonical JSON text per RFC 8785 (JCS), as fixed by `protocol/vectors/tool_input_sha256.json`:
     * object keys sorted by UTF-16 code units (Kotlin's natural `String` order), no insignificant whitespace,
     * minimal string escaping (`\"`, `\\`, short escapes for `\b \t \n \f \r`, other controls below 0x20 as
     * lowercase `\u00xx`, everything else raw), and every number serialised through its IEEE-754 double using
     * ECMAScript `Number::toString` (so `1.0` -> `1`, `-0` -> `0`, `1e21` -> `1e+21`, `2^64-1` -> `18446744073709552000`).
     * Duplicate object keys: the last one wins (that is how the parser builds the tree).
     */
    fun json(element: JsonElement): String = StringBuilder().also { write(it, element) }.toString()

    /** `SHA-256(canonical JSON(toolInput))` as lowercase hex (security.md 6.1). */
    fun toolInputSha256(toolInput: JsonElement): String =
        Sha256.hex(Sha256.digest(json(toolInput).toByteArray(Charsets.UTF_8)))

    private fun write(sb: StringBuilder, element: JsonElement) {
        when (element) {
            is JsonNull -> sb.append("null")
            is JsonPrimitive -> if (element.isString) writeString(sb, element.content) else writeLiteral(sb, element.content)
            is JsonArray -> {
                sb.append('[')
                element.forEachIndexed { i, e ->
                    if (i > 0) sb.append(',')
                    write(sb, e)
                }
                sb.append(']')
            }
            is JsonObject -> {
                sb.append('{')
                var first = true
                for (key in element.keys.sorted()) {
                    if (!first) sb.append(',')
                    first = false
                    writeString(sb, key)
                    sb.append(':')
                    write(sb, element.getValue(key))
                }
                sb.append('}')
            }
        }
    }

    private fun writeString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (ch in s) {
            when {
                ch == '"' -> sb.append("\\\"")
                ch == '\\' -> sb.append("\\\\")
                ch == '\b' -> sb.append("\\b")
                ch == '\u000C' -> sb.append("\\f")
                ch == '\n' -> sb.append("\\n")
                ch == '\r' -> sb.append("\\r")
                ch == '\t' -> sb.append("\\t")
                ch < ' ' -> sb.append("\\u00").append(HEX[ch.code ushr 4]).append(HEX[ch.code and 0xF])
                else -> sb.append(ch)
            }
        }
        sb.append('"')
    }

    private val HEX = "0123456789abcdef".toCharArray()

    private fun writeLiteral(sb: StringBuilder, literal: String) {
        if (literal == "true" || literal == "false") {
            sb.append(literal)
            return
        }
        val d = try {
            BigDecimal(literal).toDouble()
        } catch (e: NumberFormatException) {
            throw UnsupportedNumberException("not a JSON number")
        }
        sb.append(ecmaNumberToString(d))
    }

    /** ECMAScript Number::toString for a finite double (the number format RFC 8785 mandates). */
    internal fun ecmaNumberToString(value: Double): String {
        if (value.isNaN() || value.isInfinite()) throw UnsupportedNumberException("number out of range")
        if (value == 0.0) return "0" // also covers -0
        val negative = value < 0
        val decimal = shortestDecimal(Math.abs(value))
        val digits = decimal.unscaledValue().toString()
        val k = digits.length
        val n = k - decimal.scale() // value = 0.DIGITS x 10^n
        val out = StringBuilder()
        if (negative) out.append('-')
        when {
            n in k..21 -> out.append(digits).append("0".repeat(n - k))
            n in 1..21 -> out.append(digits, 0, n).append('.').append(digits, n, k)
            n in -5..0 -> out.append("0.").append("0".repeat(-n)).append(digits)
            else -> {
                val exp = n - 1
                out.append(digits[0])
                if (k > 1) out.append('.').append(digits, 1, k)
                out.append('e').append(if (exp < 0) '-' else '+').append(Math.abs(exp))
            }
        }
        return out.toString()
    }

    /**
     * The shortest decimal that parses back to [positive] (nearest one when several have that length), like the
     * digit generation of ECMAScript Number::toString. `Double.toString` is not usable here because it always keeps
     * two digits (`4.9E-324` instead of `5E-324`).
     */
    private fun shortestDecimal(positive: Double): BigDecimal {
        val exact = BigDecimal(positive)
        for (digits in 1..17) {
            val candidate = exact.round(MathContext(digits, RoundingMode.HALF_EVEN))
            if (candidate.toDouble() == positive) return candidate.stripTrailingZeros()
        }
        return exact.round(MathContext(17, RoundingMode.HALF_EVEN)).stripTrailingZeros()
    }
}
