package dev.agentnest.core.protocol

import dev.agentnest.core.crypto.B64
import dev.agentnest.core.crypto.PairingSecret
import dev.agentnest.core.crypto.SpkiPin
import dev.agentnest.core.util.HostAddress
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import java.time.Instant

/** Why a scanned QR code was rejected. [messageKo] is the user-facing text. */
enum class QrError(val messageKo: String) {
    NOT_AGENTNEST("AgentNest 페어링 QR이 아니에요"),
    BAD_ENCODING("AgentNest 페어링 QR이 아니에요"),
    BAD_FIELDS("AgentNest 페어링 QR이 아니에요"),
    UNSUPPORTED_VERSION("앱을 업데이트한 뒤 다시 시도해 주세요"),
    BAD_PIN("QR의 PC 인증 정보가 올바르지 않아요"),
    BAD_HOSTS("QR의 PC 주소가 올바르지 않아요"),
    BAD_PORT("QR의 PC 주소가 올바르지 않아요"),
    BAD_SECRET("QR의 페어링 정보가 올바르지 않아요"),
    EXPIRED("QR의 유효 시간이 지났어요. PC에서 새 QR을 만들어 주세요"),
    PC_ID_MISMATCH("QR의 PC 인증 정보가 서로 맞지 않아요"),
}

/** Result of parsing a scanned QR string. */
sealed interface QrParseResult {
    data class Success(val payload: QrPayload) : QrParseResult
    data class Failure(val error: QrError) : QrParseResult
}

/**
 * Validated pairing QR payload (security.md 4.1). The `pairing_secret` is held in a [PairingSecret] that must be
 * wiped when pairing ends. `toString` never prints the secret.
 */
class QrPayload(
    val pcId: String,
    val pcName: String,
    val hosts: List<String>,
    val port: Int,
    val pin: SpkiPin,
    val pairingId: String,
    val secret: PairingSecret,
    val expiresAt: Instant,
) {
    /** Wipes the pairing secret. Call when pairing finishes, fails or is cancelled. */
    fun wipe() = secret.wipe()

    override fun toString(): String = "QrPayload(pcId=$pcId, pcName=$pcName, hosts=$hosts, port=$port, pairingId=$pairingId, secret=<redacted>)"

    companion object {
        const val URI_PREFIX = "agentnest://pair?d="
        const val MAX_HOSTS = 8
        const val MIN_PORT = 1024
        const val MAX_PORT = 65535
        private val ID_PATTERN = Regex("^[A-Za-z0-9_-]{1,64}$")

        /**
         * Parses `agentnest://pair?d=<base64url(JSON)>` and applies the validation rules of security.md 4.2 step 2:
         * `v == 1`, `spki_pin` is `sha256/` + 44 base64 chars, 1..8 hosts, port 1024..65535, `expires_at` in the
         * future (relative to [now]) and `pc_id` consistent with the pin.
         */
        fun parse(text: String, now: Instant): QrParseResult {
            val trimmed = text.trim()
            if (!trimmed.startsWith(URI_PREFIX)) return fail(QrError.NOT_AGENTNEST)
            val encoded = trimmed.substring(URI_PREFIX.length)
            val jsonBytes = B64.decodeUrl(encoded) ?: return fail(QrError.BAD_ENCODING)
            val root: JsonObject = try {
                Codec.json.parseToJsonElement(String(jsonBytes, Charsets.UTF_8)).jsonObject
            } catch (_: SerializationException) {
                return fail(QrError.BAD_ENCODING)
            } catch (_: IllegalArgumentException) {
                return fail(QrError.BAD_ENCODING)
            }
            return validate(root, now)
        }

        private fun fail(e: QrError) = QrParseResult.Failure(e)

        private fun str(o: JsonObject, key: String): String? = (o[key] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull

        private fun validate(o: JsonObject, now: Instant): QrParseResult {
            val version = (o["v"] as? JsonPrimitive)?.intOrNull ?: return fail(QrError.BAD_FIELDS)
            if (version != Codec.PROTOCOL_VERSION) return fail(QrError.UNSUPPORTED_VERSION)
            val pcId = str(o, "pc_id")?.takeIf { ID_PATTERN.matches(it) } ?: return fail(QrError.BAD_FIELDS)
            val pcName = str(o, "pc_name") ?: ""
            val pairingId = str(o, "pairing_id")?.takeIf { ID_PATTERN.matches(it) } ?: return fail(QrError.BAD_FIELDS)
            val pin = str(o, "spki_pin")?.let(SpkiPin::parse) ?: return fail(QrError.BAD_PIN)
            val hostsRaw = try {
                o["hosts"]?.jsonArray?.map { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
            } catch (_: IllegalArgumentException) {
                null
            } ?: return fail(QrError.BAD_HOSTS)
            if (hostsRaw.isEmpty() || hostsRaw.size > MAX_HOSTS) return fail(QrError.BAD_HOSTS)
            val hosts = hostsRaw.map { it?.takeIf(HostAddress::isValidHost) ?: return fail(QrError.BAD_HOSTS) }
            val port = (o["port"] as? JsonPrimitive)?.intOrNull ?: return fail(QrError.BAD_PORT)
            if (port !in MIN_PORT..MAX_PORT) return fail(QrError.BAD_PORT)
            val secret = str(o, "pairing_secret")?.let(PairingSecret::fromBase64Url) ?: return fail(QrError.BAD_SECRET)
            val expiresAt = str(o, "expires_at")?.let(Ts::parseOrNull)?.instant
            if (expiresAt == null) {
                secret.wipe()
                return fail(QrError.BAD_FIELDS)
            }
            if (!now.isBefore(expiresAt)) {
                secret.wipe()
                return fail(QrError.EXPIRED)
            }
            if (pcId != pin.derivedPcId()) {
                secret.wipe()
                return fail(QrError.PC_ID_MISMATCH)
            }
            return QrParseResult.Success(QrPayload(pcId, pcName, hosts, port, pin, pairingId, secret, expiresAt))
        }
    }
}
