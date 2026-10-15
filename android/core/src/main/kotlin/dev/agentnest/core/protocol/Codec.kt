package dev.agentnest.core.protocol

import kotlinx.serialization.ExperimentalSerializationApi
import dev.agentnest.core.crypto.B64
import kotlinx.serialization.SerializationException
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNamingStrategy
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

/** Result of decoding one text frame. */
sealed interface DecodeResult {
    /** A well-formed message of a known type. */
    data class Decoded(val message: WireMessage) : DecodeResult

    /** A well-formed envelope with a type this build does not know. Must be ignored silently (protocol.md 2). */
    data class UnknownType(val type: String) : DecodeResult

    /** The frame violates the protocol (bad JSON, wrong `v`, missing/invalid field, ...). */
    data class Invalid(val reason: String) : DecodeResult
}

/**
 * JSON codec for the wire protocol v1: envelope handling, typed payload decoding and forward-compatible
 * configuration (`ignoreUnknownKeys`, unknown enum values -> `UNKNOWN`). All wire property names are
 * snake_case, derived from the camelCase Kotlin names.
 */
object Codec {
    /** Protocol major version spoken by this build. */
    const val PROTOCOL_VERSION: Int = 1

    /** Server -> phone frame size limit (protocol.md section 1). */
    const val MAX_SERVER_FRAME_BYTES: Int = 262_144

    /** Phone -> server frame size limit (protocol.md section 1). */
    const val MAX_CLIENT_FRAME_BYTES: Int = 32_768

    /** The configured JSON instance shared by all payload (de)serialization. */
    @OptIn(ExperimentalSerializationApi::class)
    val json: Json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        explicitNulls = false
        coerceInputValues = true
        namingStrategy = JsonNamingStrategy.SnakeCase
    }

    /** Types that must carry a `seq` (protocol.md 2). */
    private val replayableTypes = setOf(
        "snapshot", "event", "session_state", "approval_request", "approval_resolved", "adapter_status",
    )

    private val UUID7 = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

    private val decoders: Map<String, (FrameMeta, JsonElement) -> WireMessage> = mapOf(
        // server -> client
        "challenge" to { m, p -> ChallengeMessage(m, json.decodeFromJsonElement(ChallengePayload.serializer(), p)) },
        "pair_pending" to { m, p -> PairPendingMessage(m, json.decodeFromJsonElement(PairPendingPayload.serializer(), p)) },
        "pair_result" to { m, p -> PairResultMessage(m, json.decodeFromJsonElement(PairResultPayload.serializer(), p)) },
        "welcome" to { m, p -> WelcomeMessage(m, json.decodeFromJsonElement(WelcomePayload.serializer(), p)) },
        "snapshot" to { m, p -> SnapshotMessage(m, json.decodeFromJsonElement(SnapshotPayload.serializer(), p)) },
        "event" to { m, p -> EventMessage(m, json.decodeFromJsonElement(AgentEvent.serializer(), p)) },
        "session_state" to { m, p -> SessionStateMessage(m, json.decodeFromJsonElement(SessionState.serializer(), p)) },
        "approval_request" to { m, p -> ApprovalRequestMessage(m, json.decodeFromJsonElement(ApprovalRequest.serializer(), p)) },
        "approval_resolved" to { m, p ->
            ApprovalResolvedMessage(m, json.decodeFromJsonElement(ApprovalResolvedPayload.serializer(), p))
        },
        "decision_result" to { m, p -> DecisionResultMessage(m, json.decodeFromJsonElement(DecisionResultPayload.serializer(), p)) },
        "events_page" to { m, p -> EventsPageMessage(m, json.decodeFromJsonElement(EventsPagePayload.serializer(), p)) },
        "hosts_update" to { m, p -> HostsUpdateMessage(m, json.decodeFromJsonElement(HostsUpdatePayload.serializer(), p)) },
        "adapter_status" to { m, p -> AdapterStatusMessage(m, json.decodeFromJsonElement(AdapterStatusPayload.serializer(), p)) },
        "pong" to { m, p -> PongMessage(m, json.decodeFromJsonElement(PongPayload.serializer(), p)) },
        "error" to { m, p -> ErrorMessage(m, json.decodeFromJsonElement(ErrorPayload.serializer(), p)) },
        "bye" to { m, p -> ByeMessage(m, json.decodeFromJsonElement(ByePayload.serializer(), p)) },
        // client -> server (decoded strictly; used for fixtures and by tests of the PC protocol)
        "pair" to { m, p -> PairMessage(m, json.decodeFromJsonElement(PairPayload.serializer(), p)) },
        "hello" to { m, p -> HelloMessage(m, json.decodeFromJsonElement(HelloPayload.serializer(), p)) },
        "ack" to { m, p -> AckMessage(m, json.decodeFromJsonElement(AckPayload.serializer(), p)) },
        "ping" to { m, p -> PingMessage(m, json.decodeFromJsonElement(PingPayload.serializer(), p)) },
        "snapshot_request" to { m, p -> SnapshotRequestMessage(m, json.decodeFromJsonElement(SnapshotRequestPayload.serializer(), p)) },
        "events_request" to { m, p -> EventsRequestMessage(m, json.decodeFromJsonElement(EventsRequestPayload.serializer(), p)) },
        "decision" to { m, p -> DecisionMessage(m, json.decodeFromJsonElement(DecisionPayload.serializer(), p)) },
        "approval_seen" to { m, p -> ApprovalSeenMessage(m, json.decodeFromJsonElement(ApprovalSeenPayload.serializer(), p)) },
        "unpair" to { m, p -> UnpairMessage(m, json.decodeFromJsonElement(UnpairPayload.serializer(), p)) },
    )

    /**
     * Decodes one text frame of either direction. Unknown message types yield [DecodeResult.UnknownType]
     * (to be ignored without error); protocol violations yield [DecodeResult.Invalid].
     */
    fun decode(text: String): DecodeResult {
        // Frames above the server limit are refused before parsing (a pinned PC never sends them).
        if (text.length > MAX_SERVER_FRAME_BYTES || (text.length > MAX_SERVER_FRAME_BYTES / 3 && text.toByteArray(Charsets.UTF_8).size > MAX_SERVER_FRAME_BYTES)) {
            return DecodeResult.Invalid("frame exceeds $MAX_SERVER_FRAME_BYTES bytes")
        }
        val envelope: JsonObject = try {
            json.parseToJsonElement(text).jsonObject
        } catch (e: SerializationException) {
            return DecodeResult.Invalid("not a JSON object")
        } catch (e: IllegalArgumentException) {
            return DecodeResult.Invalid("not a JSON object")
        }
        val version = (envelope["v"] as? JsonPrimitive)?.longOrNull
            ?: return DecodeResult.Invalid("missing v")
        if (version != PROTOCOL_VERSION.toLong()) return DecodeResult.Invalid("unsupported protocol version $version")
        val type = (envelope["type"] as? JsonPrimitive)?.contentOrNull
            ?: return DecodeResult.Invalid("missing type")
        val decoder = decoders[type] ?: return DecodeResult.UnknownType(type)
        return try {
            val id = (envelope["id"] as? JsonPrimitive)?.contentOrNull?.takeIf { UUID7.matches(it) }
                ?: return DecodeResult.Invalid("missing or malformed id (UUIDv7 expected)")
            val ts = (envelope["ts"] as? JsonPrimitive)?.contentOrNull?.let(Ts::parseOrNull)
                ?: return DecodeResult.Invalid("missing or invalid ts")
            val seqElement = envelope["seq"]
            val seq: Long? = when {
                seqElement == null || seqElement is kotlinx.serialization.json.JsonNull -> null
                else -> (seqElement as? JsonPrimitive)?.longOrNull ?: return DecodeResult.Invalid("seq is not an integer")
            }
            if (seq != null && seq < 0) return DecodeResult.Invalid("negative seq")
            if (type in replayableTypes && seq == null) return DecodeResult.Invalid("$type requires seq")
            val payload = envelope["payload"] as? JsonObject ?: return DecodeResult.Invalid("missing payload")
            val message = decoder(FrameMeta(id, ts, seq), payload)
            validate(message)?.let { return DecodeResult.Invalid(it) }
            DecodeResult.Decoded(message)
        } catch (e: SerializationException) {
            DecodeResult.Invalid("invalid $type payload: ${e.message?.take(120)}")
        } catch (e: IllegalArgumentException) {
            DecodeResult.Invalid("invalid $type payload: ${e.message?.take(120)}")
        }
    }

    private val REQUEST_ID = Regex("^ar_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    private val SHA256_HEX = Regex("^[0-9a-f]{64}$")
    private val SAS_PATTERN = Regex("^[0-9]{6}$")
    private const val MAX_REASON_CHARS = 200
    private const val MAX_DEVICE_NAME_BYTES = 64
    private const val MAX_KINDS = 16
    private const val MAX_HOSTS = 8

    private fun portOk(port: Int) = port in 1..65535

    private fun rawLength(b64: String, url: Boolean = false): Int? =
        (if (url) B64.decodeUrl(b64) else B64.decode(b64))?.size

    /**
     * Semantic checks that the JSON Schema expresses beyond field types: values the phone must never accept or
     * emit (`decision`/auth/extra-confirmation values it does not know), binding-field formats, sizes and ranges.
     * Returns a reason string when the message is invalid, null otherwise.
     */
    private fun validate(message: WireMessage): String? = when (message) {
        is DecisionMessage -> {
            val p = message.payload
            when {
                p.decision == Decision.UNKNOWN -> "unknown decision"
                p.auth?.method == AuthMethod.UNKNOWN -> "unknown auth method"
                p.extraConfirmation?.method == ExtraConfirmationLevel.UNKNOWN -> "unknown extra confirmation method"
                !REQUEST_ID.matches(p.requestId) -> "malformed request_id"
                !SHA256_HEX.matches(p.toolInputSha256) -> "tool_input_sha256 must be lowercase hex"
                rawLength(p.nonceB64) != 16 -> "nonce_b64 must be 16 bytes"
                (p.reason?.codePointCount(0, p.reason.length) ?: 0) > MAX_REASON_CHARS -> "reason too long"
                else -> null
            }
        }
        is EventMessage -> if (message.payload.seq < 0) "negative event seq" else null
        is HelloMessage -> when {
            message.payload.lastSeq < 0 -> "negative last_seq"
            rawLength(message.payload.deviceToken, url = true) != 32 -> "device_token must be 32 bytes base64url"
            rawLength(message.payload.challengeB64) != 16 -> "challenge_b64 must be 16 bytes"
            else -> null
        }
        is PairMessage -> when {
            rawLength(message.payload.proofB64) != 32 -> "proof_b64 must be 32 bytes"
            rawLength(message.payload.challengeB64) != 16 -> "challenge_b64 must be 16 bytes"
            message.payload.device.name.toByteArray(Charsets.UTF_8).size > MAX_DEVICE_NAME_BYTES -> "device name too long"
            else -> null
        }
        is UnpairMessage ->
            if ((message.payload.deviceId == null) == (message.payload.pairingId == null)) "unpair takes exactly one of device_id / pairing_id" else null
        is AckMessage -> when {
            message.payload.throughSeq == null && message.payload.approvalIds.isEmpty() -> "ack needs through_seq or approval_ids"
            (message.payload.throughSeq ?: 0) < 0 -> "negative through_seq"
            else -> null
        }
        is EventsRequestMessage -> when {
            message.payload.beforeSeq < 0 -> "negative before_seq"
            message.payload.limit < 1 -> "limit below 1"
            (message.payload.kinds?.size ?: 0) > MAX_KINDS -> "too many kinds"
            else -> null
        }
        is ChallengeMessage -> if (rawLength(message.payload.challengeB64) != 16) "challenge must be 16 bytes" else null
        is PairPendingMessage -> if (!SAS_PATTERN.matches(message.payload.sas)) "sas must be 6 digits" else null
        is PairResultMessage -> {
            val p = message.payload
            when {
                p.ok && (p.deviceId == null || p.deviceToken == null || p.pc == null) -> "ok:true requires device_id, device_token and pc"
                !p.ok && p.errorCode == null -> "ok:false requires error_code"
                else -> null
            }
        }
        is HostsUpdateMessage ->
            if (!portOk(message.payload.port) || message.payload.addresses.size > MAX_HOSTS) "invalid hosts_update" else null
        is WelcomeMessage -> message.payload.hosts?.let {
            if (!portOk(it.port) || it.addresses.size > MAX_HOSTS) "invalid welcome.hosts" else null
        }
        else -> null
    }

    /** Decodes a frame that must be a PC -> phone message; client message types are rejected as invalid. */
    fun decodeServer(text: String): DecodeResult = when (val r = decode(text)) {
        is DecodeResult.Decoded -> if (r.message is ServerMessage) r else DecodeResult.Invalid("unexpected client message ${r.message.type}")
        else -> r
    }

    /** Encodes a phone -> PC message into one text frame. Throws if the frame would exceed 32 KiB. */
    fun encode(message: ClientMessage): String {
        val payload: JsonElement = when (message) {
            is PairMessage -> json.encodeToJsonElement(PairPayload.serializer(), message.payload)
            is HelloMessage -> json.encodeToJsonElement(HelloPayload.serializer(), message.payload)
            is AckMessage -> json.encodeToJsonElement(AckPayload.serializer(), message.payload)
            is PingMessage -> json.encodeToJsonElement(PingPayload.serializer(), message.payload)
            is SnapshotRequestMessage -> json.encodeToJsonElement(SnapshotRequestPayload.serializer(), message.payload)
            is EventsRequestMessage -> json.encodeToJsonElement(EventsRequestPayload.serializer(), message.payload)
            is DecisionMessage -> json.encodeToJsonElement(DecisionPayload.serializer(), message.payload)
            is ApprovalSeenMessage -> json.encodeToJsonElement(ApprovalSeenPayload.serializer(), message.payload)
            is UnpairMessage -> json.encodeToJsonElement(UnpairPayload.serializer(), message.payload)
        }
        val text = json.encodeToString(JsonObject.serializer(), envelopeOf(message, payload))
        check(text.toByteArray(Charsets.UTF_8).size <= MAX_CLIENT_FRAME_BYTES) { "frame exceeds client limit" }
        return text
    }

    /** Encodes any message (including PC -> phone ones) back to JSON; used by round-trip tests and caches. */
    fun encodeAny(message: WireMessage): String = when (message) {
        is ClientMessage -> encode(message)
        is ServerMessage -> json.encodeToString(JsonObject.serializer(), envelopeOf(message, serverPayload(message)))
    }

    private fun serverPayload(message: ServerMessage): JsonElement = when (message) {
        is ChallengeMessage -> enc(ChallengePayload.serializer(), message.payload)
        is PairPendingMessage -> enc(PairPendingPayload.serializer(), message.payload)
        is PairResultMessage -> enc(PairResultPayload.serializer(), message.payload)
        is WelcomeMessage -> enc(WelcomePayload.serializer(), message.payload)
        is SnapshotMessage -> enc(SnapshotPayload.serializer(), message.payload)
        is EventMessage -> enc(AgentEvent.serializer(), message.payload)
        is SessionStateMessage -> enc(SessionState.serializer(), message.payload)
        is ApprovalRequestMessage -> enc(ApprovalRequest.serializer(), message.payload)
        is ApprovalResolvedMessage -> enc(ApprovalResolvedPayload.serializer(), message.payload)
        is DecisionResultMessage -> enc(DecisionResultPayload.serializer(), message.payload)
        is EventsPageMessage -> enc(EventsPagePayload.serializer(), message.payload)
        is HostsUpdateMessage -> enc(HostsUpdatePayload.serializer(), message.payload)
        is AdapterStatusMessage -> enc(AdapterStatusPayload.serializer(), message.payload)
        is PongMessage -> enc(PongPayload.serializer(), message.payload)
        is ErrorMessage -> enc(ErrorPayload.serializer(), message.payload)
        is ByeMessage -> enc(ByePayload.serializer(), message.payload)
    }

    private fun <T> enc(strategy: SerializationStrategy<T>, value: T): JsonElement =
        json.encodeToJsonElement(strategy, value)

    private fun envelopeOf(message: WireMessage, payload: JsonElement): JsonObject = buildJsonObject {
        put("v", PROTOCOL_VERSION)
        put("type", message.type)
        put("id", message.meta.id)
        put("ts", message.meta.ts.raw)
        message.meta.seq?.let { put("seq", it) }
        put("payload", payload)
    }
}
