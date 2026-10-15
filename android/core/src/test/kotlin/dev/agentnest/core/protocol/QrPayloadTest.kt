package dev.agentnest.core.protocol

import dev.agentnest.core.Fixtures
import dev.agentnest.core.crypto.B64
import dev.agentnest.core.crypto.Sha256
import dev.agentnest.core.crypto.SpkiPin
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class QrPayloadTest {
    private val now = Instant.parse("2026-10-15T09:00:00Z")
    private val example: JsonObject = Fixtures.json("examples/qr/pairing_payload.1.json") as JsonObject

    private fun uri(o: JsonObject): String = QrPayload.URI_PREFIX + B64.encodeUrl(Codec.json.encodeToString(JsonObject.serializer(), o).toByteArray())

    private fun with(vararg changes: Pair<String, JsonElement?>): JsonObject = buildJsonObject {
        val overrides = changes.toMap()
        for ((k, v) in example) if (k !in overrides) put(k, v)
        for ((k, v) in overrides) if (v != null) put(k, v)
    }

    private fun parse(o: JsonObject, at: Instant = now) = QrPayload.parse(uri(o), at)

    private fun failure(r: QrParseResult) = assertIs<QrParseResult.Failure>(r).error

    @Test
    fun `the shared example parses`() {
        val ok = assertIs<QrParseResult.Success>(parse(example)).payload
        assertEquals("pc_8252e6280a3d81d1", ok.pcId)
        assertEquals("DESKTOP-HOME", ok.pcName)
        assertEquals(listOf("192.168.0.10", "10.8.0.2"), ok.hosts)
        assertEquals(47832, ok.port)
        assertEquals(SpkiPin.parse("sha256/glLmKAo9gdGvAGIYNxNEvncjE6SNAheIa/dX4bFINbU="), ok.pin)
        assertEquals("p_3f9c2b1ea8d04c77", ok.pairingId)
        assertEquals(Instant.parse("2026-10-15T09:14:33Z"), ok.expiresAt)
        assertEquals("PH3xtFr5K5p_eeUvT-rN8XCPxRr9HpAGz8OqMr24H-w", B64.encodeUrl(ok.secret.use { it.copyOf() }))
    }

    @Test
    fun `secret never shows up in toString and can be wiped`() {
        val ok = assertIs<QrParseResult.Success>(parse(example)).payload
        assertFalse(ok.toString().contains("PH3xtFr5K5p"))
        assertTrue(ok.toString().contains("<redacted>"))
        ok.wipe()
        ok.secret.use { assertTrue(it.all { b -> b == 0.toByte() }) }
    }

    @Test
    fun `not an AgentNest QR`() {
        for (text in listOf("https://example.com", "", "agentnest://other?d=abc", "WIFI:S:x;;")) {
            assertEquals(QrError.NOT_AGENTNEST, failure(QrPayload.parse(text, now)), text)
        }
        assertEquals(QrError.BAD_ENCODING, failure(QrPayload.parse("agentnest://pair?d=@@@", now)))
        assertEquals(QrError.BAD_ENCODING, failure(QrPayload.parse(QrPayload.URI_PREFIX + B64.encodeUrl("not json".toByteArray()), now)))
        assertEquals("AgentNest 페어링 QR이 아니에요", QrError.NOT_AGENTNEST.messageKo)
    }

    @Test
    fun `version must be 1`() {
        assertEquals(QrError.UNSUPPORTED_VERSION, failure(parse(with("v" to JsonPrimitive(2)))))
        assertEquals(QrError.BAD_FIELDS, failure(parse(with("v" to null))))
    }

    @Test
    fun `pin format is sha256 slash 44 base64 characters`() {
        for (bad in listOf("glLmKAo9gdGvAGIYNxNEvncjE6SNAheIa/dX4bFINbU=", "sha256/short", "sha256/" + "A".repeat(43) + "!", "sha1/glLmKAo9gdGvAGIYNxNEvncjE6SNAheIa/dX4bFINbU=")) {
            assertEquals(QrError.BAD_PIN, failure(parse(with("spki_pin" to JsonPrimitive(bad)))), bad)
        }
        assertEquals(QrError.BAD_PIN, failure(parse(with("spki_pin" to null))))
    }

    @Test
    fun `hosts must be 1 to 8 valid addresses`() {
        assertEquals(QrError.BAD_HOSTS, failure(parse(with("hosts" to JsonArray(emptyList())))))
        assertEquals(QrError.BAD_HOSTS, failure(parse(with("hosts" to JsonArray((1..9).map { JsonPrimitive("192.168.0.$it") })))))
        assertEquals(QrError.BAD_HOSTS, failure(parse(with("hosts" to JsonArray(listOf(JsonPrimitive("http://evil")))))))
        assertEquals(QrError.BAD_HOSTS, failure(parse(with("hosts" to JsonArray(listOf(JsonPrimitive(5)))))))
        assertEquals(QrError.BAD_HOSTS, failure(parse(with("hosts" to JsonPrimitive("192.168.0.1")))))
        assertIs<QrParseResult.Success>(parse(with("hosts" to JsonArray((1..8).map { JsonPrimitive("192.168.0.$it") }))))
    }

    @Test
    fun `port must be 1024 to 65535`() {
        for (bad in listOf(0, 80, 1023, 65536, -1)) assertEquals(QrError.BAD_PORT, failure(parse(with("port" to JsonPrimitive(bad)))), "$bad")
        assertIs<QrParseResult.Success>(parse(with("port" to JsonPrimitive(1024))))
        assertIs<QrParseResult.Success>(parse(with("port" to JsonPrimitive(65535))))
    }

    @Test
    fun `expires_at must be in the future`() {
        assertIs<QrParseResult.Success>(parse(example, Instant.parse("2026-10-15T09:14:32Z")))
        assertEquals(QrError.EXPIRED, failure(parse(example, Instant.parse("2026-10-15T09:14:33Z"))))
        assertEquals(QrError.EXPIRED, failure(parse(example, Instant.parse("2027-01-01T00:00:00Z"))))
        assertEquals(QrError.BAD_FIELDS, failure(parse(with("expires_at" to JsonPrimitive("tomorrow")))))
    }

    @Test
    fun `pc_id must match the pin`() {
        assertEquals(QrError.PC_ID_MISMATCH, failure(parse(with("pc_id" to JsonPrimitive("pc_0000000000000000")))))
        // The derivation: pc_ + first 8 bytes of the pin hash.
        val pin = SpkiPin.parse("sha256/glLmKAo9gdGvAGIYNxNEvncjE6SNAheIa/dX4bFINbU=")!!
        assertEquals("pc_" + Sha256.hex(pin.hashBytes().copyOfRange(0, 8)), pin.derivedPcId())
    }

    @Test
    fun `pairing secret must be 32 bytes base64url`() {
        for (bad in listOf("short", "PH3xtFr5K5p_eeUvT-rN8XCPxRr9HpAGz8OqMr24H-w=extra", "!!!!")) {
            assertEquals(QrError.BAD_SECRET, failure(parse(with("pairing_secret" to JsonPrimitive(bad)))), bad)
        }
        assertEquals(QrError.BAD_SECRET, failure(parse(with("pairing_secret" to null))))
    }

    @Test
    fun `ids must be simple tokens`() {
        assertEquals(QrError.BAD_FIELDS, failure(parse(with("pairing_id" to JsonPrimitive("bad id!")))))
        assertEquals(QrError.BAD_FIELDS, failure(parse(with("pairing_id" to null))))
    }
}
