package dev.agentnest.core.crypto

import dev.agentnest.core.Fixtures
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Byte-for-byte checks against protocol/vectors (shared with the Rust implementation). */
class CryptoVectorsTest {
    private val pair = Fixtures.json("vectors/pair.json").jsonObject
    private val cases: List<JsonObject> = pair["cases"]!!.jsonArray.map { it.jsonObject }

    private fun str(o: JsonObject, key: String) = o[key]!!.jsonPrimitive.content
    private fun hex(o: JsonObject, key: String) = Sha256.unhex(str(o, key))!!
    private fun secretOf(o: JsonObject) = PairingSecret.fromBase64Url(str(o, "pairing_secret_b64url"))!!

    @Test
    fun `secret hex and base64url agree`() {
        for (c in cases) {
            secretOf(c).use { assertContentEquals(hex(c, "pairing_secret_hex"), it, str(c, "name")) }
        }
    }

    @Test
    fun `canonical pair bytes match the vectors`() {
        for (c in cases) {
            val bytes = Canonical.pairBytes(
                str(c, "pc_id"), str(c, "pairing_id"), hex(c, "challenge_hex"), str(c, "device_name"),
                hex(c, "spki_hex").takeIf { it.isNotEmpty() },
            )
            assertEquals(str(c, "canonical_pair_bytes_hex"), Sha256.hex(bytes), str(c, "name"))
        }
    }

    @Test
    fun `challenge base64 and hex agree`() {
        for (c in cases) assertContentEquals(hex(c, "challenge_hex"), B64.decode(str(c, "challenge_b64")), str(c, "name"))
    }

    @Test
    fun `proof and SAS match the vectors`() {
        for (c in cases) {
            val spki = hex(c, "spki_hex").takeIf { it.isNotEmpty() }
            val secret = secretOf(c)
            val proof = PairingCrypto.proof(
                secret, str(c, "pc_id"), str(c, "pairing_id"), hex(c, "challenge_hex"), str(c, "device_name"), spki,
            )
            assertEquals(str(c, "proof_hmac_sha256_hex"), Sha256.hex(proof), str(c, "name"))
            assertEquals(str(c, "proof_b64"), B64.encode(proof), str(c, "name"))
            assertEquals(str(c, "sas"), PairingCrypto.sas(secret, hex(c, "challenge_hex"), spki), str(c, "name"))
        }
    }

    @Test
    fun `proof verification cases`() {
        val verify = pair["verify_cases"]!!.jsonArray.map { it.jsonObject }
        for (v in verify) {
            val c = cases.first { str(it, "name") == str(v, "case") }
            val expected = HmacSha256.mac(
                secretOf(c).use { it.copyOf() },
                Canonical.pairBytes(
                    str(c, "pc_id"), str(c, "pairing_id"), hex(c, "challenge_hex"), str(c, "device_name"),
                    hex(c, "spki_hex").takeIf { it.isNotEmpty() },
                ),
            )
            val actual = B64.decode(str(v, "proof_b64"))
            val valid = actual != null && HmacSha256.constantTimeEquals(expected, actual)
            assertEquals(v["expect_valid"]!!.jsonPrimitive.content.toBoolean(), valid, str(v, "name"))
        }
    }

    @Test
    fun `invalid pair inputs are refused`() {
        val invalid = pair["invalid_inputs"]!!.jsonArray.map { it.jsonObject }
        for (i in invalid) {
            assertFailsWith<IllegalArgumentException>(str(i, "name")) {
                Canonical.pairBytes(
                    str(i, "pc_id"), str(i, "pairing_id"), hex(i, "challenge_hex"), str(i, "device_name"), hex(i, "spki_hex"),
                )
            }
        }
    }

    @Test
    fun `fitDeviceName normalises to NFC and never exceeds 64 bytes`() {
        val decomposed = "홍" // Hangul jamo for a syllable that has a precomposed form
        assertEquals("홍", Canonical.fitDeviceName(decomposed))
        val long = "가".repeat(30)
        val fitted = Canonical.fitDeviceName(long)
        assertTrue(fitted.toByteArray(Charsets.UTF_8).size <= 64)
        assertEquals(21, fitted.length)
        assertEquals("Galaxy S25", Canonical.fitDeviceName("Galaxy S25"))
    }

    @Test
    fun `pin vectors`() {
        val pins = Fixtures.json("vectors/pin.json").jsonObject["cases"]!!.jsonArray.map { it.jsonObject }
        for (p in pins) {
            val spki = Sha256.unhex(str(p, "spki_hex"))!!
            val pin = SpkiPin.ofSpki(spki)
            assertEquals(str(p, "spki_pin"), pin.toPinString(), str(p, "name"))
            assertEquals(str(p, "pc_id"), pin.derivedPcId(), str(p, "name"))
            assertEquals(str(p, "sha256_hex"), Sha256.hex(Sha256.digest(spki)), str(p, "name"))
            assertEquals(pin, SpkiPin.parse(str(p, "spki_pin")))
            assertTrue(pin.matchesSpki(spki))
            assertFalse(pin.matchesSpki(spki.copyOf().also { it[10] = (it[10] + 1).toByte() }))
        }
    }

    @Test
    fun `tool_input_sha256 canonical JSON vectors`() {
        val cases = Fixtures.json("vectors/tool_input_sha256.json").jsonObject["cases"] as JsonArray
        for (c in cases.map { it.jsonObject }) {
            val input = Fixtures.let { dev.agentnest.core.protocol.Codec.json.parseToJsonElement(str(c, "input_json")) }
            val canonical = Canonical.json(input)
            assertEquals(str(c, "canonical_json"), canonical, str(c, "name"))
            assertEquals(str(c, "sha256_hex"), Canonical.toolInputSha256(input), str(c, "name"))
        }
    }

    @Test
    fun `ECMAScript number formatting`() {
        fun fmt(d: Double) = Canonical.ecmaNumberToString(d)
        assertEquals("0", fmt(0.0))
        assertEquals("0", fmt(-0.0))
        assertEquals("1", fmt(1.0))
        assertEquals("-1.5", fmt(-1.5))
        assertEquals("100000000000000000000", fmt(1e20))
        assertEquals("1e+21", fmt(1e21))
        assertEquals("0.000001", fmt(1e-6))
        assertEquals("1e-7", fmt(1e-7))
        assertEquals("0.30000000000000004", fmt(0.30000000000000004))
        assertEquals("5e-324", fmt(java.lang.Double.MIN_VALUE))
        assertEquals("1.7976931348623157e+308", fmt(Double.MAX_VALUE))
        assertFailsWith<Canonical.UnsupportedNumberException> { fmt(Double.NaN) }
    }

    @Test
    fun `hmac and hashing helpers`() {
        // RFC 4231 test case 2
        val mac = HmacSha256.mac("Jefe".toByteArray(), "what do ya want for nothing?".toByteArray())
        assertEquals("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", Sha256.hex(mac))
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Sha256.hex(Sha256.digest(ByteArray(0))))
        assertNotNull(Sha256.unhex("00ff"))
        assertEquals(null, Sha256.unhex("0g"))
        assertEquals(null, Sha256.unhex("abc"))
        assertEquals(null, B64.decode("not base64!"))
        assertContentEquals(byteArrayOf(1, 2, 3), B64.decodeUrl(B64.encodeUrl(byteArrayOf(1, 2, 3))))
    }

    @Test
    fun `secrets never appear in toString`() {
        val secret = secretOf(cases.first())
        assertFalse(secret.toString().contains(str(cases.first(), "pairing_secret_b64url")))
        secret.wipe()
        secret.use { assertTrue(it.all { b -> b == 0.toByte() }) }
    }
}
