package dev.agentnest.core.link

import dev.agentnest.core.Fixtures
import dev.agentnest.core.T
import dev.agentnest.core.crypto.B64
import dev.agentnest.core.crypto.Canonical
import dev.agentnest.core.crypto.HmacSha256
import dev.agentnest.core.crypto.PairingCrypto
import dev.agentnest.core.crypto.PairingSecret
import dev.agentnest.core.crypto.Sha256
import dev.agentnest.core.protocol.ChallengeMessage
import dev.agentnest.core.protocol.ChallengePayload
import dev.agentnest.core.protocol.Codec
import dev.agentnest.core.protocol.DecodeResult
import dev.agentnest.core.protocol.ErrorMessage
import dev.agentnest.core.protocol.ErrorPayload
import dev.agentnest.core.protocol.PairMessage
import dev.agentnest.core.protocol.PairPendingMessage
import dev.agentnest.core.protocol.PairPendingPayload
import dev.agentnest.core.protocol.PairResultMessage
import dev.agentnest.core.protocol.PairResultPayload
import dev.agentnest.core.protocol.QrParseResult
import dev.agentnest.core.protocol.QrPayload
import dev.agentnest.core.protocol.Ts
import dev.agentnest.core.protocol.UnpairMessage
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** Uses the typical case of protocol/vectors/pair.json: QR secret, challenge, device key, expected SAS and proof. */
class PairingFlowTest {
    private val now = Instant.parse("2026-10-15T09:00:00Z")
    private val vector: JsonObject = Fixtures.json("vectors/pair.json").jsonObject["cases"]!!.jsonArray.map { it.jsonObject }.first { it.getValue("name").jsonPrimitive.content == "typical" }

    private fun v(key: String) = vector.getValue(key).jsonPrimitive.content
    private val spki = Sha256.unhex(v("spki_hex"))!!
    private val challengeB64 = v("challenge_b64")
    private val expectedSas = v("sas")

    private fun qr(): QrPayload {
        val json = """{"v":1,"pc_id":"pc_8252e6280a3d81d1","pc_name":"DESKTOP-HOME","hosts":["192.168.0.10","10.8.0.2"],"port":47832,""" +
            """"spki_pin":"sha256/glLmKAo9gdGvAGIYNxNEvncjE6SNAheIa/dX4bFINbU=","pairing_id":"p_3f9c2b1ea8d04c77",""" +
            """"pairing_secret":"${v("pairing_secret_b64url")}","expires_at":"2026-10-15T09:02:00Z"}"""
        return assertIs<QrParseResult.Success>(QrPayload.parse(QrPayload.URI_PREFIX + B64.encodeUrl(json.toByteArray()), now)).payload
    }

    private fun flow(qr: QrPayload = qr()) = PairingFlow(qr, DeviceDescriptor("Galaxy S25", "SM-S938N", "16", "0.1.0"), spki, ids = { T.id() })

    private fun challenge(pcId: String = "pc_8252e6280a3d81d1", b64: String = challengeB64) =
        ChallengeMessage(T.meta(at = now), ChallengePayload(b64, pcId, Ts.of(now), 5000))

    private fun pending(sas: String, pairingId: String = "p_3f9c2b1ea8d04c77", timeoutMs: Long = 60_000) =
        PairPendingMessage(T.meta(at = now), PairPendingPayload(pairingId, sas, timeoutMs))

    private fun result(ok: Boolean = true, pc: String = "pc_8252e6280a3d81d1", error: String? = null) =
        PairResultMessage(
            T.meta(at = now),
            PairResultPayload(ok, if (ok) "dev_8a1f3c" else null, if (ok) "Zr9tokenvalue" else null, if (ok) T.PC.copy(pcId = pc) else null, error),
        )

    private fun sent(effects: List<PairingEffect>) = effects.filterIsInstance<PairingEffect.Send>().map { it.message }

    @Test
    fun `challenge is answered with a pair message carrying the vector proof`() {
        val f = flow()
        val effects = f.onMessage(challenge(), now)
        val pair = assertIs<PairMessage>(sent(effects).single())
        assertEquals("p_3f9c2b1ea8d04c77", pair.payload.pairingId)
        assertEquals(challengeB64, pair.payload.challengeB64)
        assertEquals(v("proof_b64"), pair.payload.proofB64, "byte-identical to the shared vector")
        assertEquals(B64.encode(spki), pair.payload.devicePubkeySpkiB64)
        assertEquals("Galaxy S25", pair.payload.device.name)
        assertEquals(PairingPhase.WaitingForPairPending, f.phase)
        // The frame is valid wire JSON.
        assertIs<DecodeResult.Decoded>(Codec.decode(Codec.encode(pair)))
        // proof really is HMAC(secret, canonical bytes)
        val canonical = Canonical.pairBytes("pc_8252e6280a3d81d1", "p_3f9c2b1ea8d04c77", B64.decode(challengeB64)!!, "Galaxy S25", spki)
        val expected = HmacSha256.mac(PairingSecret.fromBase64Url(v("pairing_secret_b64url"))!!.use { it.copyOf() }, canonical)
        assertEquals(B64.encode(expected), pair.payload.proofB64)
    }

    @Test
    fun `matching SAS is shown from the local computation and then the pairing completes`() {
        val f = flow()
        f.onMessage(challenge(), now)
        val effects = f.onMessage(pending(expectedSas), now)
        assertEquals(listOf(PairingEffect.ShowSas(expectedSas)), effects)
        val shown = assertIs<PairingPhase.ShowingSas>(f.phase)
        assertEquals(now.plusSeconds(65), shown.deadline, "60 s confirm timeout plus 5 s grace")

        val done = f.onMessage(result(), now.plusSeconds(10))
        val completed = assertIs<PairingEffect.Completed>(done.single()).result
        assertEquals("dev_8a1f3c", completed.deviceId)
        assertEquals("Zr9tokenvalue", completed.deviceToken)
        assertEquals("pc_8252e6280a3d81d1", completed.pc.pcId)
        assertEquals("sha256/glLmKAo9gdGvAGIYNxNEvncjE6SNAheIa/dX4bFINbU=", completed.pin.toPinString())
        assertEquals(listOf("192.168.0.10", "10.8.0.2"), completed.hosts.candidates())
        assertFalse(completed.toString().contains("Zr9tokenvalue"))
    }

    @Test
    fun `the phone never displays the SAS the PC sent`() {
        val f = flow()
        f.onMessage(challenge(), now)
        // PC sends a different number: mismatch -> abort with unpair{pairing_id}, close, wipe.
        val wrong = if (expectedSas == "000000") "000001" else "000000"
        assertNotEquals(expectedSas, wrong)
        val effects = f.onMessage(pending(wrong), now)
        assertTrue(effects.none { it is PairingEffect.ShowSas }, "a mismatching SAS must never be shown")
        val unpair = assertIs<UnpairMessage>(sent(effects).single())
        assertEquals("p_3f9c2b1ea8d04c77", unpair.payload.pairingId)
        assertEquals(null, unpair.payload.deviceId)
        assertTrue(effects.any { it is PairingEffect.Close })
        assertEquals(PairingEffect.Failed(PairingFailure.SAS_MISMATCH), effects.last())
        assertEquals("PC에서 받은 확인 숫자가 달라요. 페어링을 중단했어요", PairingFailure.SAS_MISMATCH.messageKo)
        assertEquals(PairingPhase.Failed(PairingFailure.SAS_MISMATCH), f.phase)
    }

    @Test
    fun `the secret is wiped on every terminal path`() {
        for (scenario in 0..3) {
            val q = qr()
            val f = flow(q)
            f.onMessage(challenge(), now)
            when (scenario) {
                0 -> f.onMessage(pending("999999"), now)
                1 -> { f.onMessage(pending(expectedSas), now); f.onMessage(result(), now) }
                2 -> f.onMessage(ErrorMessage(T.meta(), ErrorPayload("E_PAIR_FAILED", "x", null, null, true)), now)
                3 -> f.cancel(now)
            }
            q.secret.use { assertTrue(it.all { b -> b == 0.toByte() }, "scenario $scenario") }
        }
    }

    @Test
    fun `challenge for another PC aborts without answering`() {
        val q = qr()
        val f = flow(q)
        val effects = f.onMessage(challenge(pcId = "pc_ffffffffffffffff"), now)
        assertTrue(sent(effects).isEmpty(), "no proof for a PC the QR does not describe")
        assertEquals(PairingPhase.Failed(PairingFailure.PC_ID_MISMATCH), f.phase)
    }

    @Test
    fun `malformed challenge is refused`() {
        val f = flow()
        val effects = f.onMessage(challenge(b64 = B64.encode(ByteArray(15))), now)
        assertTrue(sent(effects).isEmpty())
        assertEquals(PairingPhase.Failed(PairingFailure.BAD_CHALLENGE), f.phase)
    }

    @Test
    fun `pair_pending for another pairing is a protocol error`() {
        val f = flow()
        f.onMessage(challenge(), now)
        f.onMessage(pending(expectedSas, pairingId = "p_other"), now)
        assertEquals(PairingPhase.Failed(PairingFailure.PROTOCOL), f.phase)
    }

    @Test
    fun `failures map to the Korean messages`() {
        for ((code, failure) in listOf(
            "E_PAIR_REJECTED" to PairingFailure.PAIR_REJECTED,
            "E_PAIR_BUSY" to PairingFailure.PAIR_BUSY,
            "E_PAIR_FAILED" to PairingFailure.PAIR_FAILED,
        )) {
            val f = flow()
            f.onMessage(challenge(), now)
            f.onMessage(pending(expectedSas), now)
            val effects = f.onMessage(result(ok = false, error = code), now)
            assertEquals(PairingEffect.Failed(failure), effects.single(), code)
        }
        assertEquals("PC에서 거절했어요", PairingFailure.PAIR_REJECTED.messageKo)
        assertEquals("PC에서 다른 요청을 먼저 처리하세요", PairingFailure.PAIR_BUSY.messageKo)
    }

    @Test
    fun `pair_result from a different PC or without a token is refused`() {
        val f = flow()
        f.onMessage(challenge(), now)
        f.onMessage(pending(expectedSas), now)
        f.onMessage(result(pc = "pc_ffffffffffffffff"), now)
        assertEquals(PairingPhase.Failed(PairingFailure.PROTOCOL), f.phase)
    }

    @Test
    fun `no approval on the PC in time ends the flow and tells the PC to drop it`() {
        val f = flow()
        f.onMessage(challenge(), now)
        f.onMessage(pending(expectedSas, timeoutMs = 60_000), now)
        assertTrue(f.onTick(now.plusSeconds(65)).isEmpty())
        val effects = f.onTick(now.plusSeconds(66))
        assertIs<UnpairMessage>(sent(effects).single())
        assertEquals(PairingPhase.Failed(PairingFailure.TIMEOUT), f.phase)
    }

    @Test
    fun `connection loss and cancel end the flow once`() {
        val a = flow()
        a.onMessage(challenge(), now)
        assertEquals(PairingEffect.Failed(PairingFailure.CONNECTION_LOST), a.onConnectionClosed().single())
        assertTrue(a.onConnectionClosed().isEmpty())

        val b = flow()
        assertTrue(sent(b.cancel(now)).isEmpty(), "cancelling before the challenge sends nothing")
        val c = flow()
        c.onMessage(challenge(), now)
        assertIs<UnpairMessage>(sent(c.cancel(now)).single())
    }

    @Test
    fun `terminal flows ignore further messages`() {
        val f = flow()
        f.onMessage(challenge(), now)
        f.onMessage(pending("111111"), now)
        assertTrue(f.onMessage(pending(expectedSas), now).isEmpty())
    }

    @Test
    fun `SAS used for comparison equals the vector computation`() {
        val secret = PairingSecret.fromBase64Url(v("pairing_secret_b64url"))!!
        assertEquals(expectedSas, PairingCrypto.sas(secret, B64.decode(challengeB64)!!, spki))
    }
}
