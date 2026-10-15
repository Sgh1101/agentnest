package dev.agentnest.app

import dev.agentnest.app.pairing.PairingController
import dev.agentnest.app.pairing.PairingSession
import dev.agentnest.app.pairing.PairingSessionState
import dev.agentnest.app.pairing.PairingUiState
import dev.agentnest.core.crypto.B64
import dev.agentnest.core.crypto.PairingCrypto
import dev.agentnest.core.crypto.SpkiPin
import dev.agentnest.core.link.DeviceDescriptor
import dev.agentnest.core.link.TransportFailure
import dev.agentnest.core.link.TransportFailureKind
import dev.agentnest.core.link.WsCallbacks
import dev.agentnest.core.link.WsConnection
import dev.agentnest.core.link.WsTransport
import dev.agentnest.core.protocol.ChallengeMessage
import dev.agentnest.core.protocol.ChallengePayload
import dev.agentnest.core.protocol.Codec
import dev.agentnest.core.protocol.DecodeResult
import dev.agentnest.core.protocol.PairMessage
import dev.agentnest.core.protocol.PairPendingMessage
import dev.agentnest.core.protocol.PairPendingPayload
import dev.agentnest.core.protocol.PairResultMessage
import dev.agentnest.core.protocol.PairResultPayload
import dev.agentnest.core.protocol.QrParseResult
import dev.agentnest.core.protocol.QrPayload
import dev.agentnest.core.protocol.Ts
import dev.agentnest.core.protocol.UnpairMessage
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class PairingSessionTest {
    private val now: Instant = Instant.parse("2026-10-15T12:00:00Z")
    private val fixedClock: Clock = Clock.fixed(now, ZoneOffset.UTC)
    private val pin = SpkiPin.ofSpki(ByteArray(91) { it.toByte() })
    private val secretBytes = ByteArray(32) { (it + 1).toByte() }
    private val spki = ByteArray(91) { (it * 3).toByte() }
    private val challengeBytes = ByteArray(16) { (it + 40).toByte() }

    private fun qrText(hosts: List<String>): String {
        val json = """{"v":1,"pc_id":"${pin.derivedPcId()}","pc_name":"DESKTOP-HOME","hosts":[${hosts.joinToString(",") { "\"$it\"" }}],"port":47832,""" +
            """"spki_pin":"${pin.toPinString()}","pairing_id":"p_3f9c2b1ea8d04c77","pairing_secret":"${B64.encodeUrl(secretBytes)}",""" +
            """"expires_at":"2026-10-15T12:02:00Z"}"""
        return QrPayload.URI_PREFIX + B64.encodeUrl(json.toByteArray(Charsets.UTF_8))
    }

    private fun parseQr(hosts: List<String>): QrPayload =
        (QrPayload.parse(qrText(hosts), now) as QrParseResult.Success).payload

    private class FakeTransport : WsTransport {
        class Opened(val host: String, val callbacks: WsCallbacks)

        val opened = ArrayList<Opened>()
        val sent = ArrayList<String>()
        val closed = ArrayList<Int>()

        override fun open(host: String, port: Int, callbacks: WsCallbacks): WsConnection {
            opened += Opened(host, callbacks)
            return object : WsConnection {
                override fun send(text: String): Boolean {
                    sent += text
                    return true
                }

                override fun close(code: Int, reason: String) {
                    closed += code
                }

                override fun cancel() = Unit
            }
        }
    }

    private fun TestScope.session(qr: QrPayload, transport: FakeTransport) =
        PairingSession(qr, DeviceDescriptor("Pixel"), spki, transport, backgroundScope, fixedClock)

    private fun challengeFrame(): String = Codec.encodeAny(
        ChallengeMessage(
            TD.meta(at = now),
            ChallengePayload(B64.encode(challengeBytes), pin.derivedPcId(), Ts.of(now), 5000),
        ),
    )

    @Test
    fun triesTheNextAddressWhenOneIsUnreachableAndFailsWhenAllAre() = runTest {
        val transport = FakeTransport()
        val session = session(parseQr(listOf("192.168.0.10", "10.8.0.2")), transport)
        session.start()
        runCurrent()
        assertEquals(listOf("192.168.0.10"), transport.opened.map { it.host })
        assertEquals(PairingSessionState.Connecting("192.168.0.10"), session.state.value)

        transport.opened[0].callbacks.onFailure(TransportFailure(TransportFailureKind.UNREACHABLE, "x"))
        runCurrent()
        assertEquals(listOf("192.168.0.10", "10.8.0.2"), transport.opened.map { it.host })
        assertEquals(PairingSessionState.Connecting("10.8.0.2"), session.state.value)

        transport.opened[1].callbacks.onFailure(TransportFailure(TransportFailureKind.UNREACHABLE, "x"))
        runCurrent()
        assertTrue(session.state.value is PairingSessionState.Failed)
    }

    @Test
    fun aPinMismatchIsReportedAsAnIdentityProblem() = runTest {
        val transport = FakeTransport()
        val session = session(parseQr(listOf("192.168.0.10")), transport)
        session.start()
        runCurrent()
        transport.opened[0].callbacks.onFailure(TransportFailure(TransportFailureKind.PIN_MISMATCH, "x"))
        runCurrent()
        val failed = session.state.value as PairingSessionState.Failed
        assertTrue(failed.messageKo.contains("인증 정보"))
    }

    @Test
    fun happyPathShowsTheLocallyComputedSasAndCompletes() = runTest {
        val transport = FakeTransport()
        val session = session(parseQr(listOf("192.168.0.10")), transport)
        session.start()
        runCurrent()
        val callbacks = transport.opened[0].callbacks
        callbacks.onOpen()
        callbacks.onText(challengeFrame())
        runCurrent()

        val pair = (Codec.decode(transport.sent.single()) as DecodeResult.Decoded).message as PairMessage
        assertEquals("p_3f9c2b1ea8d04c77", pair.payload.pairingId)

        // The PC answers with the SAS it computed; the phone shows ITS OWN computation (equal here).
        val expectedSas = PairingCrypto.sas(parseQr(listOf("192.168.0.10")).secret, challengeBytes, spki)
        callbacks.onText(Codec.encodeAny(PairPendingMessage(TD.meta(at = now), PairPendingPayload("p_3f9c2b1ea8d04c77", expectedSas, 60_000))))
        runCurrent()
        assertEquals(PairingSessionState.ShowingSas(expectedSas), session.state.value)

        val result = PairResultPayload(true, "dev_1", B64.encodeUrl(ByteArray(32) { 7 }), TD.PC.copy(pcId = pin.derivedPcId()), null)
        callbacks.onText(Codec.encodeAny(PairResultMessage(TD.meta(at = now), result)))
        runCurrent()
        val completed = session.state.value as PairingSessionState.Completed
        assertEquals("dev_1", completed.result.deviceId)
        assertTrue(transport.closed.contains(1000))
    }

    @Test
    fun aWrongSasAbortsWithUnpairAndNeverShowsTheNumber() = runTest {
        val transport = FakeTransport()
        val session = session(parseQr(listOf("192.168.0.10")), transport)
        session.start()
        runCurrent()
        val callbacks = transport.opened[0].callbacks
        callbacks.onText(challengeFrame())
        runCurrent()
        val wrong = "000000"
        val expected = PairingCrypto.sas(parseQr(listOf("192.168.0.10")).secret, challengeBytes, spki)
        val sas = if (expected == wrong) "111111" else wrong
        callbacks.onText(Codec.encodeAny(PairPendingMessage(TD.meta(at = now), PairPendingPayload("p_3f9c2b1ea8d04c77", sas, 60_000))))
        runCurrent()
        assertTrue(session.state.value is PairingSessionState.Failed)
        val sentTypes = transport.sent.map { ((Codec.decode(it) as DecodeResult.Decoded).message).type }
        assertEquals(listOf("pair", "unpair"), sentTypes)
        assertTrue(((Codec.decode(transport.sent.last()) as DecodeResult.Decoded).message) is UnpairMessage)
    }

    @Test
    fun cancelAfterTheChallengeSendsUnpair() = runTest {
        val transport = FakeTransport()
        val session = session(parseQr(listOf("192.168.0.10")), transport)
        session.start()
        runCurrent()
        transport.opened[0].callbacks.onText(challengeFrame())
        runCurrent()
        session.cancel()
        runCurrent()
        assertTrue(transport.sent.any { ((Codec.decode(it) as DecodeResult.Decoded).message) is UnpairMessage })
    }

    @Test
    fun controllerPersistsBeforeReportingDone() = runTest {
        val transport = FakeTransport()
        val persisted = ArrayList<String>()
        var startedService = 0
        val controller = PairingController(
            scope = backgroundScope,
            transportFactory = { transport },
            devicePublicKey = { spki },
            device = { DeviceDescriptor("Pixel") },
            persist = { result -> persisted += result.deviceId },
            onPersisted = { startedService++ },
        )
        controller.begin(parseQr(listOf("192.168.0.10")))
        runCurrent()
        assertTrue(controller.state.value is PairingUiState.Connecting)
        val callbacks = transport.opened[0].callbacks
        callbacks.onText(challengeFrame())
        runCurrent()
        val sas = PairingCrypto.sas(parseQr(listOf("192.168.0.10")).secret, challengeBytes, spki)
        callbacks.onText(Codec.encodeAny(PairPendingMessage(TD.meta(at = now), PairPendingPayload("p_3f9c2b1ea8d04c77", sas, 60_000))))
        runCurrent()
        assertEquals(PairingUiState.ShowingSas(sas), controller.state.value)
        val result = PairResultPayload(true, "dev_9", B64.encodeUrl(ByteArray(32) { 9 }), TD.PC.copy(pcId = pin.derivedPcId()), null)
        callbacks.onText(Codec.encodeAny(PairResultMessage(TD.meta(at = now), result)))
        runCurrent()
        assertEquals(PairingUiState.Done, controller.state.value)
        assertEquals(listOf("dev_9"), persisted)
        assertEquals(1, startedService)
    }
}
