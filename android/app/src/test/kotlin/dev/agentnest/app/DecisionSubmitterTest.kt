package dev.agentnest.app

import dev.agentnest.app.approval.AuthAvailability
import dev.agentnest.app.approval.AuthOutcome
import dev.agentnest.app.approval.AuthRequest
import dev.agentnest.app.approval.DecisionSubmitter
import dev.agentnest.app.approval.SubmitOutcome
import dev.agentnest.app.approval.UserAuthenticator
import dev.agentnest.app.data.NestRepository
import dev.agentnest.core.approval.DecisionBlock
import dev.agentnest.core.link.BackoffPolicy
import dev.agentnest.core.link.DeviceCredentials
import dev.agentnest.core.link.HostBookState
import dev.agentnest.core.link.LinkClient
import dev.agentnest.core.link.LinkSideEffects
import dev.agentnest.core.link.SecurityAlertKind
import dev.agentnest.core.link.WsCallbacks
import dev.agentnest.core.link.WsConnection
import dev.agentnest.core.link.WsTransport
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.AuthMethod
import dev.agentnest.core.protocol.ChallengeMessage
import dev.agentnest.core.protocol.ChallengePayload
import dev.agentnest.core.protocol.ClientMessage
import dev.agentnest.core.protocol.Codec
import dev.agentnest.core.protocol.DecisionMessage
import dev.agentnest.core.protocol.DecodeResult
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.RiskLevel
import dev.agentnest.core.protocol.ServerMessage
import dev.agentnest.core.protocol.Ts
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The decision path end to end with a scripted PC: validator -> authentication -> builder -> LinkClient. Proves that the
 * prompt comes first, that nothing is built or sent when a gate fails, and that nothing is queued offline.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class DecisionSubmitterTest {
    private val start: Instant = TD.T0

    private class FakeTransport : WsTransport {
        lateinit var callbacks: WsCallbacks
        val sent = ArrayList<String>()
        override fun open(host: String, port: Int, callbacks: WsCallbacks): WsConnection {
            this.callbacks = callbacks
            return object : WsConnection {
                override fun send(text: String): Boolean {
                    sent += text
                    return true
                }

                override fun close(code: Int, reason: String) = Unit
                override fun cancel() = Unit
            }
        }

        fun decisions(): List<DecisionMessage> =
            sent.mapNotNull { (Codec.decode(it) as? DecodeResult.Decoded)?.message as? DecisionMessage }
    }

    private class NoEffects : LinkSideEffects {
        override fun persistHosts(hosts: HostBookState) = Unit
        override fun wipeDeviceToken() = Unit
        override fun wipePairing() = Unit
        override fun securityAlert(kind: SecurityAlertKind) = Unit
    }

    private class FakeAuth(var outcome: AuthOutcome, var availability: AuthAvailability = AuthAvailability.READY) : UserAuthenticator {
        var prompts = 0
        val requests = ArrayList<AuthRequest>()
        override fun availability(): AuthAvailability = availability
        override suspend fun authenticate(request: AuthRequest): AuthOutcome {
            prompts++
            requests += request
            return outcome
        }
    }

    private fun TestScope.clock(): Clock = object : Clock() {
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId?): Clock = this
        override fun instant(): Instant = start.plusMillis(testScheduler.currentTime)
    }

    private class Fixture(val transport: FakeTransport, val repo: NestRepository, val client: LinkClient)

    private fun TestScope.connected(
        request: dev.agentnest.core.protocol.ApprovalRequest?,
        policy: dev.agentnest.core.protocol.Policy = dev.agentnest.core.protocol.Policy(),
    ): Fixture {
        val transport = FakeTransport()
        val client = LinkClient(
            transport = transport,
            hosts = HostBookState(qr = listOf("192.168.0.10")),
            credentials = { DeviceCredentials("dev_1", B64Token) },
            sideEffects = NoEffects(),
            scope = backgroundScope,
            clock = clock(),
            backoff = BackoffPolicy(random = { 0.5 }),
            ids = { TD.id() },
        )
        val repo = NestRepository(backgroundScope, clock())
        repo.attach(client)
        client.start(paired = true)
        runCurrent()
        transport.callbacks.onOpen()
        transport.callbacks.onText(
            Codec.encodeAny(ChallengeMessage(TD.meta(at = start), ChallengePayload("cXk4Z1l0d2VyN3U4aW9wMQ==", TD.PC.pcId, Ts.of(start), 5000))),
        )
        transport.callbacks.onText(Codec.encodeAny(TD.welcome(at = start, policy = policy)))
        val approvals = if (request == null) emptyList() else listOf(request)
        val sessions = listOf(TD.session("claude_code:s1", AgentState.AWAITING_APPROVAL, pending = approvals.map { it.requestId }))
        transport.callbacks.onText(Codec.encodeAny(TD.snapshot(10, sessions = sessions, approvals = approvals, at = start)))
        runCurrent()
        return Fixture(transport, repo, client)
    }

    private val B64Token = dev.agentnest.core.crypto.B64.encodeUrl(ByteArray(32) { it.toByte() })

    private fun TestScope.submitter(fixture: Fixture, auth: UserAuthenticator) =
        DecisionSubmitter(fixture.repo, auth, clock = { start.plusMillis(testScheduler.currentTime) })

    @Test
    fun allowAuthenticatesFirstThenSendsExactlyOneDecision() = runTest {
        val f = connected(TD.request(level = RiskLevel.HIGH))
        val auth = FakeAuth(AuthOutcome.Success(AuthMethod.BIOMETRIC, start))
        val outcome = submitter(f, auth).submit(TD.REQUEST_ID, Decision.ALLOW, ExtraConfirmationLevel.HOLD)
        assertEquals(SubmitOutcome.Sent, outcome)
        assertEquals(1, auth.prompts)
        assertEquals("승인 확인", auth.requests.single().title)
        assertEquals("rm -rf node_modules && pnpm install", auth.requests.single().description)
        val decision = f.transport.decisions().single()
        assertEquals(Decision.ALLOW, decision.payload.decision)
        assertEquals(AuthMethod.BIOMETRIC, decision.payload.auth!!.method)
        assertEquals(ExtraConfirmationLevel.HOLD, decision.payload.extraConfirmation!!.method)
        assertEquals(TD.REQUEST_ID, decision.payload.requestId)
        // A second press while the first is in flight sends nothing more.
        assertEquals(SubmitOutcome.Blocked(DecisionBlock.IN_FLIGHT), submitter(f, auth).submit(TD.REQUEST_ID, Decision.ALLOW, ExtraConfirmationLevel.HOLD))
        assertEquals(1, f.transport.decisions().size)
    }

    @Test
    fun aCancelledAuthenticationSendsNothing() = runTest {
        val f = connected(TD.request())
        val outcome = submitter(f, FakeAuth(AuthOutcome.Cancelled)).submit(TD.REQUEST_ID, Decision.ALLOW, ExtraConfirmationLevel.HOLD)
        assertEquals(SubmitOutcome.AuthCancelled, outcome)
        assertTrue(f.transport.decisions().isEmpty())
    }

    @Test
    fun aFailedAuthenticationSendsNothing() = runTest {
        val f = connected(TD.request())
        val outcome = submitter(f, FakeAuth(AuthOutcome.Failed("x"))).submit(TD.REQUEST_ID, Decision.ALLOW, ExtraConfirmationLevel.HOLD)
        assertEquals(SubmitOutcome.AuthFailed("x"), outcome)
        assertTrue(f.transport.decisions().isEmpty())
    }

    @Test
    fun highRiskWithoutTheHoldGateIsRefusedAfterAuthentication() = runTest {
        val f = connected(TD.request(level = RiskLevel.HIGH))
        val auth = FakeAuth(AuthOutcome.Success(AuthMethod.DEVICE_CREDENTIAL, start))
        val outcome = submitter(f, auth).submit(TD.REQUEST_ID, Decision.ALLOW, ExtraConfirmationLevel.NONE)
        assertEquals(SubmitOutcome.Blocked(DecisionBlock.EXTRA_CONFIRMATION_REQUIRED), outcome)
        assertTrue(f.transport.decisions().isEmpty())
    }

    @Test
    fun criticalNeedsTheReconfirmationLevelToo() = runTest {
        val f = connected(TD.request(level = RiskLevel.CRITICAL, extra = ExtraConfirmationLevel.HOLD_AND_RECONFIRM))
        val auth = FakeAuth(AuthOutcome.Success(AuthMethod.BIOMETRIC, start))
        assertEquals(
            SubmitOutcome.Blocked(DecisionBlock.EXTRA_CONFIRMATION_REQUIRED),
            submitter(f, auth).submit(TD.REQUEST_ID, Decision.ALLOW, ExtraConfirmationLevel.HOLD),
        )
        assertTrue(f.transport.decisions().isEmpty())
        assertEquals(
            SubmitOutcome.Sent,
            submitter(f, auth).submit(TD.REQUEST_ID, Decision.ALLOW, ExtraConfirmationLevel.HOLD_AND_RECONFIRM),
        )
    }

    @Test
    fun aPlainDenyNeedsNoAuthenticationByDefault() = runTest {
        val f = connected(TD.request(level = RiskLevel.CRITICAL, extra = ExtraConfirmationLevel.HOLD_AND_RECONFIRM))
        val auth = FakeAuth(AuthOutcome.Cancelled)
        val outcome = submitter(f, auth).submit(TD.REQUEST_ID, Decision.DENY, ExtraConfirmationLevel.NONE)
        assertEquals(SubmitOutcome.Sent, outcome)
        assertEquals(0, auth.prompts)
        assertEquals(Decision.DENY, f.transport.decisions().single().payload.decision)
    }

    @Test
    fun denyNeedsAuthenticationWhenThePcPolicyRequiresIt() = runTest {
        val f = connected(TD.request(), dev.agentnest.core.protocol.Policy(denyRequiresAuth = true))
        val cancelled = FakeAuth(AuthOutcome.Cancelled)
        assertEquals(SubmitOutcome.AuthCancelled, submitter(f, cancelled).submit(TD.REQUEST_ID, Decision.DENY, ExtraConfirmationLevel.NONE))
        assertEquals(1, cancelled.prompts)
        assertTrue(f.transport.decisions().isEmpty())
        val ok = FakeAuth(AuthOutcome.Success(AuthMethod.DEVICE_CREDENTIAL, start))
        assertEquals(SubmitOutcome.Sent, submitter(f, ok).submit(TD.REQUEST_ID, Decision.DENY, ExtraConfirmationLevel.NONE))
        assertEquals(AuthMethod.DEVICE_CREDENTIAL, f.transport.decisions().single().payload.auth!!.method)
    }

    @Test
    fun codexHooksCardsNeverOfferDenyAndStop() = runTest {
        val f = connected(
            TD.request(
                origin = "codex.hook.cli",
                allowed = listOf(Decision.ALLOW, Decision.DENY, Decision.DENY_AND_STOP),
            ),
        )
        val auth = FakeAuth(AuthOutcome.Success(AuthMethod.BIOMETRIC, start))
        val outcome = submitter(f, auth).submit(TD.REQUEST_ID, Decision.DENY_AND_STOP, ExtraConfirmationLevel.HOLD)
        assertEquals(SubmitOutcome.Blocked(DecisionBlock.NOT_ALLOWED), outcome)
        assertEquals(0, auth.prompts)
    }

    @Test
    fun denyAndStopUsesTheSameGateAsAllow() = runTest {
        val f = connected(TD.request(level = RiskLevel.HIGH))
        val auth = FakeAuth(AuthOutcome.Success(AuthMethod.BIOMETRIC, start))
        assertEquals(
            SubmitOutcome.Blocked(DecisionBlock.EXTRA_CONFIRMATION_REQUIRED),
            submitter(f, auth).submit(TD.REQUEST_ID, Decision.DENY_AND_STOP, ExtraConfirmationLevel.NONE),
        )
        assertEquals(1, auth.prompts)
        assertTrue(f.transport.decisions().isEmpty())
    }

    @Test
    fun expiredCardsAreRefusedWithoutAPrompt() = runTest {
        val f = connected(TD.request(ttlSeconds = 120))
        // Advance the virtual clock past expires_at - 5 s.
        val auth = FakeAuth(AuthOutcome.Success(AuthMethod.BIOMETRIC, start))
        val late = DecisionSubmitter(f.repo, auth, clock = { start.plusSeconds(118) })
        assertEquals(SubmitOutcome.Blocked(DecisionBlock.EXPIRED), late.submit(TD.REQUEST_ID, Decision.ALLOW, ExtraConfirmationLevel.HOLD))
        assertEquals(0, auth.prompts)
        assertTrue(f.transport.decisions().isEmpty())
    }

    @Test
    fun unknownCardsAreRefusedWithoutAPrompt() = runTest {
        val f = connected(null)
        val auth = FakeAuth(AuthOutcome.Success(AuthMethod.BIOMETRIC, start))
        val outcome = submitter(f, auth).submit(TD.REQUEST_ID, Decision.ALLOW, ExtraConfirmationLevel.HOLD)
        assertEquals(SubmitOutcome.Blocked(DecisionBlock.EXPIRED), outcome)
        assertEquals(0, auth.prompts)
    }

    @Test
    fun nothingIsSentOrQueuedWhileTheLinkIsDown() = runTest {
        val f = connected(TD.request())
        // The service goes away: the repository forces a non-connected link.
        f.repo.detach()
        runCurrent()
        val auth = FakeAuth(AuthOutcome.Success(AuthMethod.BIOMETRIC, start))
        val outcome = submitter(f, auth).submit(TD.REQUEST_ID, Decision.ALLOW, ExtraConfirmationLevel.HOLD)
        assertEquals(SubmitOutcome.Blocked(DecisionBlock.OFFLINE), outcome)
        assertEquals(0, auth.prompts)
        assertTrue(f.transport.decisions().isEmpty())
        assertFalse(f.repo.connectedToService)
        assertTrue(f.repo.paused.value)
    }
}
