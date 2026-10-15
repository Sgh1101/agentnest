package dev.agentnest.core.approval

import dev.agentnest.core.T
import dev.agentnest.core.link.LinkError
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.nest.ApprovalCard
import dev.agentnest.core.nest.InFlightDecision
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.AuthMethod
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.Policy
import dev.agentnest.core.protocol.RemoteApproval
import dev.agentnest.core.protocol.RiskLevel
import java.time.Duration
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class DecisionValidatorTest {
    private val now = T.T0.plusSeconds(10) // the card was created at T0

    private fun card(
        level: RiskLevel = RiskLevel.HIGH,
        extra: ExtraConfirmationLevel = ExtraConfirmationLevel.HOLD,
        origin: String = "claude_code.hook.http",
        allowed: List<Decision> = listOf(Decision.ALLOW, Decision.DENY, Decision.DENY_AND_STOP),
        ttl: Long = 120,
    ) = ApprovalCard("ar_1", T.request(id = "ar_1", level = level, extra = extra, origin = origin, allowed = allowed, ttlSeconds = ttl), T.T0)

    private fun ctx(
        at: Instant = now,
        skew: Long = 0,
        link: LinkState = T.connected(),
        remote: RemoteApproval? = RemoteApproval.AVAILABLE,
        policy: Policy = Policy(),
    ) = DecisionContext(at, skew, link, remote?.let { T.session("claude_code:s1", AgentState.AWAITING_APPROVAL, remote = it) }, policy)

    private fun fullUser(at: Instant = now, extra: ExtraConfirmationLevel = ExtraConfirmationLevel.HOLD_AND_RECONFIRM) =
        UserGateResult(AuthMethod.BIOMETRIC, at.minusSeconds(2), extra)

    private fun blockOf(e: Enablement) = assertIs<Enablement.Disabled>(e).reason

    // ---- enablement -------------------------------------------------------------------------------

    @Test
    fun `enabled for a live connected card`() {
        val e = DecisionValidator.enablement(card(), Decision.ALLOW, ctx())
        assertIs<Enablement.Enabled>(e)
    }

    @Test
    fun `offline disables every decision and nothing is queued`() {
        for (link in listOf(
            LinkState.Offline, LinkState.Challenged, LinkState.Connecting("h", 1),
            LinkState.Reconnecting(1, now, LinkError.Unreachable), LinkState.PcUnreachable(now), LinkState.Unpaired,
        )) {
            for (d in listOf(Decision.ALLOW, Decision.DENY, Decision.DENY_AND_STOP)) {
                assertEquals(DecisionBlock.OFFLINE, blockOf(DecisionValidator.enablement(card(), d, ctx(link = link))), "$link $d")
            }
        }
    }

    @Test
    fun `expired card is never actionable`() {
        val c = card(ttl = 120) // expires T0+120
        assertIs<Enablement.Enabled>(DecisionValidator.enablement(c, Decision.ALLOW, ctx(at = T.T0.plusSeconds(114))))
        // expires_at - 5 s margin = T0+115
        assertEquals(DecisionBlock.EXPIRED, blockOf(DecisionValidator.enablement(c, Decision.ALLOW, ctx(at = T.T0.plusSeconds(115)))))
        assertEquals(DecisionBlock.EXPIRED, blockOf(DecisionValidator.enablement(c, Decision.DENY, ctx(at = T.T0.plusSeconds(200)))))
    }

    @Test
    fun `expiry margin accounts for clock skew`() {
        val c = card(ttl = 120)
        // PC clock is 20 s ahead: phone T0+95 is server T0+115 => margin reached.
        assertEquals(DecisionBlock.EXPIRED, blockOf(DecisionValidator.enablement(c, Decision.ALLOW, ctx(at = T.T0.plusSeconds(95), skew = 20_000))))
        assertIs<Enablement.Enabled>(DecisionValidator.enablement(c, Decision.ALLOW, ctx(at = T.T0.plusSeconds(94), skew = 20_000)))
        // PC clock behind by 20 s: more time on the phone.
        assertIs<Enablement.Enabled>(DecisionValidator.enablement(c, Decision.ALLOW, ctx(at = T.T0.plusSeconds(130), skew = -20_000)))
    }

    @Test
    fun `seconds left never goes negative`() {
        val request = card(ttl = 120).request!!
        assertEquals(110, DecisionValidator.secondsLeft(request, now, 0))
        assertEquals(0, DecisionValidator.secondsLeft(request, T.T0.plusSeconds(500), 0))
    }

    @Test
    fun `loading placeholder and in-flight cards are disabled`() {
        val loading = ApprovalCard("ar_1", null, T.T0)
        assertEquals(DecisionBlock.LOADING, blockOf(DecisionValidator.enablement(loading, Decision.DENY, ctx())))
        val inFlight = card().copy(inFlight = InFlightDecision("m", Decision.ALLOW, now))
        assertEquals(DecisionBlock.IN_FLIGHT, blockOf(DecisionValidator.enablement(inFlight, Decision.DENY, ctx())))
    }

    @Test
    fun `decisions must be listed in allowed_decisions`() {
        val c = card(allowed = listOf(Decision.ALLOW, Decision.DENY))
        assertEquals(DecisionBlock.NOT_ALLOWED, blockOf(DecisionValidator.enablement(c, Decision.DENY_AND_STOP, ctx())))
        assertEquals(DecisionBlock.UNKNOWN_DECISION, blockOf(DecisionValidator.enablement(c, Decision.UNKNOWN, ctx())))
    }

    @Test
    fun `codex hooks cards never offer deny_and_stop even if the list says so`() {
        val c = card(origin = "codex.hook.cli", allowed = listOf(Decision.ALLOW, Decision.DENY, Decision.DENY_AND_STOP))
        assertEquals(DecisionBlock.NOT_ALLOWED, blockOf(DecisionValidator.enablement(c, Decision.DENY_AND_STOP, ctx())))
        assertIs<Enablement.Enabled>(DecisionValidator.enablement(c, Decision.DENY, ctx()))
    }

    @Test
    fun `remote approval unavailable unknown or paused disables buttons`() {
        assertEquals(DecisionBlock.REMOTE_UNAVAILABLE, blockOf(DecisionValidator.enablement(card(), Decision.ALLOW, ctx(remote = RemoteApproval.UNAVAILABLE))))
        assertEquals(DecisionBlock.REMOTE_UNAVAILABLE, blockOf(DecisionValidator.enablement(card(), Decision.ALLOW, ctx(remote = RemoteApproval.UNKNOWN))))
        assertEquals(DecisionBlock.REMOTE_PAUSED, blockOf(DecisionValidator.enablement(card(), Decision.DENY, ctx(remote = RemoteApproval.PAUSED))))
        // The session is not known yet: the PC enforces it, the phone does not guess.
        assertIs<Enablement.Enabled>(DecisionValidator.enablement(card(), Decision.ALLOW, ctx(remote = null)))
    }

    @Test
    fun `critical local_only policy blocks allow but not deny`() {
        val policy = Policy(remoteApproval = mapOf("critical" to "local_only", "high" to "hold"))
        val c = card(level = RiskLevel.CRITICAL, extra = ExtraConfirmationLevel.HOLD_AND_RECONFIRM)
        assertEquals(DecisionBlock.LOCAL_ONLY, blockOf(DecisionValidator.enablement(c, Decision.ALLOW, ctx(policy = policy))))
        assertEquals(DecisionBlock.LOCAL_ONLY, blockOf(DecisionValidator.enablement(c, Decision.DENY_AND_STOP, ctx(policy = policy))))
        assertIs<Enablement.Enabled>(DecisionValidator.enablement(c, Decision.DENY, ctx(policy = policy)))
    }

    // ---- gates ------------------------------------------------------------------------------------

    @Test
    fun `gate table by risk level`() {
        fun gate(level: RiskLevel, extra: ExtraConfirmationLevel, d: Decision = Decision.ALLOW, policy: Policy = Policy()) =
            DecisionValidator.gate(card(level, extra).request!!, d, policy)

        assertEquals(ApprovalGate(Decision.ALLOW, true, ExtraConfirmationLevel.NONE), gate(RiskLevel.LOW, ExtraConfirmationLevel.NONE))
        assertEquals(ApprovalGate(Decision.ALLOW, true, ExtraConfirmationLevel.NONE), gate(RiskLevel.MEDIUM, ExtraConfirmationLevel.NONE))
        assertEquals(ApprovalGate(Decision.ALLOW, true, ExtraConfirmationLevel.HOLD), gate(RiskLevel.HIGH, ExtraConfirmationLevel.HOLD))
        assertEquals(ApprovalGate(Decision.ALLOW, true, ExtraConfirmationLevel.HOLD_AND_RECONFIRM), gate(RiskLevel.CRITICAL, ExtraConfirmationLevel.HOLD_AND_RECONFIRM))
        // deny_and_stop uses the allow gate.
        assertEquals(ApprovalGate(Decision.DENY_AND_STOP, true, ExtraConfirmationLevel.HOLD), gate(RiskLevel.HIGH, ExtraConfirmationLevel.HOLD, Decision.DENY_AND_STOP))
        // deny has no gate by default ...
        assertEquals(ApprovalGate(Decision.DENY, false, ExtraConfirmationLevel.NONE), gate(RiskLevel.CRITICAL, ExtraConfirmationLevel.HOLD_AND_RECONFIRM, Decision.DENY))
        // ... unless the PC policy says deny requires authentication (no extra confirmation for deny).
        assertEquals(
            ApprovalGate(Decision.DENY, true, ExtraConfirmationLevel.NONE),
            gate(RiskLevel.HIGH, ExtraConfirmationLevel.HOLD, Decision.DENY, Policy(denyRequiresAuth = true)),
        )
    }

    @Test
    fun `unknown risk is treated as high and unknown extra confirmation as the strongest`() {
        val unknownRisk = DecisionValidator.gate(card(RiskLevel.UNKNOWN, ExtraConfirmationLevel.NONE).request!!, Decision.ALLOW, Policy())
        assertEquals(ExtraConfirmationLevel.HOLD, unknownRisk.extraConfirmation)
        val unknownExtra = DecisionValidator.gate(card(RiskLevel.LOW, ExtraConfirmationLevel.UNKNOWN).request!!, Decision.ALLOW, Policy())
        assertEquals(ExtraConfirmationLevel.HOLD_AND_RECONFIRM, unknownExtra.extraConfirmation)
    }

    @Test
    fun `a card cannot weaken the allow gate through auth_required_for`() {
        val c = ApprovalCard("ar_1", T.request(id = "ar_1", authRequired = emptyList()), T.T0)
        assertTrue(DecisionValidator.gate(c.request!!, Decision.ALLOW, Policy()).requiresAuth)
        assertTrue(DecisionValidator.gate(c.request, Decision.DENY_AND_STOP, Policy()).requiresAuth)
    }

    // ---- validate (authentication freshness and extra confirmation) ---------------------------------

    @Test
    fun `valid decision passes all checks`() {
        assertEquals(Validation.Valid, DecisionValidator.validate(card(), Decision.ALLOW, fullUser(), ctx()))
        assertEquals(Validation.Valid, DecisionValidator.validate(card(), Decision.DENY, UserGateResult(), ctx()))
    }

    @Test
    fun `allow without authentication is refused`() {
        for (user in listOf(
            UserGateResult(AuthMethod.NONE, null, ExtraConfirmationLevel.HOLD),
            UserGateResult(AuthMethod.BIOMETRIC, null, ExtraConfirmationLevel.HOLD),
            UserGateResult(AuthMethod.UNKNOWN, now, ExtraConfirmationLevel.HOLD),
        )) {
            val r = DecisionValidator.validate(card(), Decision.ALLOW, user, ctx())
            assertEquals(Validation.Rejected(DecisionBlock.AUTH_REQUIRED), r)
        }
    }

    @Test
    fun `authentication older than 60 seconds is refused`() {
        val later = T.T0.plusSeconds(100) // still before the expiry margin of the default 120 s card
        val stale = UserGateResult(AuthMethod.BIOMETRIC, later.minusSeconds(61), ExtraConfirmationLevel.HOLD)
        assertEquals(Validation.Rejected(DecisionBlock.AUTH_STALE), DecisionValidator.validate(card(), Decision.ALLOW, stale, ctx(at = later)))
        val ok = UserGateResult(AuthMethod.DEVICE_CREDENTIAL, later.minusSeconds(60), ExtraConfirmationLevel.HOLD)
        assertEquals(Validation.Valid, DecisionValidator.validate(card(), Decision.ALLOW, ok, ctx(at = later)))
    }

    @Test
    fun `authentication from before the request was created is refused`() {
        // Card created at T0; authentication at T0-6 s (more than the 5 s tolerance) cannot be reused.
        val early = UserGateResult(AuthMethod.BIOMETRIC, T.T0.minusSeconds(6), ExtraConfirmationLevel.HOLD)
        assertEquals(Validation.Rejected(DecisionBlock.AUTH_BEFORE_REQUEST), DecisionValidator.validate(card(), Decision.ALLOW, early, ctx(at = T.T0.minusSeconds(1).plusSeconds(30))))
        val tolerated = UserGateResult(AuthMethod.BIOMETRIC, T.T0.minusSeconds(4), ExtraConfirmationLevel.HOLD)
        assertEquals(Validation.Valid, DecisionValidator.validate(card(), Decision.ALLOW, tolerated, ctx(at = T.T0.plusSeconds(30))))
    }

    @Test
    fun `authentication from the future is refused`() {
        val future = UserGateResult(AuthMethod.BIOMETRIC, now.plusSeconds(6), ExtraConfirmationLevel.HOLD)
        assertEquals(Validation.Rejected(DecisionBlock.AUTH_BEFORE_REQUEST), DecisionValidator.validate(card(), Decision.ALLOW, future, ctx()))
    }

    @Test
    fun `extra confirmation must be at least as strong as required`() {
        val high = card(RiskLevel.HIGH, ExtraConfirmationLevel.HOLD)
        val none = UserGateResult(AuthMethod.BIOMETRIC, now, ExtraConfirmationLevel.NONE)
        assertEquals(Validation.Rejected(DecisionBlock.EXTRA_CONFIRMATION_REQUIRED), DecisionValidator.validate(high, Decision.ALLOW, none, ctx()))
        val hold = UserGateResult(AuthMethod.BIOMETRIC, now, ExtraConfirmationLevel.HOLD)
        assertEquals(Validation.Valid, DecisionValidator.validate(high, Decision.ALLOW, hold, ctx()))

        val critical = card(RiskLevel.CRITICAL, ExtraConfirmationLevel.HOLD_AND_RECONFIRM)
        assertEquals(Validation.Rejected(DecisionBlock.EXTRA_CONFIRMATION_REQUIRED), DecisionValidator.validate(critical, Decision.ALLOW, hold, ctx()))
        assertEquals(Validation.Valid, DecisionValidator.validate(critical, Decision.ALLOW, fullUser(), ctx()))
    }

    @Test
    fun `low risk allow still needs authentication but no hold`() {
        val low = card(RiskLevel.LOW, ExtraConfirmationLevel.NONE)
        val user = UserGateResult(AuthMethod.BIOMETRIC, now.minusSeconds(1), ExtraConfirmationLevel.NONE)
        assertEquals(Validation.Valid, DecisionValidator.validate(low, Decision.ALLOW, user, ctx()))
        assertEquals(Validation.Rejected(DecisionBlock.AUTH_REQUIRED), DecisionValidator.validate(low, Decision.ALLOW, UserGateResult(), ctx()))
    }

    @Test
    fun `authentication freshness is evaluated on the server timeline`() {
        // Phone 30 s behind the PC (skew +30 s). Phone time T0+10: server T0+40. Auth at phone T0+9 is 1 s old.
        val c = card()
        val user = UserGateResult(AuthMethod.BIOMETRIC, T.T0.plusSeconds(9), ExtraConfirmationLevel.HOLD)
        assertEquals(Validation.Valid, DecisionValidator.validate(c, Decision.ALLOW, user, ctx(at = T.T0.plusSeconds(10), skew = 30_000)))
        assertTrue(Duration.ofSeconds(60) == DecisionValidator.AUTH_MAX_AGE)
    }

    @Test
    fun `validate re-checks availability`() {
        val expired = card(ttl = 5)
        assertEquals(Validation.Rejected(DecisionBlock.EXPIRED), DecisionValidator.validate(expired, Decision.DENY, UserGateResult(), ctx()))
        assertEquals(Validation.Rejected(DecisionBlock.OFFLINE), DecisionValidator.validate(card(), Decision.DENY, UserGateResult(), ctx(link = LinkState.Offline)))
    }
}
