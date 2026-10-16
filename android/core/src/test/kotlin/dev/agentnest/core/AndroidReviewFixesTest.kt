package dev.agentnest.core

import dev.agentnest.core.approval.ApprovalDisplay
import dev.agentnest.core.approval.DecisionBlock
import dev.agentnest.core.approval.DecisionContext
import dev.agentnest.core.approval.DecisionValidator
import dev.agentnest.core.approval.Enablement
import dev.agentnest.core.nest.ApprovalCard
import dev.agentnest.core.nest.NestReducer
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.Codec
import dev.agentnest.core.protocol.DecisionResultReason
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.DecisionMessage
import dev.agentnest.core.protocol.DecisionPayload
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.HelloMessage
import dev.agentnest.core.protocol.HelloPayload
import dev.agentnest.core.protocol.Policy
import dev.agentnest.core.protocol.Project
import dev.agentnest.core.protocol.RiskInfo
import dev.agentnest.core.protocol.RiskLevel
import dev.agentnest.core.protocol.SessionMeta
import dev.agentnest.core.protocol.Ts
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Regression tests for the Android review fixes (hidden characters, late results, strict defaults, model parity). */
class AndroidReviewFixesTest {
    private companion object {
        const val RID = "ar_01929f1a-6c2e-7b3c-9e4d-00000000001a"
    }

    private val now = T.T0.plusSeconds(10)
    private val hidden = "‮"

    // ---- hidden characters anywhere the user reads -------------------------------------------------------------

    private fun lowRequest() = T.request(level = RiskLevel.LOW, extra = ExtraConfirmationLevel.NONE, command = "echo hi")

    private fun assertRaisesHold(label: String, tricky: dev.agentnest.core.protocol.ApprovalRequest) {
        assertTrue(ApprovalDisplay.hiddenCharCount(tricky) > 0, "$label must be counted")
        assertEquals(ExtraConfirmationLevel.HOLD, DecisionValidator.gate(tricky, Decision.ALLOW, Policy()).extraConfirmation, label)
        assertEquals(ExtraConfirmationLevel.HOLD, DecisionValidator.gate(tricky, Decision.DENY_AND_STOP, Policy()).extraConfirmation, label)
        assertEquals(ExtraConfirmationLevel.NONE, DecisionValidator.gate(tricky, Decision.DENY, Policy()).extraConfirmation, label)
    }

    @Test
    fun `a clean request has no hidden characters`() {
        assertEquals(0, ApprovalDisplay.hiddenCharCount(lowRequest()))
    }

    @Test
    fun `hidden characters in risk reasons raise the gate`() {
        val base = lowRequest()
        assertRaisesHold("reasons_ko", base.copy(risk = RiskInfo(RiskLevel.LOW, emptyList(), listOf("안전해요${hidden}"), ExtraConfirmationLevel.NONE)))
    }

    @Test
    fun `hidden characters in the agent label raise the gate`() {
        assertRaisesHold("agent_label", lowRequest().copy(agentLabel = "Claude${hidden} Code"))
    }

    @Test
    fun `hidden characters in cwd file paths project name and path hint raise the gate`() {
        val base = lowRequest()
        assertRaisesHold("cwd", base.copy(details = base.details.copy(cwdHint = "C:\\work${hidden}")))
        assertRaisesHold("file path", base.copy(details = base.details.copy(filePaths = listOf("a.txt", "b${hidden}.sh"))))
        assertRaisesHold("project name", base.copy(project = Project("p", "agent${hidden}nest")))
        assertRaisesHold("project path hint", base.copy(project = Project("p", "agentnest", pathHint = "C:\\x${hidden}")))
        assertRaisesHold("branch", base.copy(project = Project("p", "agentnest", branch = "main${hidden}")))
    }

    // ---- late decision_result of an earlier decision --------------------------------------------------------------

    private val reducer = NestReducer(ids = { T.id() })

    private fun stateWithInFlight(): dev.agentnest.core.nest.NestState {
        val req = T.request(id = RID)
        var s = reducer.reduce(reducer.initial(T.T0), T.welcome(), T.T0).state
        s = reducer.reduce(s, T.snapshot(10, listOf(T.session("claude_code:s1", AgentState.AWAITING_APPROVAL, pending = listOf(RID))), listOf(req)), T.T0).state
        return reducer.markDecisionSent(s, RID, "msg-new", Decision.ALLOW, now)
    }

    @Test
    fun `a late rejection of an earlier decision does not clear the decision in flight`() {
        var s = stateWithInFlight()
        val late = T.decisionResult(RID, false, DecisionResultReason.AUTH_REQUIRED, inReplyTo = "msg-old")
        s = reducer.reduce(s, late, now).state
        val card = s.approvals.getValue(RID)
        assertEquals("msg-new", card.inFlight?.messageId, "the new decision stays in flight")
        assertNull(card.lastResult)
        assertNull(s.lastDecisionResult, "a stale answer must not drive a toast either")
    }

    @Test
    fun `a rejection without in_reply_to cannot unblock a decision in flight`() {
        var s = stateWithInFlight()
        s = reducer.reduce(s, T.decisionResult(RID, false, DecisionResultReason.AUTH_REQUIRED, inReplyTo = null), now).state
        assertNotNull(s.approvals.getValue(RID).inFlight)
    }

    @Test
    fun `the matching rejection still clears the decision in flight`() {
        var s = stateWithInFlight()
        s = reducer.reduce(s, T.decisionResult(RID, false, DecisionResultReason.AUTH_REQUIRED, inReplyTo = "msg-new"), now).state
        assertNull(s.approvals.getValue(RID).inFlight)
        assertEquals(DecisionResultReason.AUTH_REQUIRED, s.approvals.getValue(RID).lastResult?.reason)
    }

    @Test
    fun `an expired answer closes the card even when it answers an earlier decision`() {
        var s = stateWithInFlight()
        s = reducer.reduce(s, T.decisionResult(RID, false, DecisionResultReason.EXPIRED, inReplyTo = "msg-old"), now).state
        assertFalse(s.approvals.containsKey(RID))
    }

    // ---- strict defaults before the policy is known ---------------------------------------------------------------

    @Test
    fun `without a welcome the context uses the strictest policy`() {
        val req = T.request(id = RID, level = RiskLevel.CRITICAL, extra = ExtraConfirmationLevel.HOLD_AND_RECONFIRM)
        val session = T.session("claude_code:s1", AgentState.AWAITING_APPROVAL, pending = listOf(RID))
        val bare = reducer.initial(T.T0).copy(sessions = mapOf(session.sessionKey to session), approvals = mapOf(RID to ApprovalCard(RID, req, T.T0)))
        assertNull(bare.welcome)
        val ctx = DecisionContext.from(bare, req, now).copy(link = T.connected(), awaitingSnapshot = false)
        assertEquals(DecisionContext.STRICT_POLICY, ctx.policy)
        assertEquals(DecisionBlock.LOCAL_ONLY, assertIs<Enablement.Disabled>(DecisionValidator.enablement(bare.approvals.getValue(RID), Decision.ALLOW, ctx)).reason)
        val denyGate = (DecisionValidator.enablement(bare.approvals.getValue(RID), Decision.DENY, ctx) as Enablement.Enabled).gate
        assertTrue(denyGate.requiresAuth, "deny needs authentication until the PC policy says otherwise")
    }

    @Test
    fun `after a welcome the PC policy applies and normal flows are unchanged`() {
        val req = T.request(id = RID, level = RiskLevel.HIGH)
        val session = T.session("claude_code:s1", AgentState.AWAITING_APPROVAL, pending = listOf(RID))
        var s = reducer.reduce(reducer.initial(T.T0), T.welcome(policy = Policy()), T.T0).state
        s = s.copy(sessions = mapOf(session.sessionKey to session), approvals = mapOf(RID to ApprovalCard(RID, req, T.T0)))
        val ctx = DecisionContext.from(s, req, now).copy(link = T.connected(), awaitingSnapshot = false)
        assertEquals(Policy(), ctx.policy)
        assertIs<Enablement.Enabled>(DecisionValidator.enablement(s.approvals.getValue(RID), Decision.ALLOW, ctx))
        assertFalse((DecisionValidator.enablement(s.approvals.getValue(RID), Decision.DENY, ctx) as Enablement.Enabled).gate.requiresAuth)
    }

    @Test
    fun `an unknown session is never approvable remotely`() {
        val req = T.request(id = RID)
        val card = ApprovalCard(RID, req, T.T0)
        val ctx = DecisionContext(now, 0, T.connected(), null, Policy(), awaitingSnapshot = false)
        for (d in listOf(Decision.ALLOW, Decision.DENY, Decision.DENY_AND_STOP)) {
            assertEquals(DecisionBlock.REMOTE_UNAVAILABLE, assertIs<Enablement.Disabled>(DecisionValidator.enablement(card, d, ctx)).reason, d.name)
        }
    }

    // ---- model parity with the Rust types / JSON schema -----------------------------------------------------------

    @Test
    fun `session meta carries pr fields and an integer context percentage`() {
        val json = """{"title":"t","cost_usd":1.5,"context_used_pct":41,"pr_number":42,"pr_url":"https://github.com/owner/agentnest/pull/42","future":1}"""
        val meta = Codec.json.decodeFromString(SessionMeta.serializer(), json)
        assertEquals(41, meta.contextUsedPct)
        assertEquals(42L, meta.prNumber)
        assertEquals("https://github.com/owner/agentnest/pull/42", meta.prUrl)
        val again = Codec.json.parseToJsonElement(Codec.json.encodeToString(SessionMeta.serializer(), meta)).jsonObject
        assertEquals("41", again.getValue("context_used_pct").jsonPrimitive.content)
        assertEquals("42", again.getValue("pr_number").jsonPrimitive.content)
        // optional fields stay absent when unset (explicit_nulls = false)
        val empty = Codec.json.parseToJsonElement(Codec.json.encodeToString(SessionMeta.serializer(), SessionMeta())).jsonObject
        assertFalse("pr_number" in empty)
    }

    @Test
    fun `hello and decision accept the optional phase 3 signature and omit it by default`() {
        val hello = HelloMessage(T.meta(), HelloPayload("dev_1", "tok", "cXk4Z1l0d2VyN3U4aW9wMQ==", 1, null, 0, false))
        assertFalse("signature_b64" in Codec.json.parseToJsonElement(Codec.encodeAny(hello)).jsonObject["payload"]!!.jsonObject)
        val signed = Codec.json.decodeFromString(HelloPayload.serializer(), """{"device_id":"d","device_token":"t","challenge_b64":"c","protocol":1,"last_seq":0,"signature_b64":"AAAA"}""")
        assertEquals("AAAA", signed.signatureB64)
        val decision = Codec.json.decodeFromString(
            DecisionPayload.serializer(),
            """{"request_id":"ar_x","session_key":"k","nonce_b64":"n","tool_input_sha256":"h","decision":"deny","decided_at":"2026-10-15T09:12:33.120Z","signature_b64":"AAAA"}""",
        )
        assertEquals("AAAA", decision.signatureB64)
        val plain = DecisionMessage(T.meta(), decision.copy(signatureB64 = null, decidedAt = Ts.of(Instant.parse("2026-10-15T09:12:33.120Z"))))
        assertTrue(plain.payload.signatureB64 == null)
    }
}
