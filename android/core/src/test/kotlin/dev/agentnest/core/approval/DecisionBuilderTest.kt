package dev.agentnest.core.approval

import dev.agentnest.core.T
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.nest.ApprovalCard
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.AuthMethod
import dev.agentnest.core.protocol.Codec
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.DecodeResult
import dev.agentnest.core.protocol.DecisionMessage
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.Policy
import dev.agentnest.core.protocol.RemoteApproval
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DecisionBuilderTest {
    private val builder = DecisionBuilder { T.id() }
    private val now = T.T0.plusSeconds(10)
    private val requestId = "ar_01929f1a-6c2e-7b3c-9e4d-00000000001a"
    private val card = ApprovalCard(requestId, T.request(id = requestId), T.T0)

    private fun ctx(skew: Long = 0, at: Instant = now) = DecisionContext(
        at, skew, T.connected(), T.session("claude_code:s1", AgentState.AWAITING_APPROVAL, remote = RemoteApproval.AVAILABLE), Policy(),
    )

    private val user get() = UserGateResult(AuthMethod.BIOMETRIC, now.minusSeconds(2), ExtraConfirmationLevel.HOLD)

    @Test
    fun `builds a decision that echoes all four binding fields verbatim`() {
        val built = assertIs<BuildResult.Built>(builder.build(card, Decision.ALLOW, user, ctx()))
        val p = built.message.payload
        val req = card.request!!
        assertEquals(req.requestId, p.requestId)
        assertEquals(req.sessionKey, p.sessionKey)
        assertEquals(req.nonceB64, p.nonceB64)
        assertEquals(req.toolInputSha256, p.toolInputSha256)
        assertEquals(Decision.ALLOW, p.decision)
        assertEquals(AuthMethod.BIOMETRIC, p.auth!!.method)
        assertEquals(ExtraConfirmationLevel.HOLD, p.extraConfirmation!!.method)
        assertTrue(p.extraConfirmation.completed)
    }

    @Test
    fun `the encoded frame is valid wire JSON and decodes back`() {
        val built = assertIs<BuildResult.Built>(builder.build(card, Decision.ALLOW, user, ctx()))
        val text = Codec.encode(built.message)
        val result = Codec.decode(text)
        val decoded = assertIs<DecodeResult.Decoded>(result, "$result")
        assertEquals(built.message, decoded.message)
        assertTrue(text.contains("\"decision\":\"allow\""))
        assertFalse(text.contains("allow_for_session"))
    }

    @Test
    fun `decided_at and authenticated_at are converted to the server timeline`() {
        val built = assertIs<BuildResult.Built>(builder.build(card, Decision.ALLOW, user, ctx(skew = 4_000)))
        assertEquals(now.plusSeconds(4), built.message.payload.decidedAt.instant)
        assertEquals(now.minusSeconds(2).plusSeconds(4), built.message.payload.auth!!.authenticatedAt!!.instant)
    }

    @Test
    fun `refuses what the validator refuses`() {
        val noAuth = builder.build(card, Decision.ALLOW, UserGateResult(), ctx())
        assertEquals(BuildResult.Refused(DecisionBlock.AUTH_REQUIRED), noAuth)
        val offline = builder.build(card, Decision.DENY, UserGateResult(), ctx().copy(link = LinkState.Offline))
        assertEquals(BuildResult.Refused(DecisionBlock.OFFLINE), offline)
        val expired = builder.build(card, Decision.DENY, UserGateResult(), ctx(at = T.T0.plusSeconds(500)))
        assertEquals(BuildResult.Refused(DecisionBlock.EXPIRED), expired)
    }

    @Test
    fun `an unknown decision can never be built or encoded`() {
        assertEquals(BuildResult.Refused(DecisionBlock.UNKNOWN_DECISION), builder.build(card, Decision.UNKNOWN, user, ctx()))
        val frame = DecisionMessage(T.meta(), dev.agentnest.core.protocol.DecisionPayload(
            "ar_1", "k", "n", "h", Decision.UNKNOWN, null, T.ts(now), null, null,
        ))
        assertFailsWith<kotlinx.serialization.SerializationException> { Codec.encode(frame) }
    }

    @Test
    fun `deny without authentication is built with auth none and no extra confirmation`() {
        val built = assertIs<BuildResult.Built>(builder.build(card, Decision.DENY, UserGateResult(), ctx(), reason = "no thanks"))
        assertEquals(AuthMethod.NONE, built.message.payload.auth!!.method)
        assertNull(built.message.payload.extraConfirmation)
        assertEquals("no thanks", built.message.payload.reason)
    }

    @Test
    fun `reason is sanitised and bounded`() {
        assertNull(DecisionBuilder.sanitizeReason(null))
        assertNull(DecisionBuilder.sanitizeReason("  \u0000\u0085\n"))
        assertEquals("a b", DecisionBuilder.sanitizeReason("a\nb"))
        assertEquals("ab", DecisionBuilder.sanitizeReason("a‮b"), "bidi controls are removed")
        assertEquals("ab", DecisionBuilder.sanitizeReason("a\u0007b"), "control chars are removed")
        val long = "가".repeat(300)
        assertEquals(200, DecisionBuilder.sanitizeReason(long)!!.length)
        val emoji = "😀".repeat(250)
        assertEquals(200, DecisionBuilder.sanitizeReason(emoji)!!.codePointCount(0, DecisionBuilder.sanitizeReason(emoji)!!.length))
    }

    @Test
    fun `approval_seen message`() {
        val msg = builder.seen("ar_1", now)
        assertEquals("ar_1", msg.payload.requestId)
        assertIs<DecodeResult.Decoded>(Codec.decode(Codec.encode(msg)))
    }

    @Test
    fun `decision payload toString hides nothing secret but also never prints the nonce`() {
        val built = assertIs<BuildResult.Built>(builder.build(card, Decision.ALLOW, user, ctx()))
        assertFalse(built.message.payload.toString().contains(card.request!!.nonceB64))
    }
}
