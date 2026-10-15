package dev.agentnest.core.approval

import dev.agentnest.core.link.ClockSkew
import dev.agentnest.core.nest.ApprovalCard
import dev.agentnest.core.protocol.ApprovalSeenMessage
import dev.agentnest.core.protocol.ApprovalSeenPayload
import dev.agentnest.core.protocol.AuthClaim
import dev.agentnest.core.protocol.AuthMethod
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.DecisionMessage
import dev.agentnest.core.protocol.DecisionPayload
import dev.agentnest.core.protocol.ExtraConfirmationClaim
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.FrameMeta
import dev.agentnest.core.protocol.Ts
import dev.agentnest.core.util.Uuid7Generator
import java.text.Normalizer
import java.time.Instant

/** Result of [DecisionBuilder.build]. */
sealed interface BuildResult {
    /** A message ready to send. Pass [DecisionMessage.meta] id to `NestReducer.markDecisionSent`. */
    data class Built(val message: DecisionMessage) : BuildResult
    data class Refused(val reason: DecisionBlock) : BuildResult
}

/**
 * Builds `decision` messages (docs/android.md 1.3). It runs [DecisionValidator.validate] first and refuses to
 * build anything that would be certain to fail; the four binding fields are echoed verbatim from the card, the
 * phone never computes the hash. There is no way to express a scope-expanding decision.
 */
class DecisionBuilder(private val ids: () -> String = Uuid7Generator()::next) {

    /**
     * Builds a decision for [card] or explains why not. [user] holds what the user completed (phone clock);
     * `decided_at` and `authenticated_at` are converted to the server timeline with [DecisionContext.clockSkewMs].
     * [reason] is an optional free-text deny reason; the PC sanitises it again before it reaches the agent.
     */
    fun build(
        card: ApprovalCard,
        decision: Decision,
        user: UserGateResult,
        ctx: DecisionContext,
        reason: String? = null,
    ): BuildResult {
        when (val validation = DecisionValidator.validate(card, decision, user, ctx)) {
            Validation.Valid -> Unit
            is Validation.Rejected -> return BuildResult.Refused(validation.reason)
        }
        val request = card.request!!
        val decidedAt = ClockSkew.toServer(ctx.now, ctx.clockSkewMs)
        val auth = AuthClaim(
            method = if (user.authMethod == AuthMethod.UNKNOWN) AuthMethod.NONE else user.authMethod,
            authenticatedAt = user.authenticatedAt?.let { Ts.of(ClockSkew.toServer(it, ctx.clockSkewMs)) },
        )
        val extra = user.extraConfirmation.takeIf { it != ExtraConfirmationLevel.NONE && it != ExtraConfirmationLevel.UNKNOWN }
            ?.let { ExtraConfirmationClaim(method = it, completed = true) }
        val payload = DecisionPayload(
            requestId = request.requestId,
            sessionKey = request.sessionKey,
            nonceB64 = request.nonceB64,
            toolInputSha256 = request.toolInputSha256,
            decision = decision,
            reason = sanitizeReason(reason),
            decidedAt = Ts.of(decidedAt),
            auth = auth,
            extraConfirmation = extra,
        )
        return BuildResult.Built(DecisionMessage(FrameMeta(ids(), Ts.of(ctx.now)), payload))
    }

    /** Builds the UI-only `approval_seen` message (the card was shown on screen). */
    fun seen(requestId: String, now: Instant): ApprovalSeenMessage =
        ApprovalSeenMessage(FrameMeta(ids(), Ts.of(now)), ApprovalSeenPayload(requestId, Ts.of(now)))

    companion object {
        /** Maximum number of characters of a deny reason. */
        const val MAX_REASON_CHARS = 200

        /**
         * Light phone-side clean-up of a deny reason: NFC, control and bidi-control characters removed (line
         * breaks become spaces), trimmed, cut to 200 characters. Null when nothing is left.
         */
        fun sanitizeReason(text: String?): String? {
            if (text == null) return null
            val normalized = Normalizer.normalize(text, Normalizer.Form.NFC)
            val sb = StringBuilder()
            var i = 0
            while (i < normalized.length) {
                val cp = normalized.codePointAt(i)
                i += Character.charCount(cp)
                when {
                    cp == '\n'.code || cp == '\r'.code || cp == 0x2028 || cp == 0x2029 -> sb.append(' ')
                    cp < 0x20 || cp in 0x7F..0x9F || cp in 0x202A..0x202E || cp in 0x2066..0x2069 -> Unit
                    else -> sb.appendCodePoint(cp)
                }
            }
            val trimmed = sb.toString().trim()
            if (trimmed.isEmpty()) return null
            val cut = if (trimmed.codePointCount(0, trimmed.length) > MAX_REASON_CHARS) {
                trimmed.substring(0, trimmed.offsetByCodePoints(0, MAX_REASON_CHARS))
            } else {
                trimmed
            }
            return cut
        }
    }
}
