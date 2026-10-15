package dev.agentnest.core.approval

import dev.agentnest.core.link.ClockSkew
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.nest.ApprovalCard
import dev.agentnest.core.protocol.ApprovalRequest
import dev.agentnest.core.protocol.AuthMethod
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.Policy
import dev.agentnest.core.protocol.RemoteApproval
import dev.agentnest.core.protocol.RiskLevel
import dev.agentnest.core.protocol.SessionState
import dev.agentnest.core.text.Fallbacks
import java.time.Duration
import java.time.Instant

/** Why a decision button is disabled or a decision was refused locally. [messageKo] is the user-facing reason. */
enum class DecisionBlock(val messageKo: String) {
    OFFLINE(Fallbacks.BLOCKED_OFFLINE),
    LOADING("승인 요청을 불러오는 중이에요"),
    EXPIRED("시간이 지나 PC에서 직접 처리하도록 넘겼어요"),
    IN_FLIGHT("PC에 전달 중이에요"),
    UNKNOWN_DECISION("이 요청에는 쓸 수 없는 결정이에요"),
    NOT_ALLOWED("이 요청에는 쓸 수 없는 결정이에요"),
    REMOTE_UNAVAILABLE("이 세션은 휴대폰에서 승인할 수 없어요"),
    REMOTE_PAUSED("PC에서 원격 승인을 잠시 멈춰 두었어요"),
    LOCAL_ONLY("위험한 작업이라 PC에서만 처리할 수 있어요"),
    AUTH_REQUIRED("허용하려면 생체 인증이나 기기 잠금 인증이 필요해요"),
    AUTH_STALE("인증한 지 시간이 지났어요. 다시 인증해 주세요"),
    AUTH_BEFORE_REQUEST("이 요청 전에 한 인증은 쓸 수 없어요. 다시 인증해 주세요"),
    EXTRA_CONFIRMATION_REQUIRED("위험한 작업이라 추가 확인이 필요해요"),
}

/** Whether a decision can currently be started for a card. */
sealed interface Enablement {
    /** The button may be enabled; the user must pass [gate] (hold / re-confirm sheet / authentication) first. */
    data class Enabled(val gate: ApprovalGate) : Enablement
    data class Disabled(val reason: DecisionBlock) : Enablement
}

/**
 * What the user must do before [decision] may be sent (docs/android.md 2.2 / 4.2). [requiresAuth] means a
 * `BiometricPrompt` (`BIOMETRIC_STRONG or DEVICE_CREDENTIAL`); [extraConfirmation] is [ExtraConfirmationLevel.NONE],
 * [ExtraConfirmationLevel.HOLD] (1.5 s long press) or [ExtraConfirmationLevel.HOLD_AND_RECONFIRM] (long press plus
 * the re-confirm sheet).
 */
data class ApprovalGate(
    val decision: Decision,
    val requiresAuth: Boolean,
    val extraConfirmation: ExtraConfirmationLevel,
)

/** What the user actually completed. Times are on the PHONE clock. */
data class UserGateResult(
    val authMethod: AuthMethod = AuthMethod.NONE,
    val authenticatedAt: Instant? = null,
    val extraConfirmation: ExtraConfirmationLevel = ExtraConfirmationLevel.NONE,
)

/** Everything the validator needs besides the card. */
data class DecisionContext(
    val now: Instant,
    val clockSkewMs: Long,
    val link: LinkState,
    val session: SessionState?,
    val policy: Policy,
)

/** Outcome of [DecisionValidator.validate]. */
sealed interface Validation {
    data object Valid : Validation
    data class Rejected(val reason: DecisionBlock) : Validation
}

/**
 * Phone-side checks that must pass before an approve/deny button is enabled and again before a decision is built
 * (docs/android.md 2.2, security.md 6.2). The server repeats all of them; this only avoids sending decisions that
 * are certain to fail and keeps expired cards from ever being actionable.
 *
 * Fail-closed: unknown risk levels count as `high`, unknown extra-confirmation values as the strongest, and the
 * `unknown`/`unavailable`/`paused` remote-approval states all disable the buttons.
 */
object DecisionValidator {
    /** The button is disabled this long before `expires_at` (docs/android.md 2.2: `expires_at - skew - 5s`). */
    val EXPIRY_MARGIN: Duration = Duration.ofSeconds(5)

    /** Authentication must be at most this old when the decision is made (security.md 6.2 step 8). */
    val AUTH_MAX_AGE: Duration = Duration.ofSeconds(60)

    /** Authentication may precede `created_at` / follow `decided_at` by at most this much (clock tolerance). */
    val AUTH_CLOCK_TOLERANCE: Duration = Duration.ofSeconds(5)

    /** True when the card still has [EXPIRY_MARGIN] left on the phone clock. */
    fun hasTimeLeft(request: ApprovalRequest, now: Instant, clockSkewMs: Long): Boolean {
        val phoneDeadline = ClockSkew.toPhone(request.expiresAt.instant, clockSkewMs).minus(EXPIRY_MARGIN)
        return now.isBefore(phoneDeadline)
    }

    /** Seconds left until the server-clock `expires_at` (for the countdown); never negative. */
    fun secondsLeft(request: ApprovalRequest, now: Instant, clockSkewMs: Long): Long {
        val server = ClockSkew.toServer(now, clockSkewMs)
        return Duration.between(server, request.expiresAt.instant).seconds.coerceAtLeast(0)
    }

    /** Whether [decision] may be started for [card] right now, and the gate it needs. */
    fun enablement(card: ApprovalCard, decision: Decision, ctx: DecisionContext): Enablement {
        blockFor(card, decision, ctx)?.let { return Enablement.Disabled(it) }
        return Enablement.Enabled(gate(card.request!!, decision, ctx.policy))
    }

    /** The gate for [decision] on [request]. Pure; does not check time, link or state. */
    fun gate(request: ApprovalRequest, decision: Decision, policy: Policy): ApprovalGate {
        val requiresAuth = decision in authRequiredDecisions(request, policy)
        if (!requiresAuth) return ApprovalGate(decision, requiresAuth = false, extraConfirmation = ExtraConfirmationLevel.NONE)
        val byLevel = when (request.risk.level.effective) {
            RiskLevel.CRITICAL -> ExtraConfirmationLevel.HOLD_AND_RECONFIRM
            RiskLevel.HIGH -> ExtraConfirmationLevel.HOLD
            else -> ExtraConfirmationLevel.NONE
        }
        // Hold / re-confirm guard the allow-type decisions; a plain deny only ever needs authentication (if at all).
        val extra = if (decision == Decision.DENY) ExtraConfirmationLevel.NONE else strongest(byLevel, request.risk.extraConfirmation.effective)
        return ApprovalGate(decision, requiresAuth = true, extraConfirmation = extra)
    }

    /**
     * Final validation of a decision with the user's completed gates. Returns [Validation.Valid] only when every
     * check passes: availability checks of [enablement] plus authentication freshness and extra confirmation.
     */
    fun validate(card: ApprovalCard, decision: Decision, user: UserGateResult, ctx: DecisionContext): Validation {
        blockFor(card, decision, ctx)?.let { return Validation.Rejected(it) }
        val request = card.request!!
        val gate = gate(request, decision, ctx.policy)
        if (gate.requiresAuth) {
            authBlock(request, user, ctx)?.let { return Validation.Rejected(it) }
            if (strength(user.extraConfirmation) < strength(gate.extraConfirmation)) {
                return Validation.Rejected(DecisionBlock.EXTRA_CONFIRMATION_REQUIRED)
            }
        }
        return Validation.Valid
    }

    // ---------------------------------------------------------------------------------------------

    private fun blockFor(card: ApprovalCard, decision: Decision, ctx: DecisionContext): DecisionBlock? {
        if (ctx.link !is LinkState.Connected) return DecisionBlock.OFFLINE
        val request = card.request ?: return DecisionBlock.LOADING
        if (decision == Decision.UNKNOWN) return DecisionBlock.UNKNOWN_DECISION
        if (!hasTimeLeft(request, ctx.now, ctx.clockSkewMs)) return DecisionBlock.EXPIRED
        if (card.inFlight != null) return DecisionBlock.IN_FLIGHT
        ctx.session?.let { session ->
            when (session.remoteApproval) {
                RemoteApproval.AVAILABLE -> Unit
                RemoteApproval.PAUSED -> return DecisionBlock.REMOTE_PAUSED
                RemoteApproval.UNAVAILABLE, RemoteApproval.UNKNOWN -> return DecisionBlock.REMOTE_UNAVAILABLE
            }
        }
        if (decision !in request.allowedDecisions) return DecisionBlock.NOT_ALLOWED
        // Codex hooks cannot stop a turn; the PC never lists deny_and_stop there, and the phone double-checks.
        if (decision == Decision.DENY_AND_STOP && request.isCodexHooksOrigin) return DecisionBlock.NOT_ALLOWED
        val criticalLocalOnly = ctx.policy.remoteApproval["critical"] == "local_only" &&
            request.risk.level.effective == RiskLevel.CRITICAL
        if (criticalLocalOnly && decision != Decision.DENY) return DecisionBlock.LOCAL_ONLY
        return null
    }

    /** Decisions that need authentication: the request's `auth_required_for` plus `deny` when the PC policy says so. */
    private fun authRequiredDecisions(request: ApprovalRequest, policy: Policy): Set<Decision> {
        val required = request.authRequiredFor.toMutableSet()
        // Allow-type decisions ALWAYS need authentication, whatever the card claims (fail-closed).
        required += Decision.ALLOW
        required += Decision.DENY_AND_STOP
        if (policy.denyRequiresAuth) required += Decision.DENY
        return required
    }

    private fun authBlock(request: ApprovalRequest, user: UserGateResult, ctx: DecisionContext): DecisionBlock? {
        val method = user.authMethod
        val authenticatedAt = user.authenticatedAt
        if ((method != AuthMethod.BIOMETRIC && method != AuthMethod.DEVICE_CREDENTIAL) || authenticatedAt == null) {
            return DecisionBlock.AUTH_REQUIRED
        }
        // Compare on the server timeline like the PC does (security.md 6.2 step 8).
        val authServer = ClockSkew.toServer(authenticatedAt, ctx.clockSkewMs)
        val decidedServer = ClockSkew.toServer(ctx.now, ctx.clockSkewMs)
        if (authServer.isBefore(request.createdAt.instant.minus(AUTH_CLOCK_TOLERANCE))) return DecisionBlock.AUTH_BEFORE_REQUEST
        if (authServer.isAfter(decidedServer.plus(AUTH_CLOCK_TOLERANCE))) return DecisionBlock.AUTH_BEFORE_REQUEST
        if (Duration.between(authServer, decidedServer) > AUTH_MAX_AGE) return DecisionBlock.AUTH_STALE
        return null
    }

    private fun strength(level: ExtraConfirmationLevel): Int = when (level.effective) {
        ExtraConfirmationLevel.NONE -> 0
        ExtraConfirmationLevel.HOLD -> 1
        else -> 2
    }

    private fun strongest(a: ExtraConfirmationLevel, b: ExtraConfirmationLevel) = if (strength(a) >= strength(b)) a.effective else b.effective
}
