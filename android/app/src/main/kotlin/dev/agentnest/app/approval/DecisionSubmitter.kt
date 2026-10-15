package dev.agentnest.app.approval

import dev.agentnest.app.data.NestRepository
import dev.agentnest.core.approval.ApprovalGate
import dev.agentnest.core.approval.BuildResult
import dev.agentnest.core.approval.DecisionBlock
import dev.agentnest.core.approval.DecisionBuilder
import dev.agentnest.core.approval.DecisionContext
import dev.agentnest.core.approval.DecisionValidator
import dev.agentnest.core.approval.Enablement
import dev.agentnest.core.approval.UserGateResult
import dev.agentnest.core.nest.ApprovalCard
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.protocol.ApprovalRequest
import dev.agentnest.core.protocol.AuthMethod
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.Policy
import java.time.Instant

/** Whether the device can authenticate the user at all (a screen lock or a biometric must be enrolled). */
enum class AuthAvailability { READY, NOT_ENROLLED, UNAVAILABLE }

/** Text shown by the system authentication prompt. [description] never contains agent-written purpose text. */
data class AuthRequest(val title: String, val subtitle: String, val description: String)

/** Result of one authentication prompt. */
sealed interface AuthOutcome {
    /** [at] is the PHONE clock time of the successful authentication. */
    data class Success(val method: AuthMethod, val at: Instant) : AuthOutcome
    data object Cancelled : AuthOutcome
    data class Failed(val messageKo: String) : AuthOutcome
}

/** Abstraction over BiometricPrompt so the decision flow is testable on the JVM. */
interface UserAuthenticator {
    /** Cheap pre-check used to disable the approve button before the user tries. */
    fun availability(): AuthAvailability

    /** Shows the system prompt (BIOMETRIC_STRONG or DEVICE_CREDENTIAL, no negative button). Main thread only. */
    suspend fun authenticate(request: AuthRequest): AuthOutcome
}

/** What happened to a decision the user asked for. Only [Sent] means a message left the phone. */
sealed interface SubmitOutcome {
    data object Sent : SubmitOutcome
    data class Blocked(val reason: DecisionBlock) : SubmitOutcome
    data class AuthFailed(val messageKo: String) : SubmitOutcome
    data object AuthCancelled : SubmitOutcome
    data object NotSent : SubmitOutcome
}

/** Shared lookups for the UI and the submitter (always computed from the freshest state). */
object ApprovalLogic {
    /** The validator context for [request] at [now]. Fail-closed: a missing policy never relaxes anything. */
    fun context(state: NestState, request: ApprovalRequest, now: Instant): DecisionContext = DecisionContext(
        now = now,
        clockSkewMs = state.clockSkewMs,
        link = state.link,
        session = state.sessions[request.sessionKey],
        policy = state.welcome?.policy ?: Policy(),
    )

    /** Whether [decision] may be started for [card] now, and the gate to pass. */
    fun enablement(state: NestState, card: ApprovalCard, decision: Decision, now: Instant): Enablement {
        val request = card.request ?: return Enablement.Disabled(DecisionBlock.LOADING)
        return DecisionValidator.enablement(card, decision, context(state, request, now))
    }
}

/**
 * The only place where a decision message is created. Order (docs/android.md 2.2 / 4.2): re-check enablement on the
 * freshest state -> authentication when the gate needs it -> re-validate and build with `DecisionBuilder` -> send via
 * the repository (which refuses while not connected and never queues). There is no code path that builds a decision
 * without a user action.
 */
class DecisionSubmitter(
    private val repository: NestRepository,
    private val authenticator: UserAuthenticator,
    private val builder: DecisionBuilder = DecisionBuilder(),
    private val clock: () -> Instant = { Instant.now() },
) {
    /**
     * [extra] is what the user already completed in the UI (hold / re-confirm dialog); pass
     * [ExtraConfirmationLevel.NONE] when nothing was required. [reason] is an optional deny reason.
     */
    suspend fun submit(
        requestId: String,
        decision: Decision,
        extra: ExtraConfirmationLevel,
        reason: String? = null,
    ): SubmitOutcome {
        val first = repository.nest.value
        val card = first.approvals[requestId] ?: return SubmitOutcome.Blocked(DecisionBlock.EXPIRED)
        val request = card.request ?: return SubmitOutcome.Blocked(DecisionBlock.LOADING)
        val gate: ApprovalGate = when (val e = ApprovalLogic.enablement(first, card, decision, clock())) {
            is Enablement.Disabled -> return SubmitOutcome.Blocked(e.reason)
            is Enablement.Enabled -> e.gate
        }

        var authMethod = AuthMethod.NONE
        var authAt: Instant? = null
        if (gate.requiresAuth) {
            val prompt = AuthRequest(
                title = AUTH_TITLE,
                subtitle = request.title,
                description = AuthText.description(request),
            )
            when (val outcome = authenticator.authenticate(prompt)) {
                is AuthOutcome.Success -> {
                    authMethod = outcome.method
                    authAt = outcome.at
                }
                AuthOutcome.Cancelled -> return SubmitOutcome.AuthCancelled
                is AuthOutcome.Failed -> return SubmitOutcome.AuthFailed(outcome.messageKo)
            }
        }

        // The prompt can take a while: re-read the card (it may have expired or been resolved meanwhile).
        val state = repository.nest.value
        val freshCard = state.approvals[requestId] ?: return SubmitOutcome.Blocked(DecisionBlock.EXPIRED)
        val freshRequest = freshCard.request ?: return SubmitOutcome.Blocked(DecisionBlock.LOADING)
        val now = clock()
        val user = UserGateResult(
            authMethod = authMethod,
            authenticatedAt = authAt,
            extraConfirmation = if (gate.requiresAuth) extra else ExtraConfirmationLevel.NONE,
        )
        return when (val built = builder.build(freshCard, decision, user, ApprovalLogic.context(state, freshRequest, now), reason)) {
            is BuildResult.Refused -> SubmitOutcome.Blocked(built.reason)
            is BuildResult.Built -> if (repository.submitDecision(built.message)) SubmitOutcome.Sent else SubmitOutcome.NotSent
        }
    }

    private companion object {
        const val AUTH_TITLE = "승인 확인"
    }
}

/** Text for the authentication prompt. */
object AuthText {
    private const val MAX_DESCRIPTION_CHARS = 80

    /** The command (first line, 80 characters) or, when there is none, the first affected path. Never the agent's purpose. */
    fun description(request: ApprovalRequest): String {
        val source = request.details.command?.takeIf { it.isNotBlank() }
            ?: request.details.filePaths.firstOrNull()
            ?: request.toolName
        val oneLine = source.lineSequence().firstOrNull { it.isNotBlank() }?.trim() ?: ""
        return if (oneLine.length > MAX_DESCRIPTION_CHARS) oneLine.take(MAX_DESCRIPTION_CHARS - 1) + "…" else oneLine
    }
}
