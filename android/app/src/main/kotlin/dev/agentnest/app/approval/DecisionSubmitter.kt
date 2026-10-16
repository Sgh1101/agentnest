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
import dev.agentnest.core.approval.ApprovalDisplay
import dev.agentnest.core.protocol.ApprovalBinding
import dev.agentnest.core.protocol.ApprovalRequest
import dev.agentnest.core.protocol.AuthMethod
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.text.DisplaySanitizer
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

/** How the refusing button of a card is offered (protocol.md 6.1). */
enum class DenyKind {
    /** `deny` is allowed: the plain "거부" button (and "거부하고 멈추기" in the menu when allowed). */
    DENY,

    /** `deny` is absent but `deny_and_stop` is allowed: the refusal IS the stop, labelled "거부 (중단)". */
    DENY_AND_STOP_AS_DENY,

    /** Neither can be offered (e.g. Codex hooks without `deny`): no refusing button. */
    NONE,
}

/** Shared lookups for the UI and the submitter (always computed from the freshest state). */
object ApprovalLogic {
    /** Which refusing button [request] gets. `deny_and_stop` is never offered for Codex hooks cards. */
    fun denyKind(request: ApprovalRequest): DenyKind = when {
        Decision.DENY in request.allowedDecisions -> DenyKind.DENY
        Decision.DENY_AND_STOP in request.allowedDecisions && !request.isCodexHooksOrigin -> DenyKind.DENY_AND_STOP_AS_DENY
        else -> DenyKind.NONE
    }

    /** The validator context for [request] at [now]. Fail-closed: a missing policy never relaxes anything. */
    fun context(state: NestState, request: ApprovalRequest, now: Instant): DecisionContext =
        DecisionContext.from(state, request, now)

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
 *
 * Two guards beyond the validator: (1) only ONE decision flow per request id may run at a time (a second concurrent
 * call is blocked, so two prompts can never open for one card); (2) after the prompt returns, the freshly re-read
 * card must carry the SAME binding (request id, session, nonce, tool input hash) as the card the user authenticated
 * for, otherwise nothing is built.
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
        if (!repository.beginDecision(requestId)) return SubmitOutcome.Blocked(DecisionBlock.IN_FLIGHT)
        try {
            return submitGuarded(requestId, decision, extra, reason)
        } finally {
            repository.endDecision(requestId)
        }
    }

    private suspend fun submitGuarded(
        requestId: String,
        decision: Decision,
        extra: ExtraConfirmationLevel,
        reason: String?,
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
                subtitle = DisplaySanitizer.display(request.title),
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
        // The user authenticated for THIS body; a card that was replaced meanwhile (same id, new nonce / hash) is not it.
        if (ApprovalBinding.of(freshRequest) != ApprovalBinding.of(request)) return SubmitOutcome.Blocked(DecisionBlock.BINDING_CHANGED)
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

    /**
     * The command (first line, at most 80 characters in total) or, when there is none, the first affected path. When
     * the command has more lines the first line is followed by " (+N줄)" (N = further non-blank lines), so the prompt
     * never suggests that the whole command is one line. Never the agent's purpose. Hidden / direction-changing
     * characters are shown as `⟨U+XXXX⟩` escapes, and a second line says how many there are (the prompt must not show
     * something the user cannot see).
     */
    fun description(request: ApprovalRequest): String {
        val source = request.details.command?.takeIf { it.isNotBlank() }
            ?: request.details.filePaths.firstOrNull()
            ?: request.toolName
        val lines = source.lineSequence().map { it.trim() }.filter { it.isNotBlank() }.toList()
        val first = lines.firstOrNull() ?: ""
        val more = lines.size - 1
        val suffix = if (more > 0) moreLines(more) else ""
        val shown = clip(first, MAX_DESCRIPTION_CHARS - suffix.length) + suffix
        val hidden = ApprovalDisplay.hiddenCharCount(request)
        return if (hidden > 0) shown + "\n" + hiddenNote(hidden) else shown
    }

    /** " (+N줄)": how many more lines the command has than the one shown. */
    fun moreLines(count: Int): String = " (+${count}줄)"

    /** "보이지 않는 문자 N개" (also used by the cards). */
    fun hiddenNote(count: Int): String = dev.agentnest.app.ui.S.hiddenChars(count)

    /** Sanitises [line] and cuts it to [limit] characters without splitting an escape. */
    private fun clip(line: String, limit: Int): String {
        val pieces = ArrayList<String>()
        var i = 0
        while (i < line.length) {
            val cp = line.codePointAt(i)
            i += Character.charCount(cp)
            pieces += if (DisplaySanitizer.isHidden(cp)) DisplaySanitizer.escape(cp) else String(Character.toChars(cp))
        }
        if (pieces.sumOf { it.length } <= limit) return pieces.joinToString("")
        val sb = StringBuilder()
        for (piece in pieces) {
            if (sb.length + piece.length > limit - 1) break
            sb.append(piece)
        }
        return sb.append('…').toString()
    }
}
