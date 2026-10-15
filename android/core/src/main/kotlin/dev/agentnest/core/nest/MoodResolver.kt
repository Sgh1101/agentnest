package dev.agentnest.core.nest

import dev.agentnest.core.link.ClockSkew
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.SessionState
import dev.agentnest.core.text.Fallbacks
import java.time.Duration
import java.time.Instant

/** The character's state shown on the home screen, the foreground notification and (later) widgets. */
data class MoodDecision(
    val mood: KongiMood,
    val typingVariant: TypingVariant?,
    val badge: Badge,
    val badgeCount: Int,
    val primarySessionKey: String?,
    val headline: String,
    /** Phone time at which [mood] (with its variant) last changed; drives the minimum hold time. */
    val since: Instant,
    internal val rank: Int,
) {
    /** True when this decision shows the same face as [other] (mood and typing variant). */
    fun sameFace(other: MoodDecision): Boolean = mood == other.mood && typingVariant == other.typingVariant
}

/** Inputs of [MoodResolver]. */
data class MoodInput(
    val link: LinkState,
    val sessions: Collection<SessionState>,
    /** `serverTime - phoneTime` in milliseconds, used to age `state_since` of completed sessions. */
    val clockSkewMs: Long = 0,
)

/**
 * Mood priority and hysteresis (docs/character.md section 2). A pure function of the inputs, the previous decision
 * and an explicit `now`, so tests drive it with a virtual clock.
 *
 * Priority: link > awaiting_approval > awaiting_input > error > testing > writing_code > reviewing > working >
 * completed (4 s) > idle > all disconnected. Hysteresis: a mood is held at least 1.5 s; link, approval, input and
 * error moods take over immediately when they outrank the current one; leaving a link problem or a celebration is
 * immediate too. `flustered` follows `AgentState.error` and has no phone-side timer.
 */
object MoodResolver {
    /** Minimum time a mood stays on screen (ms). */
    val MIN_HOLD: Duration = Duration.ofMillis(1500)

    /** How long `celebrate` lasts after a session completes. */
    val CELEBRATE_DURATION: Duration = Duration.ofMillis(4000)

    private const val RANK_LINK = 1
    private const val RANK_APPROVAL = 2
    private const val RANK_INPUT = 3
    private const val RANK_ERROR = 4
    private const val RANK_TESTING = 5
    private const val RANK_WRITING = 6
    private const val RANK_REVIEWING = 7
    private const val RANK_WORKING = 8
    private const val RANK_COMPLETED = 9
    private const val RANK_IDLE = 10
    private const val RANK_DISCONNECTED = 11
    private const val MAX_IMMEDIATE_RANK = RANK_ERROR

    /** Computes the decision for [input] at [now], applying hysteresis against [previous]. */
    fun resolve(input: MoodInput, previous: MoodDecision?, now: Instant): MoodDecision {
        val candidate = candidate(input, previous, now)
        if (previous == null) return candidate
        if (candidate.sameFace(previous)) {
            // Same face: refresh badge/headline/primary but keep the original change time.
            return candidate.copy(since = previous.since)
        }
        val held = Duration.between(previous.since, now)
        val immediate = candidate.rank == RANK_LINK ||
            (candidate.rank < previous.rank && candidate.rank <= MAX_IMMEDIATE_RANK) ||
            (previous.rank == RANK_LINK && candidate.rank != RANK_LINK) ||
            (previous.mood == KongiMood.CELEBRATE && candidate.rank < RANK_COMPLETED)
        return if (immediate || held >= MIN_HOLD) candidate.copy(since = now) else previous
    }

    private fun candidate(input: MoodInput, previous: MoodDecision?, now: Instant): MoodDecision {
        linkCandidate(input.link, now)?.let { return it }
        val active = input.sessions.filter { !it.ended }
        if (active.isEmpty()) return decision(KongiMood.BLINK_SLOW, null, Badge.NONE, 0, null, Fallbacks.NO_SESSIONS, now, RANK_IDLE)
        if (active.all { it.state == AgentState.DISCONNECTED }) {
            val primary = FocusSelector.pick(active)
            return decision(KongiMood.WORRIED, null, Badge.NONE, 0, primary?.sessionKey, Fallbacks.SESSION_LOST, now, RANK_DISCONNECTED)
        }
        val serverNow = ClockSkew.toServer(now, input.clockSkewMs)
        val celebrateOver = previous != null && previous.mood == KongiMood.CELEBRATE &&
            Duration.between(previous.since, now) >= CELEBRATE_DURATION
        // Focus uses the raw state order (shared with Rust `state::focus`); only the mood of a completed session ages.
        val primary = FocusSelector.pick(active) ?: return decision(KongiMood.BLINK_SLOW, null, Badge.NONE, 0, null, Fallbacks.NO_SESSIONS, now, RANK_IDLE)
        val headline = headlineFor(primary, active)
        val key = primary.sessionKey
        return when (primary.state.effective) {
            AgentState.AWAITING_APPROVAL -> {
                val count = active.count { it.state == AgentState.AWAITING_APPROVAL }
                decision(KongiMood.RAISE_HAND, null, Badge.EXCLAMATION, count, key, headline, now, RANK_APPROVAL)
            }
            AgentState.AWAITING_INPUT -> {
                val count = active.count { it.state == AgentState.AWAITING_INPUT }
                decision(KongiMood.RAISE_HAND, null, Badge.QUESTION, count, key, headline, now, RANK_INPUT)
            }
            AgentState.ERROR -> decision(KongiMood.FLUSTERED, null, Badge.NONE, 0, key, headline, now, RANK_ERROR)
            AgentState.TESTING -> decision(KongiMood.TOOLS, null, Badge.NONE, 0, key, headline, now, RANK_TESTING)
            AgentState.WRITING_CODE ->
                decision(KongiMood.TYPING, TypingVariant.FULL, Badge.NONE, 0, key, headline, now, RANK_WRITING)
            AgentState.REVIEWING -> decision(KongiMood.MAGNIFIER, null, Badge.NONE, 0, key, headline, now, RANK_REVIEWING)
            AgentState.WORKING, AgentState.UNKNOWN ->
                decision(KongiMood.TYPING, TypingVariant.WEAK, Badge.NONE, 0, key, headline, now, RANK_WORKING)
            AgentState.COMPLETED ->
                if (isCelebrating(primary, serverNow, celebrateOver)) {
                    decision(KongiMood.CELEBRATE, null, Badge.NONE, 0, key, headline, now, RANK_COMPLETED)
                } else {
                    decision(KongiMood.BLINK_SLOW, null, Badge.NONE, 0, key, headline, now, RANK_IDLE)
                }
            AgentState.DISCONNECTED, AgentState.IDLE -> decision(KongiMood.BLINK_SLOW, null, Badge.NONE, 0, key, headline, now, RANK_IDLE)
        }
    }

    private fun isCelebrating(session: SessionState, serverNow: Instant, celebrateOver: Boolean): Boolean {
        if (celebrateOver) return false
        val since = session.stateSince?.instant ?: return false
        return Duration.between(since, serverNow) < CELEBRATE_DURATION
    }

    private fun linkCandidate(link: LinkState, now: Instant): MoodDecision? = when (link) {
        is LinkState.Connected -> null
        LinkState.Unpaired -> decision(KongiMood.BLINK_SLOW, null, Badge.NONE, 0, null, Fallbacks.UNPAIRED, now, RANK_IDLE)
        LinkState.Offline -> decision(KongiMood.SLEEPY, null, Badge.NONE, 0, null, Fallbacks.linkHeadline(link, now), now, RANK_LINK)
        else -> decision(KongiMood.WORRIED, null, Badge.NONE, 0, null, Fallbacks.linkHeadline(link, now), now, RANK_LINK)
    }

    /** Home headline: the focused session's PC-written headline, prefixed with the agent when several sessions run. */
    private fun headlineFor(primary: SessionState, active: List<SessionState>): String {
        val base = primary.headline.ifBlank { fallbackHeadline(primary.state) }
        if (active.size < 2) return base
        val others = active.size - 1
        return "${primary.agentKind.shortName}${subjectParticle(primary.agentKind.shortName)} $base · 다른 ${others}개는 대기 중"
    }

    private fun fallbackHeadline(state: AgentState): String = when (state.effective) {
        AgentState.AWAITING_APPROVAL -> Fallbacks.APPROVAL_NEEDED
        AgentState.AWAITING_INPUT -> Fallbacks.NEEDS_INPUT
        AgentState.ERROR -> Fallbacks.ERROR
        AgentState.COMPLETED -> Fallbacks.COMPLETED
        AgentState.IDLE -> Fallbacks.NO_SESSIONS
        AgentState.DISCONNECTED -> Fallbacks.SESSION_LOST
        else -> Fallbacks.WORKING
    }

    /** Korean subject particle for a product name: Hangul with a final consonant takes 이, everything else 가. */
    private fun subjectParticle(name: String): String {
        val last = name.lastOrNull() ?: return "가"
        if (last in '가'..'힣' && (last.code - 0xAC00) % 28 != 0) return "이"
        return "가"
    }

    private fun decision(
        mood: KongiMood,
        variant: TypingVariant?,
        badge: Badge,
        count: Int,
        key: String?,
        headline: String,
        now: Instant,
        rank: Int,
    ) = MoodDecision(mood, variant, badge, count, key, headline, now, rank)
}
