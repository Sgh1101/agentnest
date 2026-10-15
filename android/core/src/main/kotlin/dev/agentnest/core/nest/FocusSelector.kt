package dev.agentnest.core.nest

import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.SessionState
import java.time.Instant

/**
 * Multi-session focus (protocol.md 5.5): `awaiting_approval 0 > awaiting_input 1 > error 2 > testing 3 >
 * writing_code 4 > reviewing 5 > working 6 > completed 7 > idle 8 > disconnected 9`; ties are broken by the most
 * recent `last_event_at`. The same rule is implemented in Rust (`state::focus`).
 */
object FocusSelector {
    /** Focus order of a state (lower wins). An unknown state counts as `working`. */
    fun order(state: AgentState): Int = when (state.effective) {
        AgentState.AWAITING_APPROVAL -> 0
        AgentState.AWAITING_INPUT -> 1
        AgentState.ERROR -> 2
        AgentState.TESTING -> 3
        AgentState.WRITING_CODE -> 4
        AgentState.REVIEWING -> 5
        AgentState.WORKING, AgentState.UNKNOWN -> 6
        AgentState.COMPLETED -> 7
        AgentState.IDLE -> 8
        AgentState.DISCONNECTED -> 9
    }

    /**
     * Picks the focused session among [sessions] using [orderOf] (defaults to [order] of the session state).
     * Ended sessions never take part. Ties on both rank and `last_event_at` fall back to the session key so the
     * result is deterministic.
     */
    fun pick(
        sessions: Collection<SessionState>,
        orderOf: (SessionState) -> Int = { order(it.state) },
    ): SessionState? = sessions
        .filter { !it.ended }
        .minWithOrNull(
            compareBy<SessionState> { orderOf(it) }
                .thenByDescending { it.lastEventAt?.instant ?: Instant.EPOCH }
                .thenBy { it.sessionKey },
        )
}
