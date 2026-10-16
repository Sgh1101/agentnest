package dev.agentnest.app.data

import dev.agentnest.core.protocol.AgentEvent
import dev.agentnest.core.protocol.SessionState
import dev.agentnest.core.protocol.SnapshotMessage

/**
 * What the on-disk snapshot cache keeps (docs/android.md 1.3 / 2.1). The cache lives in plain DataStore, so it holds
 * only what a cold start needs to draw the home screen at once: session state, headlines, counters, adapter status
 * and the timeline lines. Everything that carries command text, file paths or prompt text is dropped, exactly like
 * the approval cards: `recent_commands`, `recent_files`, `turn.prompt_preview`, the project path hint and the
 * free-form `detail` of sessions and events. The live snapshot after reconnecting refills them. Pure; unit-tested.
 */
object SnapshotRedaction {
    /** [message] without approval cards and without command / path / prompt text. */
    fun strip(message: SnapshotMessage): SnapshotMessage {
        val p = message.payload
        return SnapshotMessage(
            message.meta,
            p.copy(
                sessions = p.sessions.map(::session),
                pendingApprovals = emptyList(),
                pendingApprovalIdsComplete = emptyList(),
                recentErrors = p.recentErrors.map(::event),
                recentEvents = p.recentEvents.map(::event),
            ),
        )
    }

    private fun session(s: SessionState): SessionState = s.copy(
        project = s.project.copy(pathHint = null),
        detail = null,
        turn = s.turn.copy(promptPreview = null),
        recentFiles = emptyList(),
        recentCommands = emptyList(),
    )

    private fun event(e: AgentEvent): AgentEvent = e.copy(
        project = e.project?.copy(pathHint = null),
        summary = e.summary.copy(detail = null),
        detail = null,
    )
}
