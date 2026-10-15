package dev.agentnest.app.ui.activity

import dev.agentnest.core.protocol.AgentEvent
import dev.agentnest.core.protocol.EventKind
import dev.agentnest.core.protocol.Severity

/** Filter chips of the activity timeline (docs/android.md 2.3). */
enum class EventFilter(val labelKo: String) {
    ALL("전체"),
    ERRORS("오류"),
    DONE("완료"),
    APPROVALS("승인"),
    FILES("파일"),
    COMMANDS("명령");

    /** True when [event] belongs to this filter. */
    fun matches(event: AgentEvent): Boolean = when (this) {
        ALL -> true
        ERRORS -> event.severity == Severity.ERROR || event.severity == Severity.WARNING || event.kind in ERROR_KINDS
        DONE -> event.kind in DONE_KINDS
        APPROVALS -> event.kind in APPROVAL_KINDS
        FILES -> event.kind == EventKind.FILE_READ || event.kind == EventKind.FILE_MODIFIED
        COMMANDS -> event.kind in COMMAND_KINDS
    }

    private companion object {
        val ERROR_KINDS = setOf(
            EventKind.TURN_FAILED, EventKind.TOOL_FAILED, EventKind.COMMAND_FAILED, EventKind.TEST_FAILED, EventKind.AGENT_ERROR,
        )
        val DONE_KINDS = setOf(
            EventKind.TURN_COMPLETED, EventKind.TASK_COMPLETED, EventKind.TEST_PASSED, EventKind.COMMAND_COMPLETED,
            EventKind.REVIEW_COMPLETED,
        )
        val APPROVAL_KINDS = setOf(
            EventKind.APPROVAL_REQUESTED, EventKind.APPROVAL_RESOLVED, EventKind.PERMISSION_DENIED_AUTO,
        )
        val COMMAND_KINDS = setOf(
            EventKind.COMMAND_STARTED, EventKind.COMMAND_COMPLETED, EventKind.COMMAND_FAILED,
        )
    }
}
