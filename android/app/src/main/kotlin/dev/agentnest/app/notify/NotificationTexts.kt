package dev.agentnest.app.notify

import dev.agentnest.app.ui.Labels
import dev.agentnest.core.link.ClockSkew
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.link.SecurityAlertKind
import dev.agentnest.core.protocol.AgentEvent
import dev.agentnest.core.protocol.ApprovalRequest
import dev.agentnest.core.protocol.EventKind
import dev.agentnest.core.protocol.SessionState
import dev.agentnest.core.text.Fallbacks
import dev.agentnest.core.text.RelativeTime
import java.time.Duration
import java.time.Instant

/** Notification channel ids (docs/android.md 5). */
object ChannelIds {
    const val APPROVALS = "approvals"
    const val ALERTS = "alerts"
    const val COMPLETIONS = "completions"
    const val LINK = "link"
    const val SECURITY = "security"
}

/** Title and body of one notification. */
data class NotificationText(val title: String, val body: String)

/**
 * Pure notification wording (unit-tested). Approval notifications carry ONLY the PC-written title, the risk level and
 * the remaining time: never the command, paths or the agent's purpose text (docs/android.md 5, lock screen).
 */
object NotificationTexts {
    /** Shown on the lock screen instead of the details (setPublicVersion). */
    val APPROVAL_PUBLIC = NotificationText("승인 필요", "승인 요청이 있어요")

    /** Heads-up notification of one approval card. [remainingSeconds] is measured on the server clock. */
    fun approval(request: ApprovalRequest, remainingSeconds: Long): NotificationText {
        val agent = Labels.agent(request.agentKind, request.agentLabel)
        val title = "승인 필요 · $agent"
        val parts = ArrayList<String>(3)
        if (request.title.isNotBlank()) parts += request.title
        parts += Labels.risk(request.risk.level)
        parts += "${RelativeTime.countdown(remainingSeconds)} 남음"
        return NotificationText(title, parts.joinToString(" · "))
    }

    /** Remaining seconds of [request] at phone time [now], given the clock skew. Never negative. */
    fun remainingSeconds(request: ApprovalRequest, now: Instant, clockSkewMs: Long): Long {
        val server = ClockSkew.toServer(now, clockSkewMs)
        return Duration.between(server, request.expiresAt.instant).seconds.coerceAtLeast(0)
    }

    /** Group summary line "승인 대기 N건". */
    fun approvalSummary(count: Int): NotificationText = NotificationText("승인 대기 ${count}건", "탭하여 확인하세요")

    /** Persistent status notification of the foreground service. */
    fun linkStatus(link: LinkState, pcName: String?, paused: Boolean, now: Instant): String {
        if (paused) return "연결이 일시정지됐어요"
        return when (link) {
            is LinkState.Connected -> {
                val name = pcName?.takeIf { it.isNotBlank() } ?: link.pc.name
                if (name.isBlank()) "연결됨" else "연결됨 · $name"
            }
            else -> Fallbacks.linkHeadline(link, now)
        }
    }

    /** Title and body of a security notification. */
    fun security(kind: SecurityAlertKind): NotificationText = when (kind) {
        SecurityAlertKind.PC_IDENTITY_CHANGED ->
            NotificationText("PC 신원이 바뀌었어요", "연결을 멈췄어요. PC를 직접 확인한 뒤 다시 페어링해 주세요")
        SecurityAlertKind.DEVICE_REVOKED ->
            NotificationText("PC에서 이 기기를 해제했어요", "다시 연결하려면 PC에서 새 QR을 만들어 페어링해 주세요")
        SecurityAlertKind.REPEATED_AUTH_FAILURE ->
            NotificationText("인증에 계속 실패했어요", "연결을 멈췄어요. 다시 페어링해 주세요")
    }

    /** Alert (error) notification: the PC-written headline and the project name. */
    fun alert(event: AgentEvent, session: SessionState?): NotificationText {
        val project = event.project?.name?.takeIf { it.isNotBlank() } ?: session?.project?.name.orEmpty()
        val title = event.summary.headline.ifBlank { Labels.eventKind(event.kind) }
        val agent = Labels.agent(event.agentKind, session?.agentLabel.orEmpty())
        val body = if (project.isBlank()) agent else "$agent · $project"
        return NotificationText(title, body)
    }
}

/** Which notification channel an event belongs to. */
enum class AlertKind { ERROR, COMPLETION }

/** Pure rules deciding which events notify (docs/android.md 5: errors on `alerts`, long turns on `completions`). */
object AlertPolicy {
    /** Turns shorter than this do not notify on completion. */
    const val COMPLETION_MIN_TURN_SECONDS: Long = 30

    /** At most one alert per session in this window. */
    const val ALERT_THROTTLE_SECONDS: Long = 60

    private val errorKinds = setOf(EventKind.TURN_FAILED, EventKind.AGENT_ERROR, EventKind.TEST_FAILED)

    /** The alert kind of [event], or null when it should not notify. [session] supplies the turn start time. */
    fun classify(event: AgentEvent, session: SessionState?): AlertKind? {
        if (event.kind in errorKinds) return AlertKind.ERROR
        if (event.kind == EventKind.TURN_COMPLETED) {
            val started = session?.turn?.startedAt?.instant ?: return null
            val seconds = Duration.between(started, event.ts.instant).seconds
            return if (seconds >= COMPLETION_MIN_TURN_SECONDS) AlertKind.COMPLETION else null
        }
        return null
    }
}

/** Per-session throttle for alerts ("세션당 60초 1건"). Not thread-safe; call from one thread. */
class AlertThrottle(private val window: Duration = Duration.ofSeconds(AlertPolicy.ALERT_THROTTLE_SECONDS)) {
    private val last = HashMap<String, Instant>()

    /** True (and remembers [now]) when [sessionKey] has not alerted within the window. */
    fun allow(sessionKey: String, now: Instant): Boolean {
        val previous = last[sessionKey]
        if (previous != null && Duration.between(previous, now) < window) return false
        last[sessionKey] = now
        if (last.size > MAX_TRACKED) last.entries.removeAll { Duration.between(it.value, now) >= window }
        return true
    }

    private companion object {
        const val MAX_TRACKED = 64
    }
}
