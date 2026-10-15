package dev.agentnest.core.text

import dev.agentnest.core.link.LinkError
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.link.RepairReason
import java.time.Duration
import java.time.Instant

/**
 * Korean strings the phone itself produces. Everything about agents, sessions and approvals is worded by the
 * PC (protocol.md 5.2); these cover only link states and empty states.
 */
object Fallbacks {
    const val NO_SESSIONS = "지금은 조용해요. 에이전트를 기다리고 있어요"
    const val WORKING = "작업하고 있어요"
    const val NEEDS_INPUT = "도움이 필요해요"
    const val APPROVAL_NEEDED = "승인이 필요해요"
    const val ERROR = "문제가 생겼어요"
    const val COMPLETED = "작업을 마쳤어요"
    const val SESSION_LOST = "에이전트와 연결이 끊겼어요"
    const val UNPAIRED = "PC를 연결해 주세요"
    const val OFFLINE = "인터넷에 연결되어 있지 않아요"
    const val BLOCKED_OFFLINE = "PC와 연결이 끊겨 지금은 응답할 수 없어요"
    const val UNKNOWN_OUTCOME = "처리됨"

    /** One-line headline for a non-connected link state (home banner / mood headline). */
    fun linkHeadline(link: LinkState, now: Instant): String = when (link) {
        LinkState.Unpaired -> UNPAIRED
        is LinkState.Connecting -> "PC에 연결하고 있어요"
        LinkState.Challenged -> "PC에 연결하고 있어요"
        is LinkState.Connected -> ""
        is LinkState.Reconnecting -> {
            val seconds = Duration.between(now, link.nextAt).seconds.coerceAtLeast(0)
            val reason = when (val e = link.lastError) {
                is LinkError.PcShutdown -> e.messageKo ?: "PC에서 휴대폰 연결을 껐어요"
                LinkError.Superseded -> "다른 곳에서 연결됐어요"
                else -> "PC와 연결이 끊겼어요"
            }
            "$reason · 다시 연결 중 (${link.attempt}번째, ${seconds}초 후)"
        }
        LinkState.Offline -> OFFLINE
        is LinkState.PcUnreachable -> "PC를 찾을 수 없어요. 같은 Wi-Fi인지 확인해 주세요"
        is LinkState.NeedsRepair -> when (link.reason) {
            RepairReason.AUTH_FAILED -> "인증에 실패했어요. 다시 페어링해 주세요"
            RepairReason.IDENTITY_CHANGED -> "PC 신원이 바뀌었어요. 다시 페어링해 주세요"
        }
        is LinkState.Revoked -> "PC에서 이 기기의 연결을 해제했어요"
        is LinkState.Suspended -> "PC 신원이 바뀌었어요"
        LinkState.Incompatible -> "앱을 업데이트해 주세요"
    }
}
