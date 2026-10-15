package dev.agentnest.core.text

import java.time.Duration
import java.time.Instant

/** Korean relative time ("3분 전") for "마지막 확인 N분 전" and timelines. The only text formatting the phone does itself. */
object RelativeTime {
    /** Formats how long ago [then] was, relative to [now]. Future timestamps read as "방금 전". */
    fun ago(then: Instant, now: Instant): String {
        val seconds = Duration.between(then, now).seconds
        return when {
            seconds < 10 -> "방금 전"
            seconds < 60 -> "${seconds}초 전"
            seconds < 3600 -> "${seconds / 60}분 전"
            seconds < 86_400 -> "${seconds / 3600}시간 전"
            else -> "${seconds / 86_400}일 전"
        }
    }

    /** Formats a remaining time as `m:ss` for countdowns ("1:48 남음"). */
    fun countdown(secondsLeft: Long): String {
        val s = secondsLeft.coerceAtLeast(0)
        return "${s / 60}:${(s % 60).toString().padStart(2, '0')}"
    }
}
