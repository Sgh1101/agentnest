package dev.agentnest.app.ui

import dev.agentnest.core.link.ClockSkew
import dev.agentnest.core.protocol.Ts
import dev.agentnest.core.text.RelativeTime
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/** Small pure formatting helpers shared by the screens. */
object Format {
    private val CLOCK: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm")
    private val DAY: DateTimeFormatter = DateTimeFormatter.ofPattern("M월 d일")

    /** "3분 전" for a server timestamp, or null when [ts] is missing. */
    fun ago(ts: Ts?, now: Instant, skewMs: Long): String? {
        val instant = ts?.instant ?: return null
        return RelativeTime.ago(ClockSkew.toPhone(instant, skewMs), now)
    }

    /** Local "HH:mm" of a server timestamp. */
    fun clock(ts: Ts, skewMs: Long, zone: ZoneId = ZoneId.systemDefault()): String =
        CLOCK.format(ClockSkew.toPhone(ts.instant, skewMs).atZone(zone))

    /** Local "10월 15일" of a server timestamp (timeline date dividers). */
    fun day(ts: Ts, skewMs: Long, zone: ZoneId = ZoneId.systemDefault()): String =
        DAY.format(ClockSkew.toPhone(ts.instant, skewMs).atZone(zone))

    /** The local calendar date of a server timestamp, as a sortable key. */
    fun dayKey(ts: Ts, skewMs: Long, zone: ZoneId = ZoneId.systemDefault()): String =
        ClockSkew.toPhone(ts.instant, skewMs).atZone(zone).toLocalDate().toString()

    /** Cuts [text] to [max] characters with an ellipsis. */
    fun shorten(text: String, max: Int): String = if (text.length <= max) text else text.take(max - 1) + "…"
}
