package dev.agentnest.core.link

import java.time.Instant

/**
 * Phone <-> PC clock offset. `skewMs = serverTime - phoneTime` (positive when the PC clock is ahead).
 * Security decisions are made on the server clock only; the phone uses the skew for display and for
 * `expires_at - skew - 5s` / `decided_at = phoneNow + skew` (docs/android.md 3.2).
 */
object ClockSkew {
    /** Skew measured when a message carrying a server time arrives at [phoneNow]. */
    fun measure(serverTime: Instant, phoneNow: Instant): Long = serverTime.toEpochMilli() - phoneNow.toEpochMilli()

    /** Converts a phone instant to the server timeline. */
    fun toServer(phoneTime: Instant, skewMs: Long): Instant = phoneTime.plusMillis(skewMs)

    /** Converts a server instant to the phone timeline. */
    fun toPhone(serverTime: Instant, skewMs: Long): Instant = serverTime.minusMillis(skewMs)
}
