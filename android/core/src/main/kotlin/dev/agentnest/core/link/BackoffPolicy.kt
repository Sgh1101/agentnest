package dev.agentnest.core.link

import java.time.Duration

/**
 * Reconnect backoff: 1, 2, 4, 8, 16, 32, 60, 60, ... seconds with +/-20% jitter (docs/android.md 3.2).
 * [random] must return values in `[0, 1)`; it is injectable so tests are deterministic.
 */
class BackoffPolicy(
    private val random: () -> Double = Math::random,
    private val jitterFraction: Double = 0.2,
) {
    /** The un-jittered delay in seconds for the given 1-based [attempt]. */
    fun baseSeconds(attempt: Int): Long = SCHEDULE[(attempt - 1).coerceIn(0, SCHEDULE.lastIndex)]

    /** The jittered delay before the [attempt]-th retry (1-based). */
    fun delay(attempt: Int): Duration {
        val base = baseSeconds(attempt) * 1000.0
        val factor = 1.0 + (random() * 2.0 - 1.0) * jitterFraction
        return Duration.ofMillis(Math.round(base * factor))
    }

    companion object {
        private val SCHEDULE = longArrayOf(1, 2, 4, 8, 16, 32, 60)
    }
}
