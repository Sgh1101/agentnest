package dev.agentnest.app.ui.approvals

/** How long the button must be held (docs/android.md 2.2: "길게 누르기 1.5초"). */
const val HOLD_MILLIS: Int = 1500

/**
 * Wall-clock decision of the press-and-hold gate (docs/android.md 2.2). It is deliberately independent of Compose:
 * Compose animations finish on their first frame when the system animation scale is 0 (developer options or the
 * accessibility "remove animations" switch), so an animation that ends can never be what proves the user held the
 * button. The caller feeds a monotonic clock (`SystemClock.uptimeMillis()`); the progress ring is cosmetic only.
 *
 * A hold counts only while one press is active: [release] (finger lifted, gesture cancelled) forgets it, and a new
 * [press] starts again from zero. [complete] returns true at most once per press.
 */
class HoldGate(private val requiredMillis: Long) {
    private var pressedAt: Long? = null
    private var fired = false

    init {
        require(requiredMillis > 0) { "requiredMillis must be positive" }
    }

    /** A finger went down at [nowMillis]; any earlier partial hold is discarded. */
    fun press(nowMillis: Long) {
        pressedAt = nowMillis
        fired = false
    }

    /** The finger lifted or the gesture was cancelled. */
    fun release() {
        pressedAt = null
        fired = false
    }

    /** Milliseconds still to wait at [nowMillis]; 0 once satisfied, [requiredMillis] when nothing is pressed. */
    fun remainingMillis(nowMillis: Long): Long {
        val start = pressedAt ?: return requiredMillis
        return (requiredMillis - (nowMillis - start)).coerceIn(0L, requiredMillis)
    }

    /** True exactly once: when a press has lasted [requiredMillis] on the wall clock. */
    fun complete(nowMillis: Long): Boolean {
        val start = pressedAt ?: return false
        if (fired) return false
        // A clock that went backwards (should not happen with uptime) never satisfies the gate.
        val held = nowMillis - start
        if (held < requiredMillis) return false
        fired = true
        return true
    }
}
