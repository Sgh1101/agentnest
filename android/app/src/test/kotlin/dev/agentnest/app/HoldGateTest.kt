package dev.agentnest.app

import dev.agentnest.app.ui.approvals.HOLD_MILLIS
import dev.agentnest.app.ui.approvals.HoldGate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The hold gate is decided on the wall clock, so animation scale 0 (instant animations) cannot satisfy it. */
class HoldGateTest {
    private val required = HOLD_MILLIS.toLong()

    @Test
    fun aTouchDownAloneNeverSatisfiesTheGate() {
        // With the system animation scale at 0 the ring animation "ends" on the first frame; the gate only looks at
        // the clock, so the same instant (and any time shorter than the hold) must not complete it.
        val gate = HoldGate(required)
        gate.press(10_000)
        assertFalse(gate.complete(10_000))
        assertFalse(gate.complete(10_000 + required - 1))
        assertEquals(required, gate.remainingMillis(10_000))
    }

    @Test
    fun holdingForTheFullTimeCompletesExactlyOnce() {
        val gate = HoldGate(required)
        gate.press(5_000)
        assertEquals(500, gate.remainingMillis(5_000 + required - 500))
        assertTrue(gate.complete(5_000 + required))
        assertEquals(0, gate.remainingMillis(5_000 + required))
        assertFalse("a second completion for the same press", gate.complete(5_000 + required + 100))
    }

    @Test
    fun liftingEarlyForgetsTheHoldAndANewPressStartsFromZero() {
        val gate = HoldGate(required)
        gate.press(0)
        assertFalse(gate.complete(required - 200))
        gate.release()
        // Nothing pressed: even a much later check cannot complete.
        assertFalse(gate.complete(required * 10))
        // Press again 100 ms later: the earlier 1.3 s of holding does not count.
        gate.press(required + 100)
        assertFalse(gate.complete(required + 100 + required - 1))
        assertTrue(gate.complete(required + 100 + required))
    }

    @Test
    fun aClockThatGoesBackwardsNeverCompletes() {
        val gate = HoldGate(required)
        gate.press(50_000)
        assertFalse(gate.complete(1_000))
        assertEquals(required, gate.remainingMillis(1_000))
    }

    @Test
    fun aGateWithoutPressNeverCompletes() {
        val gate = HoldGate(required)
        assertFalse(gate.complete(0))
        assertFalse(gate.complete(Long.MAX_VALUE))
        assertEquals(required, gate.remainingMillis(123))
    }

    @Test(expected = IllegalArgumentException::class)
    fun aNonPositiveHoldTimeIsRejected() {
        HoldGate(0)
    }
}
