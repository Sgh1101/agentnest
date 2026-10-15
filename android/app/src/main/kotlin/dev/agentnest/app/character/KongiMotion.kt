package dev.agentnest.app.character

import dev.agentnest.core.nest.Badge
import dev.agentnest.core.nest.KongiMood
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sin

/**
 * Everything the canvas needs for one frame. Mutable and reused (no per-frame allocation); all lengths are in the
 * 100 x 100 drawing units of [KongiMotion].
 */
class KongiPose {
    var prop: Prop = Prop.NONE
    var badge: Badge = Badge.NONE
    var bodyDx = 0f
    var bodyDy = 0f
    var eyeOpenL = 1f
    var eyeOpenR = 1f
    var eyeScaleL = 1f
    var eyeScaleR = 1f
    var eyeShake = 0f
    var pupilDx = 0f
    var pupilDy = 0f

    /** 1 = closed happy arcs, 0 = normal eyes. */
    var eyeHappy = 0f
    var mouthCurve = 0.2f
    var mouthOpen = 0f

    /** 0..1: how far the eyebrows are drawn tilted. */
    var brow = 0f
    var handLx = 0f
    var handLy = 0f
    var handRx = 0f
    var handRy = 0f
    var propX = 0f
    var propY = 0f
    var propAngle = 0f

    /** 0..1 progress of the looping prop animation (sparks, sweat drop, z letters). */
    var propPhase = 0f
    var badgeScale = 1f

    /** Copies every field of [o]. */
    fun set(o: KongiPose) {
        prop = o.prop; badge = o.badge
        bodyDx = o.bodyDx; bodyDy = o.bodyDy
        eyeOpenL = o.eyeOpenL; eyeOpenR = o.eyeOpenR; eyeScaleL = o.eyeScaleL; eyeScaleR = o.eyeScaleR
        eyeShake = o.eyeShake; pupilDx = o.pupilDx; pupilDy = o.pupilDy; eyeHappy = o.eyeHappy
        mouthCurve = o.mouthCurve; mouthOpen = o.mouthOpen; brow = o.brow
        handLx = o.handLx; handLy = o.handLy; handRx = o.handRx; handRy = o.handRy
        propX = o.propX; propY = o.propY; propAngle = o.propAngle; propPhase = o.propPhase; badgeScale = o.badgeScale
    }
}

/**
 * Pure pose computation (docs/character.md 3.2). `pose(spec, level, tMs, moodElapsedMs, out)` depends only on its
 * arguments, so the motion table can be tested without Compose.
 */
object KongiMotion {
    const val BODY_CX = 50f
    const val BODY_CY = 60f
    const val BODY_RX = 28f
    const val BODY_RY = 25f
    const val EYE_DX = 10f
    const val EYE_Y = 54f
    const val EYE_R = 4.6f
    const val MOUTH_Y = 67f
    const val HAND_R = 5f
    const val REST_HAND_DX = 31f
    const val REST_HAND_Y = 68f

    /** Duration of the cross-fade between two moods. */
    const val TRANSITION_MS = 300L

    /** Jump height of `celebrate` (12 dp ~ 7.5 units at 160 dp) and its duration. */
    const val JUMP_UNITS = 7.5f
    const val JUMP_MS = 500L

    private const val TWO_PI = (2.0 * PI).toFloat()
    private const val BLINK_CYCLE_MS = 14_000L
    private val BLINK_ENDS = longArrayOf(3200L, 7300L, 10_200L, 14_000L)
    private const val BLINK_CLOSE_MS = 300f

    /** The time at which a still pose is drawn when animations are off (a characteristic frame per mood). */
    fun stillTimeMs(mood: KongiMood): Long = when (mood) {
        KongiMood.TYPING -> 60L
        KongiMood.MAGNIFIER -> 400L
        KongiMood.TOOLS -> 100L
        KongiMood.RAISE_HAND -> 150L
        KongiMood.FLUSTERED -> 300L
        KongiMood.CELEBRATE -> 700L
        else -> 0L
    }

    /** Fills [out] for [spec] at time [tMs]; [moodElapsedMs] is the time since the mood started (one-shot motions). */
    fun pose(spec: KongiSpec, level: MotionLevel, tMs: Long, moodElapsedMs: Long, out: KongiPose) {
        val still = stillTimeMs(spec.mood)
        when (level) {
            MotionLevel.FULL -> fill(spec, tMs, moodElapsedMs, out)
            MotionLevel.NONE -> fill(spec, still, still, out)
            MotionLevel.LOW -> {
                fill(spec, still, still, out)
                if (spec.mood != KongiMood.SLEEPY && spec.mood != KongiMood.CELEBRATE) {
                    val blink = blinkFactor(tMs)
                    out.eyeOpenL = min(out.eyeOpenL, blink)
                    out.eyeOpenR = min(out.eyeOpenR, blink)
                }
                out.bodyDy += wave(tMs, 3000) * 1.0f
            }
        }
    }

    /** Linear blend of two poses (`f` in 0..1). Discrete parts (prop, badge) switch at the midpoint. */
    fun blend(a: KongiPose, b: KongiPose, f: Float, out: KongiPose) {
        out.prop = if (f < 0.5f) a.prop else b.prop
        out.badge = if (f < 0.5f) a.badge else b.badge
        out.bodyDx = mix(a.bodyDx, b.bodyDx, f)
        out.bodyDy = mix(a.bodyDy, b.bodyDy, f)
        out.eyeOpenL = mix(a.eyeOpenL, b.eyeOpenL, f)
        out.eyeOpenR = mix(a.eyeOpenR, b.eyeOpenR, f)
        out.eyeScaleL = mix(a.eyeScaleL, b.eyeScaleL, f)
        out.eyeScaleR = mix(a.eyeScaleR, b.eyeScaleR, f)
        out.eyeShake = mix(a.eyeShake, b.eyeShake, f)
        out.pupilDx = mix(a.pupilDx, b.pupilDx, f)
        out.pupilDy = mix(a.pupilDy, b.pupilDy, f)
        out.eyeHappy = mix(a.eyeHappy, b.eyeHappy, f)
        out.mouthCurve = mix(a.mouthCurve, b.mouthCurve, f)
        out.mouthOpen = mix(a.mouthOpen, b.mouthOpen, f)
        out.brow = mix(a.brow, b.brow, f)
        out.handLx = mix(a.handLx, b.handLx, f)
        out.handLy = mix(a.handLy, b.handLy, f)
        out.handRx = mix(a.handRx, b.handRx, f)
        out.handRy = mix(a.handRy, b.handRy, f)
        out.propX = mix(a.propX, b.propX, f)
        out.propY = mix(a.propY, b.propY, f)
        out.propAngle = mix(a.propAngle, b.propAngle, f)
        out.propPhase = if (f < 0.5f) a.propPhase else b.propPhase
        out.badgeScale = mix(a.badgeScale, b.badgeScale, f)
    }

    /** Eye openness 1 -> 0 -> 1 around the end of each of four blink intervals (2.8 - 4.2 s apart). */
    fun blinkFactor(tMs: Long): Float {
        val p = ((tMs % BLINK_CYCLE_MS) + BLINK_CYCLE_MS) % BLINK_CYCLE_MS
        for (end in BLINK_ENDS) {
            val x = (p - (end - BLINK_CLOSE_MS)) / BLINK_CLOSE_MS
            if (x in 0f..1f) return abs(2f * x - 1f)
        }
        return 1f
    }

    // ---------------------------------------------------------------------------------------------

    private fun fill(spec: KongiSpec, t: Long, elapsed: Long, out: KongiPose) {
        reset(spec, out)
        when (spec.mood) {
            KongiMood.BLINK_SLOW -> blinkSlow(t, out)
            KongiMood.TYPING -> if (spec.prop == Prop.KEYBOARD) typingFull(t, out) else typingWeak(t, out)
            KongiMood.MAGNIFIER -> magnifier(t, out)
            KongiMood.TOOLS -> tools(t, out)
            KongiMood.RAISE_HAND -> raiseHand(t, out)
            KongiMood.FLUSTERED -> flustered(t, out)
            KongiMood.CELEBRATE -> celebrate(t, elapsed, out)
            KongiMood.SLEEPY -> sleepy(t, out)
            KongiMood.WORRIED -> worried(t, out)
        }
    }

    private fun reset(spec: KongiSpec, out: KongiPose) {
        out.prop = spec.prop
        out.badge = spec.badge
        out.bodyDx = 0f
        out.bodyDy = 0f
        out.eyeOpenL = 1f
        out.eyeOpenR = 1f
        out.eyeScaleL = 1f
        out.eyeScaleR = 1f
        out.eyeShake = 0f
        out.pupilDx = 0f
        out.pupilDy = 0f
        out.eyeHappy = 0f
        out.mouthCurve = 0.2f
        out.mouthOpen = 0f
        out.brow = 0f
        out.handLx = BODY_CX - REST_HAND_DX
        out.handLy = REST_HAND_Y
        out.handRx = BODY_CX + REST_HAND_DX
        out.handRy = REST_HAND_Y
        out.propX = 0f
        out.propY = 0f
        out.propAngle = 0f
        out.propPhase = 0f
        out.badgeScale = 1f
    }

    private fun blinkSlow(t: Long, out: KongiPose) {
        out.bodyDy = wave(t, 3000) * 1.2f
        val blink = blinkFactor(t)
        out.eyeOpenL = blink
        out.eyeOpenR = blink
        out.mouthCurve = 0.25f
    }

    private fun typingFull(t: Long, out: KongiPose) {
        val a = wave(t, 240)
        out.eyeOpenL = 0.5f
        out.eyeOpenR = 0.5f
        out.pupilDy = 1.2f
        out.bodyDy = a * 0.35f
        out.handLx = 40f
        out.handRx = 60f
        out.handLy = 79f + max(0f, a) * 3f
        out.handRy = 79f + max(0f, -a) * 3f
        out.propX = BODY_CX
        out.propY = 84f
        out.mouthCurve = 0.15f
    }

    private fun typingWeak(t: Long, out: KongiPose) {
        val a = wave(t, 500)
        out.eyeOpenL = 0.8f
        out.eyeOpenR = 0.8f
        out.pupilDy = 0.8f
        out.handLx = 41f
        out.handRx = 59f
        out.handLy = 76f + max(0f, a) * 1.6f
        out.handRy = 76f + max(0f, -a) * 1.6f
        out.mouthCurve = 0.2f
    }

    private fun magnifier(t: Long, out: KongiPose) {
        val s = wave(t, 1600)
        out.propX = BODY_CX + 22f * s
        out.propY = 64f
        out.handRx = out.propX + 7f
        out.handRy = out.propY + 9f
        out.pupilDx = if (s >= 0f) 1.8f else -1.8f
        if (s >= 0f) out.eyeScaleR = 1.35f else out.eyeScaleL = 1.35f
        out.mouthCurve = 0.1f
    }

    private fun tools(t: Long, out: KongiPose) {
        val s = wave(t, 500)
        out.propX = 76f
        out.propY = 66f
        out.propAngle = 35f * s
        out.propPhase = fraction(t, 500)
        out.handRx = 76f
        out.handRy = 66f
        out.eyeOpenL = 0.7f
        out.eyeOpenR = 0.7f
        out.mouthCurve = 0.05f
    }

    private fun raiseHand(t: Long, out: KongiPose) {
        val s = wave(t, 600)
        out.handRx = 78f + 5f * s
        out.handRy = 30f
        out.bodyDy = s * 0.6f
        out.eyeScaleL = 1.15f
        out.eyeScaleR = 1.15f
        out.mouthCurve = 0f
        out.mouthOpen = 0.6f
        out.badgeScale = 1.125f + 0.125f * wave(t, 1000)
    }

    private fun flustered(t: Long, out: KongiPose) {
        out.eyeShake = 0.6f * wave(t, 80)
        out.propPhase = fraction(t, 1200)
        out.mouthCurve = -0.6f
        out.brow = 0.6f
        out.eyeScaleL = 1.1f
        out.eyeScaleR = 1.1f
    }

    private fun celebrate(t: Long, elapsed: Long, out: KongiPose) {
        out.eyeHappy = 1f
        out.mouthCurve = 1f
        out.mouthOpen = 0.35f
        out.bodyDy = if (elapsed in 0L until JUMP_MS) -JUMP_UNITS * sin((PI * elapsed / JUMP_MS).toFloat()) else 0f
        val cheer = wave(t, 400) * 1.5f
        out.handLx = 24f
        out.handLy = 42f + cheer
        out.handRx = 76f
        out.handRy = 42f - cheer
    }

    private fun sleepy(t: Long, out: KongiPose) {
        out.eyeOpenL = 0f
        out.eyeOpenR = 0f
        out.mouthCurve = 0f
        out.bodyDy = wave(t, 2000) * 1.6f
        out.propPhase = fraction(t, 2000)
    }

    private fun worried(t: Long, out: KongiPose) {
        out.bodyDx = wave(t, 1400) * 1.2f
        out.brow = 1f
        out.mouthCurve = -0.5f
        out.pupilDy = -0.6f
    }

    /** sin of the position inside a period of [periodMs] (-1..1). */
    internal fun wave(tMs: Long, periodMs: Int): Float {
        val p = ((tMs % periodMs) + periodMs) % periodMs
        return sin(TWO_PI * p / periodMs)
    }

    internal fun fraction(tMs: Long, periodMs: Int): Float {
        val p = ((tMs % periodMs) + periodMs) % periodMs
        return p.toFloat() / periodMs
    }

    private fun mix(a: Float, b: Float, f: Float): Float = a + (b - a) * f
}
