package dev.agentnest.app.character

import dev.agentnest.app.ui.Tone
import dev.agentnest.core.nest.Badge
import dev.agentnest.core.nest.KongiMood
import dev.agentnest.core.nest.TypingVariant

/** Held or drawn objects (docs/character.md 3.1). */
enum class Prop { NONE, KEYBOARD, MAGNIFIER, WRENCH, HAND, SWEAT, ZZZ }

/** How much the character moves. [NONE] is a still pose; [LOW] is 30 fps with breathing and blinking only. */
enum class MotionLevel { FULL, LOW, NONE }

/**
 * Static description of one mood: no Compose types, so it is unit-testable on the JVM (docs/character.md 5).
 * Lengths are in the 100 x 100 drawing units of [KongiMotion].
 */
data class KongiSpec(
    val mood: KongiMood,
    val typingVariant: TypingVariant?,
    val badge: Badge,
    val tone: Tone,
    val prop: Prop,
    /** Main motion period in milliseconds (0 = no periodic motion). */
    val periodMs: Int,
    /** `contentDescription` of the canvas, e.g. "콩이: 승인을 기다리고 있어요". */
    val description: String,
) {
    companion object {
        /** Builds the spec for [mood]. [typingVariant] only matters for [KongiMood.TYPING]; [badge] for [KongiMood.RAISE_HAND]. */
        fun of(mood: KongiMood, typingVariant: TypingVariant? = null, badge: Badge = Badge.NONE): KongiSpec {
            val variant = if (mood == KongiMood.TYPING) typingVariant ?: TypingVariant.WEAK else null
            val shownBadge = if (mood == KongiMood.RAISE_HAND) badge else Badge.NONE
            return KongiSpec(
                mood = mood,
                typingVariant = variant,
                badge = shownBadge,
                tone = toneOf(mood),
                prop = propOf(mood, variant),
                periodMs = periodOf(mood, variant),
                description = descriptionOf(mood, variant, shownBadge),
            )
        }

        internal fun toneOf(mood: KongiMood): Tone = when (mood) {
            KongiMood.BLINK_SLOW -> Tone.NEUTRAL
            KongiMood.TYPING -> Tone.ACCENT
            KongiMood.MAGNIFIER, KongiMood.TOOLS -> Tone.INFO
            KongiMood.RAISE_HAND -> Tone.WARNING
            KongiMood.FLUSTERED -> Tone.DANGER
            KongiMood.CELEBRATE -> Tone.SUCCESS
            KongiMood.SLEEPY, KongiMood.WORRIED -> Tone.MUTED
        }

        internal fun propOf(mood: KongiMood, variant: TypingVariant?): Prop = when (mood) {
            KongiMood.TYPING -> if (variant == TypingVariant.FULL) Prop.KEYBOARD else Prop.NONE
            KongiMood.MAGNIFIER -> Prop.MAGNIFIER
            KongiMood.TOOLS -> Prop.WRENCH
            KongiMood.RAISE_HAND -> Prop.HAND
            KongiMood.FLUSTERED -> Prop.SWEAT
            KongiMood.SLEEPY -> Prop.ZZZ
            else -> Prop.NONE
        }

        internal fun periodOf(mood: KongiMood, variant: TypingVariant?): Int = when (mood) {
            KongiMood.BLINK_SLOW -> 3000
            KongiMood.TYPING -> if (variant == TypingVariant.FULL) 120 else 250
            KongiMood.MAGNIFIER -> 1600
            KongiMood.TOOLS -> 500
            KongiMood.RAISE_HAND -> 600
            KongiMood.FLUSTERED -> 1200
            KongiMood.CELEBRATE -> 500
            KongiMood.SLEEPY -> 2000
            KongiMood.WORRIED -> 1400
        }

        internal fun descriptionOf(mood: KongiMood, variant: TypingVariant?, badge: Badge): String = when (mood) {
            KongiMood.BLINK_SLOW -> "콩이: 조용히 쉬고 있어요"
            KongiMood.TYPING ->
                if (variant == TypingVariant.FULL) "콩이: 코드를 작성하고 있어요" else "콩이: 열심히 작업하고 있어요"
            KongiMood.MAGNIFIER -> "콩이: 꼼꼼히 살펴보고 있어요"
            KongiMood.TOOLS -> "콩이: 테스트를 돌리고 있어요"
            KongiMood.RAISE_HAND ->
                if (badge == Badge.QUESTION) "콩이: 도움을 기다리고 있어요" else "콩이: 승인을 기다리고 있어요"
            KongiMood.FLUSTERED -> "콩이: 문제가 생겨서 당황했어요"
            KongiMood.CELEBRATE -> "콩이: 작업을 마쳐서 기뻐하고 있어요"
            KongiMood.SLEEPY -> "콩이: 졸려요. 인터넷에 연결되어 있지 않아요"
            KongiMood.WORRIED -> "콩이: 걱정하고 있어요. 연결이 끊겼어요"
        }
    }
}
