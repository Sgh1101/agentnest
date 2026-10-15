package dev.agentnest.app.character

/** What the system says about motion: animator scale 0 ([DISABLED]) or battery saver ([POWER_SAVE]). */
enum class SystemMotion { NORMAL, POWER_SAVE, DISABLED }

/** Combines the user's toggles with the system state (docs/character.md 3.3 / 3.4). Pure, unit-tested. */
object MotionPolicy {
    /**
     * Animations off (user or system animation scale 0) -> a still pose; reduced motion or battery saver -> 30 fps with
     * breathing and blinking only; otherwise full motion.
     */
    fun resolve(animationsEnabled: Boolean, reducedMotion: Boolean, system: SystemMotion): MotionLevel = when {
        !animationsEnabled || system == SystemMotion.DISABLED -> MotionLevel.NONE
        reducedMotion || system == SystemMotion.POWER_SAVE -> MotionLevel.LOW
        else -> MotionLevel.FULL
    }
}
