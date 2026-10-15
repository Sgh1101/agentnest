package dev.agentnest.core.nest

/** Moods of the character (docs/character.md section 1). */
enum class KongiMood(val wire: String) {
    BLINK_SLOW("blink_slow"),
    TYPING("typing"),
    MAGNIFIER("magnifier"),
    TOOLS("tools"),
    RAISE_HAND("raise_hand"),
    FLUSTERED("flustered"),
    CELEBRATE("celebrate"),
    SLEEPY("sleepy"),
    WORRIED("worried"),
}

/** `typing` has two variants: keyboard (writing code) and hands only (generic work). */
enum class TypingVariant { FULL, WEAK }

/** Badge above the raised hand: `!` for approvals, `?` for questions. */
enum class Badge(val symbol: String) { NONE(""), EXCLAMATION("!"), QUESTION("?") }
