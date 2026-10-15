package dev.agentnest.app.data

/** User preferences (docs/character.md 3.4, docs/android.md 3.1). All of them only make the app quieter or calmer. */
data class SettingsState(
    /** `animations_enabled`: false shows one still pose per mood plus the headline and chip. */
    val animationsEnabled: Boolean = true,
    /** `sound_enabled`: false posts approval notifications without sound/vibration. */
    val soundEnabled: Boolean = true,
    /** `low_power_mode`: 30 fps, breathing and blinking only. */
    val reducedMotion: Boolean = false,
    /** Start the link service after boot (needs the user to have paired before). */
    val autoStartOnBoot: Boolean = false,
)
