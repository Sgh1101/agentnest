package dev.agentnest.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import dev.agentnest.app.ui.Tone

private val LightColors: ColorScheme = lightColorScheme(
    primary = Color(0xFF7A5A3A),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFF1E1CC),
    onPrimaryContainer = Color(0xFF2E1F0F),
    secondary = Color(0xFF5E6B7A),
    onSecondary = Color(0xFFFFFFFF),
    background = Color(0xFFFBF7F1),
    onBackground = Color(0xFF1F1B16),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF1F1B16),
    surfaceVariant = Color(0xFFF0EAE0),
    onSurfaceVariant = Color(0xFF50483D),
    outline = Color(0xFF8A8174),
    error = Color(0xFFB3261E),
    onError = Color(0xFFFFFFFF),
)

private val DarkColors: ColorScheme = darkColorScheme(
    primary = Color(0xFFE0B98A),
    onPrimary = Color(0xFF3B2711),
    primaryContainer = Color(0xFF58402A),
    onPrimaryContainer = Color(0xFFF7E3CB),
    secondary = Color(0xFFB4C0CE),
    onSecondary = Color(0xFF1F2A36),
    background = Color(0xFF14110E),
    onBackground = Color(0xFFEBE3D8),
    surface = Color(0xFF1E1A16),
    onSurface = Color(0xFFEBE3D8),
    surfaceVariant = Color(0xFF2C2620),
    onSurfaceVariant = Color(0xFFCFC5B6),
    outline = Color(0xFF978E80),
    error = Color(0xFFF2B8B5),
    onError = Color(0xFF601410),
)

/** Background and text colour of a status chip / badge. */
data class ToneColors(val container: Color, val content: Color)

/** Maps [Tone] tokens (docs/character.md 1) to concrete colours for light and dark themes. */
object ToneTheme {
    /** Colours of [tone]; [dark] selects the dark variant. */
    fun colors(tone: Tone, dark: Boolean): ToneColors = if (dark) darkTone(tone) else lightTone(tone)

    /** The solid colour of [tone] (body of the character, accents). */
    fun solid(tone: Tone, dark: Boolean): Color = when (tone) {
        Tone.NEUTRAL -> if (dark) Color(0xFFCDBFA8) else Color(0xFF9B8B72)
        Tone.ACCENT -> if (dark) Color(0xFFE0B98A) else Color(0xFF9A6B3C)
        Tone.INFO -> if (dark) Color(0xFF8FB8E8) else Color(0xFF3F78B8)
        Tone.WARNING -> if (dark) Color(0xFFF2C35B) else Color(0xFFD98E04)
        Tone.DANGER -> if (dark) Color(0xFFF08A82) else Color(0xFFC8372D)
        Tone.SUCCESS -> if (dark) Color(0xFF86D49B) else Color(0xFF2E8B57)
        Tone.MUTED -> if (dark) Color(0xFF9A9388) else Color(0xFF8D877D)
    }

    private fun lightTone(tone: Tone): ToneColors = when (tone) {
        Tone.NEUTRAL -> ToneColors(Color(0xFFECE6DA), Color(0xFF4A4339))
        Tone.ACCENT -> ToneColors(Color(0xFFF3E4D0), Color(0xFF5E3F1E))
        Tone.INFO -> ToneColors(Color(0xFFDDEAF8), Color(0xFF1F4E80))
        Tone.WARNING -> ToneColors(Color(0xFFFFEBC2), Color(0xFF6B4300))
        Tone.DANGER -> ToneColors(Color(0xFFFADAD6), Color(0xFF8C1D14))
        Tone.SUCCESS -> ToneColors(Color(0xFFD7F0E0), Color(0xFF14573A))
        Tone.MUTED -> ToneColors(Color(0xFFE6E3DD), Color(0xFF5C574F))
    }

    private fun darkTone(tone: Tone): ToneColors = when (tone) {
        Tone.NEUTRAL -> ToneColors(Color(0xFF38332C), Color(0xFFD6CFC4))
        Tone.ACCENT -> ToneColors(Color(0xFF4A3724), Color(0xFFF0D3AE))
        Tone.INFO -> ToneColors(Color(0xFF223A55), Color(0xFFBBD6F5))
        Tone.WARNING -> ToneColors(Color(0xFF5A4410), Color(0xFFFFDE94))
        Tone.DANGER -> ToneColors(Color(0xFF5E2420), Color(0xFFFFB4AB))
        Tone.SUCCESS -> ToneColors(Color(0xFF1F4A33), Color(0xFFA9E5BE))
        Tone.MUTED -> ToneColors(Color(0xFF33302B), Color(0xFFB7B0A5))
    }
}

/** App theme: Material 3 with a warm "bean" palette; follows the system dark mode. */
@Composable
fun AgentNestTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        content = content,
    )
}

/** True when the dark colour scheme is active. */
@Composable
fun isDarkTheme(): Boolean = isSystemInDarkTheme()
