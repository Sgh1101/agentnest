package dev.agentnest.app.ui.approvals

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import dev.agentnest.app.ui.S
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch

/** How long the button must be held (docs/android.md 2.2: "길게 누르기 1.5초"). */
const val HOLD_MILLIS: Int = 1500

/**
 * A button that only fires after being held for [HOLD_MILLIS]; a fill sweeps across while holding and resets when the
 * finger lifts early. This (and the re-confirm dialog) is the real extra-confirmation gate for risky approvals: a
 * single tap can never trigger [onConfirmed].
 *
 * Accessibility: a screen reader activates a control with a double tap, which cannot "hold". The button therefore
 * exposes a click action (only through accessibility services; touch input still requires the hold) that opens an
 * explicit confirmation dialog instead.
 */
@Composable
fun HoldToConfirmButton(
    label: String,
    enabled: Boolean,
    onConfirmed: () -> Unit,
    modifier: Modifier = Modifier,
    holdMillis: Int = HOLD_MILLIS,
) {
    val progress = remember { Animatable(0f) }
    var a11yConfirm by remember { mutableStateOf(false) }
    val latest by rememberUpdatedState(onConfirmed)
    val fill = MaterialTheme.colorScheme.primary
    // Enabled: a visible outline plus a pale track, so it does not read as a disabled button; the sweep is translucent
    // so the label stays readable while it fills.
    val track = if (enabled) fill.copy(alpha = 0.14f) else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.12f)
    val borderColor = if (enabled) fill else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.12f)
    val shape = RoundedCornerShape(24.dp)

    Box(
        modifier = modifier
            .heightIn(min = 48.dp)
            .clip(shape)
            .background(track, shape)
            .drawBehind {
                drawRect(fill.copy(alpha = 0.45f), size = Size(size.width * progress.value, size.height))
            }
            .border(1.5.dp, borderColor, shape)
            .semantics {
                contentDescription = "$label. ${holdMillis / 1000f}초 동안 길게 누르세요"
                if (enabled) {
                    onClick(label = S.HOLD_A11Y_ACTION) {
                        a11yConfirm = true
                        true
                    }
                }
            }
            .pointerInput(enabled) {
                if (enabled) {
                    detectTapGestures(
                        onPress = {
                            coroutineScope {
                                val job = launch {
                                    progress.snapTo(0f)
                                    progress.animateTo(1f, tween(durationMillis = holdMillis, easing = LinearEasing))
                                    latest()
                                }
                                tryAwaitRelease()
                                job.cancel()
                                progress.snapTo(0f)
                            }
                        },
                    )
                }
            },
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f),
            modifier = Modifier.padding(horizontal = 20.dp, vertical = 12.dp),
        )
    }
    if (a11yConfirm) {
        AlertDialog(
            onDismissRequest = { a11yConfirm = false },
            title = { Text(label) },
            text = { Text(S.HOLD_A11Y_BODY) },
            confirmButton = {
                TextButton(onClick = {
                    a11yConfirm = false
                    latest()
                }) { Text(S.CONFIRM) }
            },
            dismissButton = { TextButton(onClick = { a11yConfirm = false }) { Text(S.CANCEL) } },
        )
    }
}
