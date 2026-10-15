package dev.agentnest.app.character

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import dev.agentnest.app.ui.theme.ToneTheme
import dev.agentnest.app.ui.theme.isDarkTheme
import dev.agentnest.core.nest.Badge
import kotlin.math.cos
import kotlin.math.sin

/** Caches [Stroke] objects per drawing scale so drawing allocates nothing per frame. */
private class StrokeCache {
    private var unit = -1f
    var thin: Stroke = Stroke(width = 1f)
    var normal: Stroke = Stroke(width = 1f)

    fun update(u: Float) {
        if (u == unit) return
        unit = u
        thin = Stroke(width = 1.4f * u, cap = StrokeCap.Round)
        normal = Stroke(width = 2.0f * u, cap = StrokeCap.Round)
    }
}

/**
 * The character (docs/character.md 3): one Canvas, state-driven, no bitmaps or text, a few dozen draw calls per
 * frame. [motion] is [MotionLevel.NONE] when the user turned animations off or the system animation scale is 0 (a
 * still pose is drawn and nothing is scheduled); [active] is false while the app is not visible, which stops the frame
 * loop. The frame time lives in a `MutableLongState` that is only read in the draw phase, so animating never
 * recomposes anything.
 */
@Composable
fun KongiCanvas(
    spec: KongiSpec,
    motion: MotionLevel,
    active: Boolean,
    modifier: Modifier = Modifier,
    dimension: Dp = 160.dp,
) {
    val dark = isDarkTheme()
    val bodyColor = ToneTheme.solid(spec.tone, dark)
    val ink = if (dark) Color(0xFF1B1713) else Color(0xFF2B2118)
    val badgeColor = ToneTheme.solid(dev.agentnest.app.ui.Tone.WARNING, dark)

    var timeMs by remember { mutableLongStateOf(0L) }
    var switchAtMs by remember { mutableLongStateOf(0L) }
    var pendingSwitch by remember { mutableStateOf(true) }
    var current by remember { mutableStateOf(spec) }
    var previous by remember { mutableStateOf<KongiSpec?>(null) }

    val animate = active && motion != MotionLevel.NONE

    // A new mood: remember the old one for the 300 ms cross-fade and restart the one-shot clock on the next frame.
    LaunchedEffect(spec) {
        if (spec != current) {
            previous = current
            current = spec
            pendingSwitch = true
        }
    }

    LaunchedEffect(animate, motion) {
        if (!animate) return@LaunchedEffect
        val minFrameMs = if (motion == MotionLevel.LOW) 33L else 0L
        var last = 0L
        while (true) {
            withFrameNanos { nanos ->
                val ms = nanos / 1_000_000L
                if (pendingSwitch) {
                    switchAtMs = ms
                    pendingSwitch = false
                }
                if (ms - last >= minFrameMs) {
                    last = ms
                    timeMs = ms
                }
            }
        }
    }

    val poseA = remember { KongiPose() }
    val poseB = remember { KongiPose() }
    val poseOut = remember { KongiPose() }
    val strokes = remember { StrokeCache() }

    Canvas(
        modifier = modifier
            .size(dimension)
            .semantics { contentDescription = spec.description },
    ) {
        val t = timeMs
        val cur = current
        val prev = previous
        val elapsed = t - switchAtMs
        val fade = if (prev == null || !animate) 1f else (elapsed.toFloat() / KongiMotion.TRANSITION_MS).coerceIn(0f, 1f)
        if (fade < 1f && prev != null) {
            KongiMotion.pose(prev, motion, t, KongiMotion.JUMP_MS, poseA)
            KongiMotion.pose(cur, motion, t, elapsed, poseB)
            KongiMotion.blend(poseA, poseB, fade, poseOut)
        } else {
            KongiMotion.pose(cur, motion, t, elapsed, poseOut)
        }
        strokes.update(this.size.minDimension / 100f)
        drawKongi(poseOut, bodyColor, ink, badgeColor, strokes)
    }
}

private fun DrawScope.drawKongi(p: KongiPose, body: Color, ink: Color, badgeColor: Color, strokes: StrokeCache) {
    val u = size.minDimension / 100f
    val dx = p.bodyDx
    val dy = p.bodyDy
    val cx = KongiMotion.BODY_CX + dx

    // Shadow stays on the ground while the body bobs or jumps.
    drawOval(
        color = ink,
        topLeft = Offset((KongiMotion.BODY_CX - 22f) * u, 88f * u),
        size = Size(44f * u, 6f * u),
        alpha = 0.12f,
    )
    // Body and a soft highlight.
    drawOval(
        color = body,
        topLeft = Offset((cx - KongiMotion.BODY_RX) * u, (KongiMotion.BODY_CY - KongiMotion.BODY_RY + dy) * u),
        size = Size(KongiMotion.BODY_RX * 2f * u, KongiMotion.BODY_RY * 2f * u),
    )
    drawOval(
        color = Color.White,
        topLeft = Offset((cx - 16f) * u, (KongiMotion.BODY_CY - 19f + dy) * u),
        size = Size(14f * u, 8f * u),
        alpha = 0.22f,
    )
    // Hands travel with the body (so a jump does not detach them).
    drawCircle(body, KongiMotion.HAND_R * u, Offset((p.handLx + dx) * u, (p.handLy + dy) * u))
    drawCircle(body, KongiMotion.HAND_R * u, Offset((p.handRx + dx) * u, (p.handRy + dy) * u))

    drawProp(p, ink, strokes, dx, dy)
    drawEyes(p, ink, strokes, cx, dy)
    drawBrows(p, ink, cx, dy)
    drawMouth(p, ink, strokes, cx, dy)
    drawBadge(p, badgeColor, strokes)
}

private fun DrawScope.drawEyes(p: KongiPose, ink: Color, strokes: StrokeCache, cx: Float, dy: Float) {
    val u = size.minDimension / 100f
    val y = (KongiMotion.EYE_Y + dy) * u
    val r = KongiMotion.EYE_R
    for (side in 0..1) {
        val x = (if (side == 0) cx - KongiMotion.EYE_DX else cx + KongiMotion.EYE_DX) + p.eyeShake
        val open = if (side == 0) p.eyeOpenL else p.eyeOpenR
        val scale = if (side == 0) p.eyeScaleL else p.eyeScaleR
        val er = r * scale
        if (p.eyeHappy > 0.5f) {
            // Happy eye: an upward arc.
            drawArc(
                color = ink,
                startAngle = 180f,
                sweepAngle = 180f,
                useCenter = false,
                topLeft = Offset((x - er) * u, y - er * u + 1.5f * u),
                size = Size(2f * er * u, 2f * er * u),
                style = strokes.normal,
            )
        } else if (open < 0.12f) {
            // Closed eye: a short flat line.
            drawLine(ink, Offset((x - er) * u, y), Offset((x + er) * u, y), strokeWidth = 2f * u, cap = StrokeCap.Round)
        } else {
            val h = 2f * er * open
            drawOval(ink, Offset((x - er + p.pupilDx * 0.3f) * u, y - h / 2f * u + p.pupilDy * 0.4f * u), Size(2f * er * u, h * u))
            if (open > 0.5f) {
                drawCircle(Color.White, 1.1f * u * scale, Offset((x - er * 0.3f) * u, y - er * 0.35f * u), alpha = 0.85f)
            }
        }
    }
}

private fun DrawScope.drawBrows(p: KongiPose, ink: Color, cx: Float, dy: Float) {
    if (p.brow < 0.05f) return
    val u = size.minDimension / 100f
    val y = (KongiMotion.EYE_Y - 9f + dy) * u
    // Inner ends higher than outer ends: the worried look.
    drawLine(ink, Offset((cx - 16f) * u, y + 2.5f * u), Offset((cx - 5f) * u, y - 1.5f * u), strokeWidth = 1.8f * u, cap = StrokeCap.Round, alpha = p.brow)
    drawLine(ink, Offset((cx + 16f) * u, y + 2.5f * u), Offset((cx + 5f) * u, y - 1.5f * u), strokeWidth = 1.8f * u, cap = StrokeCap.Round, alpha = p.brow)
}

private fun DrawScope.drawMouth(p: KongiPose, ink: Color, strokes: StrokeCache, cx: Float, dy: Float) {
    val u = size.minDimension / 100f
    val y = (KongiMotion.MOUTH_Y + dy)
    if (p.mouthOpen > 0.05f) {
        val w = 7f + 5f * p.mouthOpen
        val h = 3f + 6f * p.mouthOpen
        drawOval(ink, Offset((cx - w / 2f) * u, (y - h / 2f + 1f) * u), Size(w * u, h * u))
        return
    }
    val c = p.mouthCurve
    if (c > -0.08f && c < 0.08f) {
        drawLine(ink, Offset((cx - 4f) * u, y * u), Offset((cx + 4f) * u, y * u), strokeWidth = 1.6f * u, cap = StrokeCap.Round)
        return
    }
    val h = 5f * (if (c < 0f) -c else c)
    if (c > 0f) {
        // Smile: lower half of an ellipse.
        drawArc(ink, 0f, 180f, false, Offset((cx - 6f) * u, (y - h) * u), Size(12f * u, 2f * h * u), style = strokes.thin)
    } else {
        // Frown: upper half of an ellipse, placed lower.
        drawArc(ink, 180f, 180f, false, Offset((cx - 5f) * u, y * u), Size(10f * u, 2f * h * u), style = strokes.thin)
    }
}

private fun DrawScope.drawProp(p: KongiPose, ink: Color, strokes: StrokeCache, dx: Float, dy: Float) {
    val u = size.minDimension / 100f
    when (p.prop) {
        Prop.KEYBOARD -> {
            drawRoundRect(
                color = ink,
                topLeft = Offset((p.propX + dx - 18f) * u, (p.propY + dy - 4f) * u),
                size = Size(36f * u, 8f * u),
                cornerRadius = CornerRadius(2f * u),
                alpha = 0.85f,
            )
            drawLine(Color.White, Offset((p.propX + dx - 14f) * u, (p.propY + dy) * u), Offset((p.propX + dx + 14f) * u, (p.propY + dy) * u), strokeWidth = 1.2f * u, alpha = 0.45f)
        }
        Prop.MAGNIFIER -> {
            val x = p.propX + dx
            val y = p.propY + dy
            drawCircle(Color.White, 9f * u, Offset(x * u, y * u), alpha = 0.25f)
            drawCircle(ink, 9f * u, Offset(x * u, y * u), style = strokes.normal)
            drawLine(ink, Offset((x + 6.4f) * u, (y + 6.4f) * u), Offset((x + 13f) * u, (y + 13f) * u), strokeWidth = 2.6f * u, cap = StrokeCap.Round)
        }
        Prop.WRENCH -> {
            val rad = Math.toRadians((-90f + p.propAngle).toDouble())
            val px = p.propX + dx
            val py = p.propY + dy
            val tipX = px + 18f * cos(rad).toFloat()
            val tipY = py + 18f * sin(rad).toFloat()
            drawLine(ink, Offset(px * u, py * u), Offset(tipX * u, tipY * u), strokeWidth = 3f * u, cap = StrokeCap.Round)
            drawCircle(ink, 4f * u, Offset(tipX * u, tipY * u), style = strokes.normal)
            if (p.propPhase < 0.5f) {
                drawCircle(Color(0xFFFFC857), 1.3f * u, Offset((tipX + 5f) * u, (tipY - 3f) * u))
                drawCircle(Color(0xFFFFC857), 1.0f * u, Offset((tipX - 5f) * u, (tipY - 5f) * u))
            }
        }
        Prop.SWEAT -> {
            val ph = p.propPhase
            val alpha = 1f - ph * ph
            drawOval(Color(0xFF6CB8F0), Offset((74f + dx) * u, (40f + 24f * ph + dy) * u), Size(4f * u, 6f * u), alpha = alpha)
            val ph2 = (ph + 0.5f) % 1f
            drawOval(Color(0xFF6CB8F0), Offset((22f + dx) * u, (40f + 24f * ph2 + dy) * u), Size(3f * u, 5f * u), alpha = 1f - ph2 * ph2)
        }
        Prop.ZZZ -> {
            drawZ(ink, 66f, 42f, p.propPhase, u)
            drawZ(ink, 74f, 34f, (p.propPhase + 0.5f) % 1f, u)
        }
        Prop.HAND, Prop.NONE -> Unit
    }
}

/** A floating "Z" built from three lines: rises and fades as [phase] goes 0 -> 1. */
private fun DrawScope.drawZ(ink: Color, x: Float, y: Float, phase: Float, u: Float) {
    val s = 4f + 3f * phase
    val top = y - 14f * phase
    val alpha = 1f - phase
    drawLine(ink, Offset(x * u, top * u), Offset((x + s) * u, top * u), strokeWidth = 1.2f * u, alpha = alpha)
    drawLine(ink, Offset((x + s) * u, top * u), Offset(x * u, (top + s) * u), strokeWidth = 1.2f * u, alpha = alpha)
    drawLine(ink, Offset(x * u, (top + s) * u), Offset((x + s) * u, (top + s) * u), strokeWidth = 1.2f * u, alpha = alpha)
}

/** The "!" / "?" bubble above the head, drawn from circles, lines and arcs (no text). */
private fun DrawScope.drawBadge(p: KongiPose, badgeColor: Color, strokes: StrokeCache) {
    if (p.badge == Badge.NONE) return
    val u = size.minDimension / 100f
    val r = 8f * p.badgeScale
    drawCircle(badgeColor, r * u, Offset(50f * u, 17f * u))
    val glyph = Color.White
    if (p.badge == Badge.EXCLAMATION) {
        drawLine(glyph, Offset(50f * u, 11.5f * u), Offset(50f * u, 17.5f * u), strokeWidth = 2.4f * u, cap = StrokeCap.Round)
        drawCircle(glyph, 1.3f * u, Offset(50f * u, 21.2f * u))
    } else {
        drawArc(
            color = glyph,
            startAngle = 180f,
            sweepAngle = 270f,
            useCenter = false,
            topLeft = Offset(46.6f * u, 12f * u),
            size = Size(6.8f * u, 6.8f * u),
            style = strokes.thin,
        )
        drawCircle(glyph, 1.2f * u, Offset(50f * u, 22f * u))
    }
}
