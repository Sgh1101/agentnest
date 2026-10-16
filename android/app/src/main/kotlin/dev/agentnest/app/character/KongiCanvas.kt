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
import androidx.compose.ui.graphics.lerp
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
    var rim: Stroke = Stroke(width = 1f)
    var outline: Stroke = Stroke(width = 1f)
    var kbHalo: Stroke = Stroke(width = 1f)
    var kbLine: Stroke = Stroke(width = 1f)
    var ringHalo: Stroke = Stroke(width = 1f)
    var ring: Stroke = Stroke(width = 1f)
    var wrenchHalo: Stroke = Stroke(width = 1f)
    var wrench: Stroke = Stroke(width = 1f)
    var question: Stroke = Stroke(width = 1f)

    fun update(u: Float) {
        if (u == unit) return
        unit = u
        thin = Stroke(width = 1.4f * u, cap = StrokeCap.Round)
        normal = Stroke(width = 2.0f * u, cap = StrokeCap.Round)
        rim = Stroke(width = 2.4f * u, cap = StrokeCap.Round)
        outline = Stroke(width = 1.1f * u)
        kbHalo = Stroke(width = 3.4f * u)
        kbLine = Stroke(width = 1.3f * u)
        ringHalo = Stroke(width = 5.2f * u)
        ring = Stroke(width = 2.6f * u)
        wrenchHalo = Stroke(width = 6f * u, cap = StrokeCap.Round)
        wrench = Stroke(width = 3.4f * u, cap = StrokeCap.Round)
        question = Stroke(width = 2.2f * u, cap = StrokeCap.Round)
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
    val palette = remember(spec.tone, dark) { KongiPalette.of(ToneTheme.solid(spec.tone, dark), ToneTheme.solid(dev.agentnest.app.ui.Tone.WARNING, dark), dark) }

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
        drawKongi(poseOut, palette, strokes)
    }
}

/**
 * Colours of one drawing. [ink] is for the face (drawn on the body, always dark), [prop] for held objects and floating
 * letters (drawn on the screen background, so it flips with the theme) with a [halo] of the opposite lightness so a
 * prop stays readable both over the body and over the background.
 */
private class KongiPalette(
    val body: Color,
    val bodyDark: Color,
    val bodyLight: Color,
    val ink: Color,
    val prop: Color,
    val halo: Color,
    val badge: Color,
) {
    companion object {
        fun of(body: Color, badge: Color, dark: Boolean) = KongiPalette(
            body = body,
            bodyDark = lerp(body, Color.Black, 0.22f),
            bodyLight = lerp(body, Color.White, 0.28f),
            ink = if (dark) Color(0xFF1B1713) else Color(0xFF2B2118),
            prop = if (dark) Color(0xFFF1E8DA) else Color(0xFF2B2118),
            halo = if (dark) Color(0xFF14110E) else Color(0xFFFFFFFF),
            badge = badge,
        )
    }
}

private const val SCALE = 1.1f

private fun DrawScope.drawKongi(p: KongiPose, c: KongiPalette, strokes: StrokeCache) {
    val u = size.minDimension / 100f
    val dx = p.bodyDx
    val dy = p.bodyDy
    val cx = KongiMotion.BODY_CX + dx

    // Shadow stays on the ground while the body bobs or jumps.
    drawOval(
        color = c.ink,
        topLeft = Offset((KongiMotion.BODY_CX - 22f) * u, 88f * u),
        size = Size(44f * u, 6f * u),
        alpha = 0.12f,
    )
    // The whole character is drawn 10 % larger around its middle: the face needs the room to read at 40-160 dp.
    val canvas = drawContext.canvas
    canvas.save()
    canvas.translate(50f * u, 62f * u)
    canvas.scale(SCALE, SCALE)
    canvas.translate(-50f * u, -62f * u)
    run {
        // Arms first (behind the body): every hand is joined to a shoulder, so nothing floats.
        arm(c, u, cx - 21f, 64f + dy, p.handLx + dx, p.handLy + dy)
        arm(c, u, cx + 21f, 64f + dy, p.handRx + dx, p.handRy + dy)

        // Body, a rim light on the upper left and, for happy moods, blush.
        drawOval(
            color = c.body,
            topLeft = Offset((cx - KongiMotion.BODY_RX) * u, (KongiMotion.BODY_CY - KongiMotion.BODY_RY + dy) * u),
            size = Size(KongiMotion.BODY_RX * 2f * u, KongiMotion.BODY_RY * 2f * u),
        )
        drawArc(
            color = Color.White,
            startAngle = 196f,
            sweepAngle = 54f,
            useCenter = false,
            topLeft = Offset((cx - 23f) * u, (KongiMotion.BODY_CY - 20.5f + dy) * u),
            size = Size(46f * u, 41f * u),
            style = strokes.rim,
            alpha = 0.4f,
        )
        if (p.mouthCurve > 0.05f || p.eyeHappy > 0.5f) {
            val blush = Color(0xFFFF7A70)
            drawCircle(blush, 3.4f * u, Offset((cx - 18f) * u, (KongiMotion.MOUTH_Y - 4f + dy) * u), alpha = 0.3f)
            drawCircle(blush, 3.4f * u, Offset((cx + 18f) * u, (KongiMotion.MOUTH_Y - 4f + dy) * u), alpha = 0.3f)
        }

        // The keyboard sits in front of the belly; the hands are drawn over it.
        if (p.prop == Prop.KEYBOARD) drawKeyboard(c, strokes, u, p.propX + dx, p.propY + dy)
        hand(c, strokes, u, p.handLx + dx, p.handLy + dy)
        hand(c, strokes, u, p.handRx + dx, p.handRy + dy)

        drawProp(p, c, strokes, dx, dy)
        drawEyes(p, c.ink, strokes, cx, dy)
        drawBrows(p, c.ink, cx, dy)
        drawMouth(p, c.ink, strokes, cx, dy)
        drawBadge(p, c.badge, strokes)
    }
    canvas.restore()
}

/** An arm: a thick rounded line from the shoulder to the hand, in a slightly darker body colour. */
private fun DrawScope.arm(c: KongiPalette, u: Float, sx: Float, sy: Float, hx: Float, hy: Float) {
    drawLine(c.bodyDark, Offset(sx * u, sy * u), Offset(hx * u, hy * u), strokeWidth = 7.2f * u, cap = StrokeCap.Round)
}

/** A hand: a lighter disc with a thin outline so it also reads when it lies on the body. */
private fun DrawScope.hand(c: KongiPalette, strokes: StrokeCache, u: Float, x: Float, y: Float) {
    drawCircle(c.bodyLight, KongiMotion.HAND_R * u, Offset(x * u, y * u))
    drawCircle(c.bodyDark, KongiMotion.HAND_R * u, Offset(x * u, y * u), style = strokes.outline)
}

private fun DrawScope.drawKeyboard(c: KongiPalette, strokes: StrokeCache, u: Float, x: Float, y: Float) {
    val w = 42f
    val h = 10f
    val tl = Offset((x - w / 2f) * u, (y - h / 2f) * u)
    drawRoundRect(c.halo, tl, Size(w * u, h * u), CornerRadius(2.4f * u), style = strokes.kbHalo, alpha = 0.7f)
    drawRoundRect(Color(0xFFEDE6DA), tl, Size(w * u, h * u), CornerRadius(2f * u))
    drawRoundRect(c.prop, tl, Size(w * u, h * u), CornerRadius(2f * u), style = strokes.kbLine)
    val key = Color(0xFF8A7C6A)
    for (row in 0..1) {
        for (col in 0..4) {
            drawRoundRect(
                key,
                Offset((x - w / 2f + 4.6f + col * 7.2f) * u, (y - h / 2f + 2.2f + row * 3.6f) * u),
                Size(5f * u, 2.2f * u),
                CornerRadius(0.6f * u),
            )
        }
    }
}

/** A line with a thin halo underneath, so a dark prop stays visible on a dark background and vice versa. */
private fun DrawScope.haloLine(c: KongiPalette, u: Float, a: Offset, b: Offset, width: Float) {
    drawLine(c.halo, a * u, b * u, strokeWidth = (width + 2.4f) * u, cap = StrokeCap.Round, alpha = 0.7f)
    drawLine(c.prop, a * u, b * u, strokeWidth = width * u, cap = StrokeCap.Round)
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
                drawCircle(Color.White, 1.3f * u * scale, Offset((x - er * 0.3f) * u, y - er * 0.35f * u), alpha = 0.9f)
            }
        }
    }
}

private fun DrawScope.drawBrows(p: KongiPose, ink: Color, cx: Float, dy: Float) {
    if (p.brow < 0.05f) return
    val u = size.minDimension / 100f
    val y = (KongiMotion.EYE_Y - 9.5f + dy) * u
    // Inner ends higher than outer ends: the worried look.
    drawLine(ink, Offset((cx - 17f) * u, y + 3f * u), Offset((cx - 5f) * u, y - 1.5f * u), strokeWidth = 2.2f * u, cap = StrokeCap.Round, alpha = p.brow)
    drawLine(ink, Offset((cx + 17f) * u, y + 3f * u), Offset((cx + 5f) * u, y - 1.5f * u), strokeWidth = 2.2f * u, cap = StrokeCap.Round, alpha = p.brow)
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
        drawLine(ink, Offset((cx - 4f) * u, y * u), Offset((cx + 4f) * u, y * u), strokeWidth = 1.8f * u, cap = StrokeCap.Round)
        return
    }
    val h = 5f * (if (c < 0f) -c else c)
    if (c > 0f) {
        // Smile: lower half of an ellipse.
        drawArc(ink, 0f, 180f, false, Offset((cx - 6f) * u, (y - h) * u), Size(12f * u, 2f * h * u), style = strokes.normal)
    } else {
        // Frown: upper half of an ellipse, placed lower.
        drawArc(ink, 180f, 180f, false, Offset((cx - 5f) * u, y * u), Size(10f * u, 2f * h * u), style = strokes.normal)
    }
}

private fun DrawScope.drawProp(p: KongiPose, c: KongiPalette, strokes: StrokeCache, dx: Float, dy: Float) {
    val u = size.minDimension / 100f
    when (p.prop) {
        Prop.MAGNIFIER -> {
            val x = p.propX + dx
            val y = p.propY + dy
            drawLine(c.halo, Offset((x + 6.6f) * u, (y + 6.6f) * u), Offset((x + 15f) * u, (y + 15f) * u), strokeWidth = 6f * u, cap = StrokeCap.Round, alpha = 0.7f)
            drawLine(c.prop, Offset((x + 6.6f) * u, (y + 6.6f) * u), Offset((x + 15f) * u, (y + 15f) * u), strokeWidth = 3.4f * u, cap = StrokeCap.Round)
            drawCircle(Color.White, 10f * u, Offset(x * u, y * u), alpha = 0.3f)
            drawCircle(c.halo, 10f * u, Offset(x * u, y * u), style = strokes.ringHalo, alpha = 0.7f)
            drawCircle(c.prop, 10f * u, Offset(x * u, y * u), style = strokes.ring)
        }
        Prop.WRENCH -> {
            val rad = Math.toRadians((-90f + p.propAngle).toDouble())
            val px = p.propX + dx
            val py = p.propY + dy
            val len = 21f
            val tipX = px + len * cos(rad).toFloat()
            val tipY = py + len * sin(rad).toFloat()
            haloLine(c, u, Offset(px, py), Offset(tipX, tipY), 3.6f)
            // Open-ended head: a ring with a gap that faces away from the handle.
            val canvas = drawContext.canvas
            canvas.save()
            canvas.translate(tipX * u, tipY * u)
            canvas.rotate(p.propAngle)
            canvas.translate(-tipX * u, -tipY * u)
            val r = 5.6f * u
            val tl = Offset(tipX * u - r, tipY * u - r)
            drawArc(c.halo, -50f, 280f, false, tl, Size(2f * r, 2f * r), style = strokes.wrenchHalo, alpha = 0.7f)
            drawArc(c.prop, -50f, 280f, false, tl, Size(2f * r, 2f * r), style = strokes.wrench)
            canvas.restore()
            if (p.propPhase < 0.5f) {
                drawCircle(Color(0xFFFFC857), 1.7f * u, Offset((tipX + 8f) * u, (tipY - 3f) * u))
                drawCircle(Color(0xFFFFC857), 1.3f * u, Offset((tipX - 8f) * u, (tipY - 6f) * u))
                drawCircle(Color(0xFFFFC857), 1.1f * u, Offset((tipX + 5f) * u, (tipY - 10f) * u))
            }
        }
        Prop.SWEAT -> {
            val ph = p.propPhase
            val drop = Color(0xFF4FA3E0)
            drawOval(drop, Offset((74f + dx) * u, (38f + 24f * ph + dy) * u), Size(5f * u, 7.5f * u), alpha = 1f - ph * ph)
            val ph2 = (ph + 0.5f) % 1f
            drawOval(drop, Offset((21f + dx) * u, (38f + 24f * ph2 + dy) * u), Size(4f * u, 6f * u), alpha = 1f - ph2 * ph2)
        }
        Prop.ZZZ -> {
            drawZ(c, 66f, 44f, p.propPhase, u)
            drawZ(c, 75f, 34f, (p.propPhase + 0.5f) % 1f, u)
        }
        Prop.KEYBOARD, Prop.HAND, Prop.NONE -> Unit
    }
}

/** A floating "Z" built from three lines: rises and fades as [phase] goes 0 -> 1. */
private fun DrawScope.drawZ(c: KongiPalette, x: Float, y: Float, phase: Float, u: Float) {
    val s = 6f + 4f * phase
    val top = y - 16f * phase
    val alpha = (1f - phase * phase).coerceIn(0f, 1f)
    zLine(c, u, x, top, x + s, top, alpha)
    zLine(c, u, x + s, top, x, top + s, alpha)
    zLine(c, u, x, top + s, x + s, top + s, alpha)
}

private fun DrawScope.zLine(c: KongiPalette, u: Float, x1: Float, y1: Float, x2: Float, y2: Float, alpha: Float) {
    val from = Offset(x1 * u, y1 * u)
    val to = Offset(x2 * u, y2 * u)
    drawLine(c.halo, from, to, strokeWidth = 3.4f * u, cap = StrokeCap.Round, alpha = alpha * 0.6f)
    drawLine(c.prop, from, to, strokeWidth = 1.9f * u, cap = StrokeCap.Round, alpha = alpha)
}

/** The "!" / "?" bubble above the head, drawn from circles, lines and arcs (no text). */
private fun DrawScope.drawBadge(p: KongiPose, badgeColor: Color, strokes: StrokeCache) {
    if (p.badge == Badge.NONE) return
    val u = size.minDimension / 100f
    val r = 8.5f * p.badgeScale
    drawCircle(badgeColor, r * u, Offset(50f * u, 17f * u))
    val glyph = Color.White
    if (p.badge == Badge.EXCLAMATION) {
        drawLine(glyph, Offset(50f * u, 11f * u), Offset(50f * u, 17.5f * u), strokeWidth = 2.8f * u, cap = StrokeCap.Round)
        drawCircle(glyph, 1.5f * u, Offset(50f * u, 21.4f * u))
    } else {
        drawArc(
            color = glyph,
            startAngle = 180f,
            sweepAngle = 270f,
            useCenter = false,
            topLeft = Offset(46.4f * u, 11.6f * u),
            size = Size(7.2f * u, 7.2f * u),
            style = strokes.question,
        )
        drawCircle(glyph, 1.4f * u, Offset(50f * u, 22.2f * u))
    }
}
