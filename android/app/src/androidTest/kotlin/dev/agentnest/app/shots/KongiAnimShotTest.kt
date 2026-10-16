package dev.agentnest.app.shots

import android.graphics.Bitmap
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.agentnest.app.character.KongiCanvas
import dev.agentnest.app.character.KongiSpec
import dev.agentnest.app.character.MotionLevel
import dev.agentnest.core.nest.Badge
import dev.agentnest.core.nest.KongiMood
import dev.agentnest.core.nest.TypingVariant
import org.junit.Test
import org.junit.runner.RunWith

/** Animation frames: the test clock is advanced by hand and four frames per mood are stitched into one strip. */
@RunWith(AndroidJUnit4::class)
class KongiAnimShotTest : ShotBase() {
    private fun frames(name: String, spec: KongiSpec, offsetsMs: List<Long>) {
        try {
            compose.mainClock.autoAdvance = false
            show(220, 220, dark = false, fontScale = 1f) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    KongiCanvas(spec = spec, motion = MotionLevel.FULL, active = true, dimension = 200.dp)
                }
            }
            // Compose the scene and let the character's frame loop take its first frame (that frame starts the clock).
            repeat(3) { compose.mainClock.advanceTimeByFrame() }
            val shots = ArrayList<Bitmap>()
            var last = 0L
            for (t in offsetsMs) {
                if (t > last) compose.mainClock.advanceTimeBy(t - last, ignoreFrameDuration = false)
                last = t
                shots += capture()
            }
            strip("kongi_anim_$name", shots)
        } catch (t: Throwable) {
            ShotFiles.note("FAILED kongi_anim_$name: ${t::class.java.simpleName}: ${t.message?.take(300)}")
        } finally {
            compose.mainClock.autoAdvance = true
        }
    }

    @Test
    fun animation() {
        frames("typing_strong", KongiSpec.of(KongiMood.TYPING, TypingVariant.FULL), listOf(0, 60, 120, 180))
        frames("typing_weak", KongiSpec.of(KongiMood.TYPING, TypingVariant.WEAK), listOf(0, 125, 250, 375))
        frames("celebrate", KongiSpec.of(KongiMood.CELEBRATE), listOf(0, 125, 250, 375))
        frames("raise_hand", KongiSpec.of(KongiMood.RAISE_HAND, badge = Badge.EXCLAMATION), listOf(0, 150, 300, 450))
        frames("tools", KongiSpec.of(KongiMood.TOOLS), listOf(0, 125, 250, 375))
        frames("magnifier", KongiSpec.of(KongiMood.MAGNIFIER), listOf(0, 400, 800, 1200))
        frames("flustered", KongiSpec.of(KongiMood.FLUSTERED), listOf(0, 300, 600, 900))
        frames("sleepy", KongiSpec.of(KongiMood.SLEEPY), listOf(0, 500, 1000, 1500))
        frames("worried", KongiSpec.of(KongiMood.WORRIED), listOf(0, 350, 700, 1050))
        frames("blink_slow", KongiSpec.of(KongiMood.BLINK_SLOW), listOf(0, 750, 1500, 2250))
    }
}
