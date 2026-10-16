package dev.agentnest.app.shots

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.agentnest.app.character.KongiCanvas
import dev.agentnest.app.character.KongiSpec
import dev.agentnest.app.character.MotionLevel
import dev.agentnest.app.ui.common.ToneChip
import dev.agentnest.core.nest.Badge
import dev.agentnest.core.nest.KongiMood
import dev.agentnest.core.nest.TypingVariant
import org.junit.Test
import org.junit.runner.RunWith

/** The nine moods (eleven faces: typing has two variants, raise_hand two badges) as still frames. */
@RunWith(AndroidJUnit4::class)
class KongiShotTest : ShotBase() {
    companion object {
        val FACES: List<Pair<String, KongiSpec>> = listOf(
            "blink_slow" to KongiSpec.of(KongiMood.BLINK_SLOW),
            "typing_strong" to KongiSpec.of(KongiMood.TYPING, TypingVariant.FULL),
            "typing_weak" to KongiSpec.of(KongiMood.TYPING, TypingVariant.WEAK),
            "magnifier" to KongiSpec.of(KongiMood.MAGNIFIER),
            "tools" to KongiSpec.of(KongiMood.TOOLS),
            "raise_hand_excl" to KongiSpec.of(KongiMood.RAISE_HAND, badge = Badge.EXCLAMATION),
            "raise_hand_ques" to KongiSpec.of(KongiMood.RAISE_HAND, badge = Badge.QUESTION),
            "flustered" to KongiSpec.of(KongiMood.FLUSTERED),
            "celebrate" to KongiSpec.of(KongiMood.CELEBRATE),
            "sleepy" to KongiSpec.of(KongiMood.SLEEPY),
            "worried" to KongiSpec.of(KongiMood.WORRIED),
        )
    }

    @Composable
    private fun Cell(label: String, spec: KongiSpec, size: Int) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(4.dp)) {
            KongiCanvas(spec = spec, motion = MotionLevel.NONE, active = false, dimension = size.dp)
            ToneChip(label, spec.tone)
        }
    }

    @Test
    fun gallery() {
        for (dark in listOf(false, true)) {
            shoot("kongi_gallery_${if (dark) "dark" else "light"}", Phone.LARGE_W, 780, dark = dark) {
                Column(
                    modifier = Modifier.fillMaxSize().padding(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    FACES.chunked(3).forEach { row ->
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                            row.forEach { (label, spec) -> Cell(label, spec, 120) }
                        }
                    }
                }
            }
        }
    }

    @Test
    fun bigOnes() {
        for ((label, spec) in FACES) {
            shoot("kongi_big_$label", 360, 360) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { Cell(label, spec, 280) }
            }
        }
    }

    @Test
    fun darkBig() {
        // Dark theme: body colours change; check the worst contrast ones (muted / neutral) at full size.
        for (label in listOf("blink_slow", "sleepy", "worried", "raise_hand_excl")) {
            val spec = FACES.first { it.first == label }.second
            shoot("kongi_big_${label}_dark", 360, 360, dark = true) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { Cell(label, spec, 280) }
            }
        }
    }

    @Test
    fun sizes() {
        // The character as it appears at 160 dp (home), 96 dp, 64 dp and 40 dp.
        val spec = KongiSpec.of(KongiMood.TYPING, TypingVariant.FULL)
        val spec2 = KongiSpec.of(KongiMood.RAISE_HAND, badge = Badge.EXCLAMATION)
        shoot("kongi_sizes", Phone.LARGE_W, 400) {
            Column(modifier = Modifier.fillMaxSize().padding(8.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                for (s in listOf(spec, spec2)) {
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.Bottom) {
                        for (size in listOf(160, 96, 64, 40)) {
                            KongiCanvas(spec = s, motion = MotionLevel.NONE, active = false, dimension = size.dp)
                        }
                    }
                }
                Text("160 / 96 / 64 / 40 dp", style = MaterialTheme.typography.labelMedium)
            }
        }
    }
}
