package dev.agentnest.app.shots

import android.content.res.Configuration
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color as AColor
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.compose.foundation.layout.requiredSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.junit4.ComposeContentTestRule
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.test.platform.app.InstrumentationRegistry
import dev.agentnest.app.ui.theme.AgentNestTheme
import org.junit.After
import org.junit.Before
import org.junit.Rule
import java.io.File
import java.io.FileOutputStream

/** Where the PNGs go and how they leave the device (the app is uninstalled when the test run ends). */
object ShotFiles {
    private const val TAG = "AgentNestShots"
    private const val PUBLIC_DIR = "/data/local/tmp/agentnest-shots"

    val dir: File by lazy {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val base = ctx.getExternalFilesDir("screenshots") ?: File(ctx.filesDir, "screenshots")
        base.mkdirs()
        base
    }

    fun save(name: String, bitmap: Bitmap) {
        val bytes = java.io.ByteArrayOutputStream().also { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }.toByteArray()
        FileOutputStream(File(dir, "$name.png")).use { it.write(bytes) }
        Log.i(TAG, "saved $name ${bitmap.width}x${bitmap.height} ${bytes.size} bytes")
        pushToShell("$name.png", bytes)
    }

    fun note(line: String) {
        Log.i(TAG, line)
        File(dir, "log.txt").appendText(line + "\n")
        pushToShell("log.txt", File(dir, "log.txt").readBytes())
    }

    /**
     * Streams the bytes into [PUBLIC_DIR] through a shell process (`dd of=file`). Gradle uninstalls the app when the run
     * ends, which deletes the app's own storage, and the shell cannot read the app's external files directory on
     * recent Android versions; /data/local/tmp survives and `adb pull` can read it.
     */
    private fun pushToShell(fileName: String, bytes: ByteArray) {
        try {
            val ui = InstrumentationRegistry.getInstrumentation().uiAutomation
            // The command string is split on spaces (no shell, no quotes), hence plain `mkdir` and `dd of=`.
            ParcelFileDescriptor.AutoCloseInputStream(ui.executeShellCommand("mkdir -p $PUBLIC_DIR")).use { it.readBytes() }
            val fds = ui.executeShellCommandRw("dd of=$PUBLIC_DIR/$fileName")
            ParcelFileDescriptor.AutoCloseOutputStream(fds[1]).use { it.write(bytes) }
            ParcelFileDescriptor.AutoCloseInputStream(fds[0]).use { it.readBytes() }
        } catch (t: Throwable) {
            Log.e(TAG, "pushToShell failed for $fileName: $t")
        }
    }
}

/** One captured frame: a fixed-size "phone" with its own density / dark mode / font scale. */
class Scene(
    val id: Int,
    val width: Int,
    val height: Int,
    val dark: Boolean,
    val fontScale: Float,
    val content: @Composable () -> Unit,
)

const val FRAME_TAG = "shot-frame"

@Composable
private fun SceneFrame(s: Scene) {
    val base = LocalConfiguration.current
    val cfg = Configuration(base).apply {
        uiMode = (uiMode and Configuration.UI_MODE_NIGHT_MASK.inv()) or
            (if (s.dark) Configuration.UI_MODE_NIGHT_YES else Configuration.UI_MODE_NIGHT_NO)
        fontScale = s.fontScale
    }
    val density = LocalDensity.current
    CompositionLocalProvider(
        LocalConfiguration provides cfg,
        LocalDensity provides Density(density.density, s.fontScale),
    ) {
        AgentNestTheme {
            Surface(
                modifier = Modifier.requiredSize(s.width.dp, s.height.dp).testTag(FRAME_TAG),
                color = MaterialTheme.colorScheme.background,
                contentColor = MaterialTheme.colorScheme.onBackground,
            ) { s.content() }
        }
    }
}

/** Small phone and a Pixel-class phone, in dp. */
object Phone {
    const val SMALL_W = 360
    const val SMALL_H = 800
    const val LARGE_W = 411
    const val LARGE_H = 914
}

abstract class ShotBase {
    @get:Rule
    val compose: ComposeContentTestRule = createComposeRule()

    private val scene = mutableStateOf<Scene?>(null)
    private var counter = 0
    private val failures = ArrayList<String>()

    @Before
    fun mount() {
        compose.setContent {
            val s = scene.value
            if (s != null) key(s.id) { SceneFrame(s) }
        }
    }

    @After
    fun finish() {
        if (failures.isNotEmpty()) throw AssertionError("screenshots failed: " + failures.joinToString("; "))
    }

    /**
     * Renders [content] in a [width] x [height] dp frame and writes `[name].png`. Scenes with an endless animation
     * (progress indicators) must use [manualClock] = true: the clock is then advanced by hand and never "idle".
     * A failing scene is recorded and the run continues, so one bad screen never hides the others.
     */
    fun shoot(
        name: String,
        width: Int = Phone.LARGE_W,
        height: Int = Phone.LARGE_H,
        dark: Boolean = false,
        fontScale: Float = 1f,
        manualClock: Boolean = false,
        before: (ComposeContentTestRule.() -> Unit)? = null,
        dialog: Boolean = false,
        content: @Composable () -> Unit,
    ) {
        try {
            val bmp = render(width, height, dark, fontScale, manualClock, before, dialog, content)
            ShotFiles.save(name, bmp)
        } catch (t: Throwable) {
            val msg = "$name: ${t::class.java.simpleName}: ${t.message?.take(300)}"
            ShotFiles.note("FAILED $msg")
            failures += msg
        }
    }

    fun render(
        width: Int,
        height: Int,
        dark: Boolean,
        fontScale: Float,
        manualClock: Boolean,
        before: (ComposeContentTestRule.() -> Unit)?,
        dialog: Boolean,
        content: @Composable () -> Unit,
    ): Bitmap {
        compose.mainClock.autoAdvance = !manualClock
        show(width, height, dark, fontScale, content)
        if (manualClock) {
            compose.mainClock.advanceTimeBy(600)
        } else {
            compose.waitForIdle()
        }
        before?.invoke(compose)
        if (manualClock) compose.mainClock.advanceTimeBy(300) else compose.waitForIdle()
        val bmp = capture(dialog)
        compose.mainClock.autoAdvance = true
        return bmp
    }

    /** Swaps the frame content (state is reset: every scene gets a fresh composition). */
    fun show(width: Int, height: Int, dark: Boolean, fontScale: Float, content: @Composable () -> Unit) {
        SD.refreshNow()
        scene.value = Scene(++counter, width, height, dark, fontScale, content)
    }

    /** Copies the pixels of the current frame. */
    fun capture(dialog: Boolean = false): Bitmap {
        settle()
        val node = if (dialog) compose.onNode(isDialog()) else compose.onNodeWithTag(FRAME_TAG)
        val bmp = node.captureToImage().asAndroidBitmap()
        return bmp.copy(Bitmap.Config.ARGB_8888, false)
    }

    /** Lets the real view system draw the last composed frame before the pixels are copied. */
    fun settle() {
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()
        Thread.sleep(150)
    }

    /** Several bitmaps side by side with a gap, for animation strips and size comparisons. */
    fun strip(name: String, frames: List<Bitmap>, background: Int = AColor.WHITE) {
        val gap = 8
        val w = frames.sumOf { it.width } + gap * (frames.size + 1)
        val h = frames.maxOf { it.height } + gap * 2
        val out = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(out)
        canvas.drawColor(background)
        var x = gap
        for (f in frames) {
            canvas.drawBitmap(f, x.toFloat(), gap.toFloat(), null)
            x += f.width + gap
        }
        ShotFiles.save(name, out)
    }
}
