package dev.agentnest.app.shots

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.test.junit4.ComposeContentTestRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeUp
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.agentnest.app.approval.AuthAvailability
import dev.agentnest.app.ui.AgentNestRoot
import dev.agentnest.core.nest.NestState
import org.junit.Test
import org.junit.runner.RunWith
import dev.agentnest.app.data.PairedInfo

/** Home in every situation, rendered through the real [AgentNestRoot] (bottom bar, insets, theme). */
@RunWith(AndroidJUnit4::class)
class HomeShotTest : ShotBase() {
    private val sw = Phone.SMALL_W
    private val sh = Phone.SMALL_H
    private val lw = Phone.LARGE_W
    private val lh = Phone.LARGE_H

    @Composable
    private fun Root(
        nest: NestState,
        paired: PairedInfo? = SD.PAIRED,
        auth: AuthAvailability = AuthAvailability.READY,
        keyReset: Boolean = false,
    ) {
        val c = remember { FakeAppController(nest, paired = paired, auth = auth, keyReset = keyReset) }
        AgentNestRoot(c)
    }

    private val scrollDown: ComposeContentTestRule.() -> Unit = {
        onNodeWithTag(FRAME_TAG).performTouchInput { swipeUp() }
    }

    @Test
    fun idleAndUnpaired() {
        shoot("home_idle_L", lw, lh) { Root(SD.idle) }
        shoot("home_idle_S", sw, sh) { Root(SD.idle) }
        shoot("home_unpaired_S", sw, sh) { Root(SD.unpaired, paired = null) }
        shoot("home_unpaired_L_dark", lw, lh, dark = true) { Root(SD.unpaired, paired = null) }
        shoot("home_key_reset_S", sw, sh) { Root(SD.unpaired, paired = null, keyReset = true) }
    }

    @Test
    fun working() {
        shoot("home_working_L", lw, lh) { Root(SD.working) }
        shoot("home_working_S", sw, sh) { Root(SD.working) }
        shoot("home_working_L_dark", lw, lh, dark = true) { Root(SD.working) }
        shoot("home_working_weak_S", sw, sh) { Root(SD.workingWeak) }
        shoot("home_reviewing_S", sw, sh) { Root(SD.reviewing) }
        shoot("home_testing_S", sw, sh) { Root(SD.testing) }
        shoot("home_completed_S", sw, sh) { Root(SD.completed) }
        shoot("home_completed_S_dark", sw, sh, dark = true) { Root(SD.completed) }
    }

    @Test
    fun approval() {
        shoot("home_approval_L", lw, lh) { Root(SD.approval) }
        shoot("home_approval_S", sw, sh) { Root(SD.approval) }
        shoot("home_approval_S_dark", sw, sh, dark = true) { Root(SD.approval) }
        shoot("home_approval_S_font13", sw, sh, fontScale = 1.3f) { Root(SD.approval) }
        shoot("home_approval_S_font13_scrolled", sw, sh, fontScale = 1.3f, before = scrollDown) { Root(SD.approval) }
        shoot("home_approval_no_lock_S", sw, sh) { Root(SD.approval, auth = AuthAvailability.NOT_ENROLLED) }
        shoot("home_input_S", sw, sh) { Root(SD.awaitingInput) }
    }

    @Test
    fun error() {
        shoot("home_error_S", sw, sh) { Root(SD.error) }
        shoot("home_error_L_dark", lw, lh, dark = true) { Root(SD.error) }
        shoot("home_error_S_font13", sw, sh, fontScale = 1.3f) { Root(SD.error) }
        shoot("home_session_lost_S", sw, sh) { Root(SD.sessionLost) }
    }

    @Test
    fun linkProblems() {
        shoot("home_reconnecting_S", sw, sh) { Root(SD.reconnectingCached) }
        shoot("home_reconnecting_S_dark", sw, sh, dark = true) { Root(SD.reconnectingCached) }
        shoot("home_offline_S", sw, sh) { Root(SD.offline) }
        shoot("home_unreachable_S", sw, sh) { Root(SD.unreachable) }
        shoot("home_unreachable_S_font13", sw, sh, fontScale = 1.3f) { Root(SD.unreachable) }
        shoot("home_needs_repair_S", sw, sh) { Root(SD.needsRepair) }
    }

    @Test
    fun multipleSessions() {
        shoot("home_multi_L", lw, lh) { Root(SD.multi) }
        shoot("home_multi_S", sw, sh) { Root(SD.multi) }
        shoot("home_multi_S_scrolled", sw, sh, before = scrollDown) { Root(SD.multi) }
        shoot("home_multi_S_dark", sw, sh, dark = true) { Root(SD.multi) }
        shoot("home_multi_S_font13", sw, sh, fontScale = 1.3f) { Root(SD.multi) }
    }
}
