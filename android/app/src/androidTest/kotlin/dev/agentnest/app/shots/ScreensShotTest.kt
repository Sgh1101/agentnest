package dev.agentnest.app.shots

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.ComposeContentTestRule
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeUp
import androidx.compose.ui.test.hasClickAction
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.agentnest.app.approval.AuthAvailability
import dev.agentnest.app.data.PairedInfo
import dev.agentnest.app.data.SettingsState
import dev.agentnest.app.pairing.PairingUiState
import dev.agentnest.app.ui.AgentNestRoot
import dev.agentnest.app.ui.S
import dev.agentnest.app.ui.agents.SessionDetailScreen
import dev.agentnest.app.ui.settings.DevicesScreen
import dev.agentnest.app.ui.settings.DiagnosticsScreen
import dev.agentnest.app.ui.settings.PairingScreen
import dev.agentnest.core.nest.NestState
import org.junit.Test
import org.junit.runner.RunWith

/** Tabs (through the real root) and the secondary screens: pairing, sessions, devices, diagnostics. */
@RunWith(AndroidJUnit4::class)
class ScreensShotTest : ShotBase() {
    private val sw = Phone.SMALL_W
    private val sh = Phone.SMALL_H
    private val lw = Phone.LARGE_W
    private val lh = Phone.LARGE_H

    @Composable
    private fun Root(
        nest: NestState,
        paired: PairedInfo? = SD.PAIRED,
        settings: SettingsState = SettingsState(animationsEnabled = true),
        auth: AuthAvailability = AuthAvailability.READY,
        notifications: Boolean = true,
    ) {
        val c = remember { FakeAppController(nest, settings = settings, paired = paired, auth = auth, notifications = notifications) }
        AgentNestRoot(c)
    }

    private fun tab(label: String): ComposeContentTestRule.() -> Unit = {
        onAllNodes(hasText(label) and isSelectable()).onFirst().performClick()
    }

    private val scrollDown: ComposeContentTestRule.() -> Unit = {
        onNodeWithTag(FRAME_TAG).performTouchInput { swipeUp() }
    }

    @Test
    fun agentsAndProjects() {
        shoot("agents_S", sw, sh, before = tab(S.TAB_AGENTS)) { Root(SD.multi) }
        shoot("agents_L_dark", lw, lh, dark = true, before = tab(S.TAB_AGENTS)) { Root(SD.multi) }
        shoot("agents_S_font13", sw, sh, fontScale = 1.3f, before = tab(S.TAB_AGENTS)) { Root(SD.multi) }
        shoot("agents_empty_S", sw, sh, before = tab(S.TAB_AGENTS)) { Root(SD.idle) }
        shoot("projects_S", sw, sh, before = tab(S.TAB_PROJECTS)) { Root(SD.multi) }
        shoot("projects_S_dark", sw, sh, dark = true, before = tab(S.TAB_PROJECTS)) { Root(SD.multi) }
        shoot("projects_empty_S", sw, sh, before = tab(S.TAB_PROJECTS)) { Root(SD.idle) }
    }

    @Test
    fun activity() {
        shoot("activity_S", sw, sh, before = tab(S.TAB_ACTIVITY)) { Root(SD.working) }
        shoot("activity_L_dark", lw, lh, dark = true, before = tab(S.TAB_ACTIVITY)) { Root(SD.working) }
        shoot("activity_S_font13", sw, sh, fontScale = 1.3f, before = tab(S.TAB_ACTIVITY)) { Root(SD.working) }
        shoot(
            "activity_errors_S", sw, sh,
            before = {
                tab(S.TAB_ACTIVITY)()
                onAllNodes(hasText("오류") and hasClickAction()).onFirst().performClick()
            },
        ) { Root(SD.error) }
        shoot("activity_empty_S", sw, sh, before = tab(S.TAB_ACTIVITY)) { Root(SD.idle) }
    }

    @Test
    fun settings() {
        shoot("settings_S", sw, sh, before = tab(S.TAB_SETTINGS)) { Root(SD.working) }
        shoot("settings_S_scrolled", sw, sh, before = { tab(S.TAB_SETTINGS)(); scrollDown() }) { Root(SD.working) }
        shoot("settings_L_dark", lw, lh, dark = true, before = tab(S.TAB_SETTINGS)) { Root(SD.working) }
        shoot("settings_S_font13", sw, sh, fontScale = 1.3f, before = tab(S.TAB_SETTINGS)) { Root(SD.working) }
        shoot(
            "settings_unpaired_S", sw, sh, before = tab(S.TAB_SETTINGS),
        ) { Root(SD.unpaired, paired = null, auth = AuthAvailability.NOT_ENROLLED, notifications = false) }
    }

    @Test
    fun sessionDetail() {
        shoot("session_detail_S", sw, sh) { Session(SD.working, SD.S1) }
        shoot("session_detail_S_dark", sw, sh, dark = true) { Session(SD.working, SD.S1) }
        shoot("session_detail_S_font13", sw, sh, fontScale = 1.3f) { Session(SD.working, SD.S1) }
        shoot("session_detail_error_L", lw, lh) { Session(SD.error, SD.S1) }
    }

    @Composable
    private fun Session(nest: NestState, key: String) {
        val c = remember { FakeAppController(nest) }
        SessionDetailScreen(key, nest, SD.NOW, c, onBack = {})
    }

    @Composable
    private fun Pairing(state: PairingUiState) {
        val c = remember { FakeAppController(SD.unpaired, paired = null, pairing = state) }
        PairingScreen(state, c, onBack = {}, onDone = {})
    }

    @Test
    fun pairing() {
        shoot("pairing_intro_S", sw, sh) { Pairing(PairingUiState.Idle) }
        shoot("pairing_intro_S_dark", sw, sh, dark = true) { Pairing(PairingUiState.Idle) }
        shoot("pairing_intro_S_font13", sw, sh, fontScale = 1.3f) { Pairing(PairingUiState.Idle) }
        shoot("pairing_scan_error_S", sw, sh) { Pairing(PairingUiState.ScanError("QR 코드를 읽지 못했어요. PC 화면의 QR이 맞는지 확인해 주세요.")) }
        shoot("pairing_connecting_S", sw, sh, manualClock = true) { Pairing(PairingUiState.Connecting("192.168.0.10")) }
        shoot("pairing_sas_S", sw, sh, manualClock = true) { Pairing(PairingUiState.ShowingSas("482915")) }
        shoot("pairing_sas_L_dark", lw, lh, dark = true, manualClock = true) { Pairing(PairingUiState.ShowingSas("482915")) }
        shoot("pairing_sas_S_font13", sw, sh, fontScale = 1.3f, manualClock = true) { Pairing(PairingUiState.ShowingSas("482915")) }
        shoot("pairing_done_S", sw, sh) { Pairing(PairingUiState.Done) }
        shoot("pairing_failed_S", sw, sh) { Pairing(PairingUiState.Failed("PC에서 연결을 거절했어요. 다시 시도해 주세요.")) }
    }

    @Test
    fun devicesAndDiagnostics() {
        shoot("devices_S", sw, sh) {
            val c = remember { FakeAppController(SD.working) }
            DevicesScreen(SD.PAIRED, c, onBack = {}, onUnpaired = {}, onRepaired = {})
        }
        shoot("devices_S_dark", sw, sh, dark = true) {
            val c = remember { FakeAppController(SD.working) }
            DevicesScreen(SD.PAIRED, c, onBack = {}, onUnpaired = {}, onRepaired = {})
        }
        shoot("diagnostics_S", sw, sh) { DiagnosticsScreen(SD.working, SD.PAIRED, SD.NOW, onBack = {}) }
        shoot("diagnostics_S_font13", sw, sh, fontScale = 1.3f) { DiagnosticsScreen(SD.working, SD.PAIRED, SD.NOW, onBack = {}) }
    }
}
