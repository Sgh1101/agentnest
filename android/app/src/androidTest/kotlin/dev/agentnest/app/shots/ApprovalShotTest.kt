package dev.agentnest.app.shots

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.test.junit4.ComposeContentTestRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.down
import androidx.compose.ui.test.swipeUp
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.agentnest.app.approval.AuthAvailability
import dev.agentnest.app.ui.S
import dev.agentnest.app.ui.approvals.ApprovalDetailScreen
import dev.agentnest.app.ui.approvals.ApprovalHistoryScreen
import dev.agentnest.app.ui.approvals.ApprovalsScreen
import dev.agentnest.app.ui.approvals.ExtraConfirmDialog
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.protocol.ApprovalRequest
import dev.agentnest.core.protocol.RemoteApproval
import org.junit.Test
import org.junit.runner.RunWith

/** Approval list, detail cards for every risk level, dialogs and the hold-to-confirm button. */
@RunWith(AndroidJUnit4::class)
class ApprovalShotTest : ShotBase() {
    private val sw = Phone.SMALL_W
    private val sh = Phone.SMALL_H
    private val lw = Phone.LARGE_W
    private val lh = Phone.LARGE_H

    @Composable
    private fun Detail(req: ApprovalRequest, nest: NestState = SD.withApproval(req), auth: AuthAvailability = AuthAvailability.READY, id: String = req.requestId) {
        val c = remember { FakeAppController(nest, auth = auth) }
        ApprovalDetailScreen(id, nest, SD.NOW, c, onBack = {})
    }

    private val scrollDown: ComposeContentTestRule.() -> Unit = {
        onNodeWithTag(FRAME_TAG).performTouchInput { swipeUp() }
    }

    @Test
    fun list() {
        shoot("approvals_list_S", sw, sh) { ApprovalsScreen(SD.manyApprovals, SD.NOW, {}, {}, {}) }
        shoot("approvals_list_L", lw, lh) { ApprovalsScreen(SD.manyApprovals, SD.NOW, {}, {}, {}) }
        shoot("approvals_list_S_dark", sw, sh, dark = true) { ApprovalsScreen(SD.manyApprovals, SD.NOW, {}, {}, {}) }
        shoot("approvals_list_S_font13", sw, sh, fontScale = 1.3f) { ApprovalsScreen(SD.manyApprovals, SD.NOW, {}, {}, {}) }
        shoot("approvals_empty_S", sw, sh) { ApprovalsScreen(SD.idle, SD.NOW, {}, {}, {}) }
        shoot("approvals_history_S", sw, sh) { ApprovalHistoryScreen(SD.manyApprovals, {}) }
        shoot("approvals_history_S_dark", sw, sh, dark = true) { ApprovalHistoryScreen(SD.manyApprovals, {}) }
    }

    @Test
    fun detailByRisk() {
        shoot("approval_low_S", sw, sh) { Detail(SD.reqLow) }
        shoot("approval_medium_S", sw, sh) { Detail(SD.reqMedium) }
        shoot("approval_high_S", sw, sh) { Detail(SD.reqHigh) }
        shoot("approval_critical_S", sw, sh) { Detail(SD.reqCritical) }
        shoot("approval_high_L", lw, lh) { Detail(SD.reqHigh) }
        shoot("approval_low_S_dark", sw, sh, dark = true) { Detail(SD.reqLow) }
        shoot("approval_high_S_dark", sw, sh, dark = true) { Detail(SD.reqHigh) }
        shoot("approval_critical_S_dark", sw, sh, dark = true) { Detail(SD.reqCritical) }
    }

    @Test
    fun detailFontScale() {
        shoot("approval_high_S_font13", sw, sh, fontScale = 1.3f) { Detail(SD.reqHigh) }
        shoot("approval_critical_S_font13", sw, sh, fontScale = 1.3f) { Detail(SD.reqCritical) }
        shoot("approval_critical_S_font13_scrolled", sw, sh, fontScale = 1.3f, before = scrollDown) { Detail(SD.reqCritical) }
        shoot("approval_medium_S_font13", sw, sh, fontScale = 1.3f) { Detail(SD.reqMedium) }
    }

    @Test
    fun detailEdgeCases() {
        shoot("approval_long_S", sw, sh) { Detail(SD.reqLong) }
        shoot("approval_long_expanded_S", sw, sh, before = { onNodeWithText(S.EXPAND).performClick() }) { Detail(SD.reqLong) }
        shoot("approval_long_S_font13", sw, sh, fontScale = 1.3f) { Detail(SD.reqLong) }
        shoot("approval_hidden_chars_S", sw, sh) { Detail(SD.reqHidden) }
        shoot("approval_expiring_S", sw, sh) { Detail(SD.reqExpiring) }
        shoot("approval_expiring_soon_S", sw, sh) {
            Detail(SD.request(SD.REQ_EXPIRING, dev.agentnest.core.protocol.RiskLevel.MEDIUM, dev.agentnest.core.protocol.ExtraConfirmationLevel.NONE, "명령을 실행하려고 해요", command = "pnpm install", secondsLeft = 3))
        }
        shoot("approval_codex_S", sw, sh) { Detail(SD.reqCodex) }
        shoot("approval_remote_unavailable_S", sw, sh) { Detail(SD.reqHigh, nest = SD.withApproval(SD.reqHigh, RemoteApproval.UNAVAILABLE)) }
        shoot("approval_no_device_lock_S", sw, sh) { Detail(SD.reqMedium, auth = AuthAvailability.NOT_ENROLLED) }
        shoot("approval_gone_S", sw, sh) { Detail(SD.reqHigh, nest = SD.idle) }
    }

    @Test
    fun holdAndDialogs() {
        // Finger down for ~1 s of the 1.5 s hold: the fill is about two thirds across and nothing has fired.
        shoot(
            "approval_high_hold_progress_S", sw, sh, manualClock = true,
            before = {
                onNodeWithText(S.HOLD_TO_ALLOW).performTouchInput { down(center) }
                mainClock.advanceTimeBy(700)
            },
        ) { Detail(SD.reqHigh) }
        shoot("approval_reconfirm_dialog_S", sw, sh, dialog = true) {
            ExtraConfirmDialog(SD.reqCritical, needHold = false, needCheckbox = true, onConfirmed = {}, onDismiss = {})
        }
        shoot("approval_reconfirm_dialog_S_dark", sw, sh, dark = true, dialog = true) {
            ExtraConfirmDialog(SD.reqCritical, needHold = false, needCheckbox = true, onConfirmed = {}, onDismiss = {})
        }
        shoot("approval_stop_dialog_S_font13", sw, sh, fontScale = 1.3f, dialog = true) {
            ExtraConfirmDialog(SD.reqLong, needHold = true, needCheckbox = true, onConfirmed = {}, onDismiss = {})
        }
    }
}
