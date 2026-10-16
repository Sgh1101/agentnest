package dev.agentnest.app.ui.common

import android.view.WindowManager
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.window.DialogWindowProvider

/**
 * Hardens the window of the enclosing dialog. A dialog is its own window, so the activity-level protection of
 * [SecureScreen] does not cover it: place this inside the dialog's content. The dialog then ignores touches while
 * another window overlays it (tap-jacking on "확인") and, when [secure] is true, is excluded from screenshots, screen
 * recording and the recents thumbnail (the re-confirm dialog shows the full command).
 */
@Composable
fun SecureDialogWindow(secure: Boolean) {
    val view = LocalView.current
    SideEffect {
        view.filterTouchesWhenObscured = true
        view.rootView.filterTouchesWhenObscured = true
        if (secure) {
            (view.parent as? DialogWindowProvider)?.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}
