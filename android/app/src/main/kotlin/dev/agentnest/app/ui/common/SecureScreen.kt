package dev.agentnest.app.ui.common

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import dev.agentnest.app.ui.AppController

/**
 * While this composable is on screen the window is marked secure (`FLAG_SECURE`: no screenshots, screen recording or
 * recents thumbnail) and ignores touches while another window covers it (tap-jacking). Used by the approval detail
 * (command, paths) and the pairing screen (SAS). Calls are reference counted by the controller.
 */
@Composable
fun SecureScreen(controller: AppController) {
    DisposableEffect(controller) {
        controller.setScreenSecure(true)
        onDispose { controller.setScreenSecure(false) }
    }
}
