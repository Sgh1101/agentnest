//! The `UiSink` the event pump talks to: webview events, the window, toasts and the tray.

use std::sync::Arc;

use agentnest_shell_api::commands::DAEMON_EVENT_NAME;
use agentnest_shell_api::events::{Envelope, Notification};
use agentnest_shell_api::pump::UiSink;
use agentnest_shell_api::tray::TrayModel;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_autostart::ManagerExt as AutostartExt;
use tauri_plugin_notification::NotificationExt;

use crate::state::Shell;
use crate::tray::{show_main, TrayController};

/// Emits a `daemon-event` to the webview.
pub fn emit_envelope(app: &AppHandle, envelope: &Envelope) {
    if let Err(e) = app.emit(DAEMON_EVENT_NAME, envelope) {
        tracing::warn!(error = %e, "could not emit a daemon-event");
    }
}

/// Recomputes the tray from the daemon's current state (async; applies on the main thread).
pub fn refresh_tray(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let Some(shell) = app.try_state::<Shell>() else {
            return;
        };
        let Some(tray) = app.try_state::<Arc<TrayController>>() else {
            return;
        };
        let autostart = app.autolaunch().is_enabled().unwrap_or(false);
        let model = TrayModel::build(&shell.api.tray_input(autostart).await);
        let tray = tray.inner().clone();
        let handle = app.clone();
        let _ = app.run_on_main_thread(move || tray.apply(&handle, model));
    });
}

/// Forwards the pump's output to the real window, toasts and tray.
pub struct TauriSink {
    app: AppHandle,
}

impl TauriSink {
    /// A sink for `app`.
    pub fn new(app: AppHandle) -> Self {
        Self { app }
    }
}

impl UiSink for TauriSink {
    fn emit(&self, envelope: &Envelope) {
        emit_envelope(&self.app, envelope);
    }

    fn show_window(&self) {
        // the SAS modal is only meaningful in a visible window; this runs off the main thread, so hop over
        let app = self.app.clone();
        let _ = self.app.run_on_main_thread(move || show_main(&app));
    }

    fn notify(&self, notification: &Notification) {
        let result = self
            .app
            .notification()
            .builder()
            .title(&notification.title)
            .body(&notification.body)
            .show();
        if let Err(e) = result {
            tracing::debug!(error = %e, "could not show a notification");
        }
    }

    fn tray_changed(&self) {
        refresh_tray(&self.app);
    }
}
