//! AgentNest desktop shell (Tauri 2): the thin glue around `agentnest-core` (the daemon) and `agentnest-shell-api`
//! (every decision of the shell, tested without Tauri). Modules:
//!
//! * `commands`: the `#[tauri::command]` wrappers of docs/desktop.md 3 / 3.1;
//! * `startup`: the `setup` hook (config, logging, daemon, tray, event pump) and graceful shutdown;
//! * `tray`, `sink`: the native tray and the sink the event pump drives;
//! * `state`: the managed state.

mod commands;
mod sink;
mod startup;
mod state;
mod tray;

use tauri::{RunEvent, WindowEvent};
use tauri_plugin_autostart::MacosLauncher;

/// Starts the app. Returns only when the process is about to exit.
pub fn run() {
    let built = tauri::Builder::default()
        // single-instance FIRST: a second process must be detected before anything else starts (docs/desktop.md 1)
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            tray::show_main(app);
        }))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        // the shell installs the global logger itself (rolling file); the plugin only forwards webview console records
        .plugin(tauri_plugin_log::Builder::new().skip_logger().build())
        .invoke_handler(tauri::generate_handler![
            commands::daemon_status,
            commands::diagnostics_run,
            commands::firewall_rule_create,
            commands::firewall_rule_remove,
            commands::link_set_enabled,
            commands::risk_accept,
            commands::pairing_start,
            commands::pairing_cancel,
            commands::pairing_confirm,
            commands::devices_list,
            commands::device_revoke,
            commands::sessions_list,
            commands::events_recent,
            commands::approvals_pending,
            commands::approvals_history,
            commands::approval_handoff_local,
            commands::approval_decide_local,
            commands::remote_approval_pause,
            commands::remote_approval_resume,
            commands::hooks_install,
            commands::hooks_uninstall,
            commands::hooks_status,
            commands::codex_probe,
            commands::settings_get,
            commands::settings_set,
            commands::logs_open_dir,
            commands::logs_tail,
        ])
        .setup(startup::setup)
        // closing the window hides it: the daemon and the tray keep running
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!());

    let app = match built {
        Ok(app) => app,
        Err(e) => {
            eprintln!("AgentNest could not start: {e}");
            std::process::exit(1);
        }
    };

    app.run(|handle, event| match event {
        // all windows closed / hidden: stay alive for the tray; only an explicit `exit(code)` ends the process
        RunEvent::ExitRequested { api, code, .. } => {
            if code.is_none() {
                api.prevent_exit();
            }
        }
        RunEvent::Exit => startup::shutdown(handle),
        _ => {}
    });
}
