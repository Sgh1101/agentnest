//! Application start-up (the Tauri `setup` hook) and shutdown.
//!
//! Order matters (docs/desktop.md 2, docs/security.md 3):
//!
//! 1. the single-instance plugin has already run (plugins initialise in `Builder::build`, before `setup`), so a second
//!    process never gets here and cannot start a second daemon or overwrite `daemon.json`;
//! 2. the saved configuration is loaded **before** the daemon starts (otherwise saved settings would be ignored);
//! 3. logging goes to the rolling file; the daemon is started with its own logger switched off;
//! 4. the daemon owns a private tokio runtime (`Daemon::start`), so Tauri keeps its own runtime and the two only talk
//!    over channels.

use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use agentnest_core::config::{AppConfig, Paths};
use agentnest_core::daemon::{Daemon, DaemonOptions};
use agentnest_core::state::timers::SystemClock;
use agentnest_shell_api::first_run::{has_minimized_flag, show_window_at_start};
use agentnest_shell_api::logs::init_global_logging;
use agentnest_shell_api::net::NetworkOps;
use agentnest_shell_api::settings::FileUiSettings;
use agentnest_shell_api::tray::{TrayInput, TrayModel};
use agentnest_shell_api::{run_event_pump, ShellApi, ShellApiOptions};
use tauri::{App, AppHandle, Manager};
use tauri_plugin_notification::NotificationExt;

use crate::sink::{refresh_tray, TauriSink};
use crate::state::Shell;
use crate::tray::{show_main, TrayController};

type SetupResult = Result<(), Box<dyn std::error::Error>>;

/// How long the exit path waits for the daemon's graceful shutdown.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(6);

/// The platform's firewall / network profile implementation.
fn network_ops() -> Arc<dyn NetworkOps> {
    #[cfg(windows)]
    {
        Arc::new(agentnest_shell_api::net::WindowsNetwork::new(
            agentnest_shell_api::net::SystemRunner,
        ))
    }
    #[cfg(not(windows))]
    {
        Arc::new(agentnest_shell_api::net::UnsupportedNetwork)
    }
}

/// `agentnest-hook` next to the app if it is there (command hooks, Codex), else the bare name for `PATH`.
fn hook_cli_path() -> String {
    let name = if cfg!(windows) {
        "agentnest-hook.exe"
    } else {
        "agentnest-hook"
    };
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(name)))
        .filter(|p| p.exists())
        .map_or_else(
            || name.to_owned(),
            |p: PathBuf| p.to_string_lossy().into_owned(),
        )
}

/// A failed start must not be silent in a windowless app: best-effort toast, then the error goes to `setup`'s caller.
fn fail(
    app: &AppHandle,
    what: &str,
    e: impl std::error::Error + 'static,
) -> Box<dyn std::error::Error> {
    tracing::error!(error = %e, "{what}");
    eprintln!("AgentNest could not start: {what}: {e}");
    let _ = app
        .notification()
        .builder()
        .title("AgentNest를 시작하지 못했어요")
        .body(what)
        .show();
    Box::new(e)
}

/// The Tauri `setup` hook.
pub fn setup(app: &mut App) -> SetupResult {
    let handle = app.handle().clone();

    let paths = Paths::default_for_user().map_err(|e| fail(&handle, "data directory", e))?;
    paths
        .ensure_dirs()
        .map_err(|e| fail(&handle, "data directory", e))?;
    // saved settings must be loaded before the daemon starts; a file with a forbidden field refuses to start (I10)
    let config =
        AppConfig::load(&paths.config).map_err(|e| fail(&handle, "configuration file", e))?;
    let log_guard = init_global_logging(&paths.logs_dir, config.log_level)
        .map_err(|e| fail(&handle, "log file", e))?;
    tracing::info!("AgentNest desktop shell starting");

    let mut options =
        DaemonOptions::production().map_err(|e| fail(&handle, "data directory", e))?;
    options.init_logging = false; // the shell owns logging
    options.hook_cli = hook_cli_path();
    let mut daemon = Daemon::start_with(config, options).map_err(|e| fail(&handle, "daemon", e))?;
    // the original receiver has seen every event since the daemon started; keep a fresh one in the handle
    let fresh = daemon.subscribe();
    let events = std::mem::replace(&mut daemon.events, fresh);
    let runtime = daemon.runtime().clone();

    let exe = std::env::current_exe().map_err(|e| fail(&handle, "executable path", e))?;
    let api = Arc::new(ShellApi::new(
        Arc::new(daemon),
        Arc::new(FileUiSettings::in_dir(&paths.root)),
        network_ops(),
        Arc::new(SystemClock),
        ShellApiOptions::for_process(exe),
    ));

    app.manage(Shell {
        api: api.clone(),
        _log: log_guard,
    });

    let model = TrayModel::build(&TrayInput::default());
    let tray =
        TrayController::create(&handle, &model).map_err(|e| fail(&handle, "tray icon", e))?;
    app.manage(tray);

    // daemon events -> webview, toasts, tray
    let sink = Arc::new(TauriSink::new(handle.clone()));
    runtime.spawn(run_event_pump(api.clone(), events, sink));
    refresh_tray(&handle);

    if show_window_at_start(
        has_minimized_flag(std::env::args()),
        api.onboarding_completed(),
    ) {
        show_main(&handle);
    }
    Ok(())
}

/// Graceful daemon shutdown on exit (bounded, so a stuck daemon cannot keep the process alive).
pub fn shutdown(app: &AppHandle) {
    let Some(shell) = app.try_state::<Shell>() else {
        return;
    };
    let api = shell.api.clone();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        api.daemon().shutdown_blocking();
        let _ = tx.send(());
    });
    if rx.recv_timeout(SHUTDOWN_WAIT).is_err() {
        tracing::warn!("the daemon did not shut down in time");
    }
}
