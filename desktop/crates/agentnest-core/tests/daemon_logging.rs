//! The daemon's own file logger (`DaemonOptions::init_logging`, security.md 8.2). Its own test binary: a process has one
//! global `tracing` subscriber.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use agentnest_core::config::AppConfig;
use agentnest_core::daemon::{Daemon, DaemonOptions};

#[test]
fn the_daemon_writes_a_redacted_daily_log_file_when_asked_to() {
    let dir = tempfile::tempdir().unwrap();
    let mut options = DaemonOptions::for_dir(dir.path());
    options.init_logging = true;
    let logs = options.paths.logs_dir.clone();
    let dm = Daemon::start_with(AppConfig::default(), options).expect("daemon");
    let token = dm.hook_token().expose().to_owned();
    // something that must never survive in a log line, however it got there
    tracing::warn!(
        "test line password=hunter2hunter2 Authorization: Bearer abcdefgh12345678 {token}"
    );
    dm.shutdown_blocking();
    drop(dm); // flushes the background writer
    std::thread::sleep(std::time::Duration::from_millis(300));
    let mut text = String::new();
    for e in std::fs::read_dir(&logs).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        assert!(
            name.starts_with("agentnest.") && name.ends_with(".log"),
            "{name}"
        );
        text.push_str(&std::fs::read_to_string(e.path()).unwrap());
    }
    assert!(text.contains("agentnest daemon started"), "{text}");
    for secret in ["hunter2hunter2", "abcdefgh12345678", token.as_str()] {
        assert!(!text.contains(secret), "{secret} reached the log file");
    }
    assert!(text.contains("<redacted>"));
}
