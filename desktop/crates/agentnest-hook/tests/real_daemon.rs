//! The CLI against the REAL daemon (`agentnest-core`), not a fake server: the relay protocol (one-time proof, signed
//! answers), the statusLine reply and the daemon.json contract have to agree between the two crates.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use agentnest_core::config::AppConfig;
use agentnest_core::daemon::{Daemon, DaemonHandle, DaemonOptions};

fn start(dir: &Path) -> DaemonHandle {
    Daemon::start_with(AppConfig::default(), DaemonOptions::for_dir(dir)).expect("daemon")
}

fn run(args: &[&str], config: &Path, stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentnest-hook"))
        .args(args)
        .arg("--daemon-config")
        .arg(config)
        .env_remove("AGENTNEST_HOOK_DEBUG")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("http_proxy", "http://127.0.0.1:9")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

/// Review PoC 10: the daemon answered the statusLine with 204 while the CLI printed its line only for 200, so the status
/// line was always empty against the real daemon.
#[test]
fn the_statusline_prints_its_line_against_the_real_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let dm = start(dir.path());
    let cfg = dm.paths().daemon_json.clone();
    let out = run(
        &["statusline"],
        &cfg,
        br#"{"session_id":"s1","session_name":"x","cost":{"total_cost_usd":1.0}}"#,
    );
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "AgentNest\n");
    dm.shutdown_blocking();
}

#[test]
fn signed_answers_of_the_real_daemon_are_printed_and_a_reused_proof_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let dm = start(dir.path());
    let cfg = dm.paths().daemon_json.clone();
    // a critical PreToolUse gets the documented `ask` body, signed
    let hook = br#"{"hook_event_name":"PreToolUse","session_id":"s1","cwd":"/w","permission_mode":"default","tool_name":"Bash","tool_use_id":"t1","tool_input":{"command":"rm -rf /"}}"#;
    let out = run(&["claude-code"], &cfg, hook);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains(r#""permissionDecision":"ask""#), "{text:?}");
    // doctor sees a signed answer
    let doc = String::from_utf8(run(&["doctor"], &cfg, b"").stdout).unwrap();
    assert!(doc.contains("signed by the daemon"), "{doc}");
    assert!(!doc.contains("an_hk_"));
    // a wrong token in daemon.json: the daemon refuses the proof (401): nothing is printed
    let wrong = dir.path().join("wrong.json");
    let port = dm.hook_port();
    std::fs::write(
        &wrong,
        format!(
            r#"{{"hook_port":{port},"wss_port":1,"hook_token":"an_hk_not_the_token_00000000"}}"#
        ),
    )
    .unwrap();
    assert!(run(&["claude-code"], &wrong, hook).stdout.is_empty());
    dm.shutdown_blocking();
}

/// Review item 12: with a TTL of 180 s the CLI has to wait for 180 + 28 s, which it can only know from `daemon.json`.
#[test]
fn daemon_json_carries_the_effective_ttl() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = AppConfig::default();
    config.approval.ttl_s = 180;
    let dm = Daemon::start_with(config, DaemonOptions::for_dir(dir.path())).expect("daemon");
    // hooks installed with TTL 180 (timeout 210) make 180 the effective TTL
    let rt = dm.runtime().clone();
    rt.block_on(dm.hooks_install(agentnest_core::daemon::HooksMode::Cli))
        .unwrap();
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&dm.paths().daemon_json).unwrap()).unwrap();
    assert_eq!(v["approval_ttl_s"], 180, "{v}");
    assert_eq!(v["hook_port"], dm.hook_port());
    dm.shutdown_blocking();
}
