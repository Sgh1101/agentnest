//! Golden tests of the installed Claude Code `settings.json` (docs/testing-and-ci.md `claude_code` row,
//! security.md 12 #8: the installed golden has no `onFailure` or `continue`).

mod common;

use agentnest_core::adapters::claude_code::install::{
    install, uninstall, HookMode, InstallOptions,
};
use common::*;
use serde_json::Value;

fn opts<'a>(deny: bool) -> InstallOptions<'a> {
    InstallOptions {
        mode: HookMode::Http,
        hook_port: 47831,
        hook_token: "an_hk_TESTTOKEN",
        approval_ttl_s: 120,
        daemon_down_deny: deny,
        install_statusline: true,
        hook_cli: "agentnest-hook",
        // the pure installer trusts this flag; the daemon sets it from `hook_cli_usable` (absolute existing file)
        hook_cli_ready: true,
        backup_stamp: Some("20261015T091233Z"),
    }
}

fn golden(name: &str) -> Value {
    read_json(&fixtures_dir().join("claude_code_install").join(name))
}

#[test]
fn fresh_install_matches_the_golden_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    install(&path, &opts(false)).unwrap();
    let got: Value = read_json(&path);
    assert_eq!(got, golden("golden_fresh_http.json"));
}

#[test]
fn the_opt_in_variant_differs_only_by_on_failure_block_on_permission_request() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    install(&path, &opts(true)).unwrap();
    assert_eq!(
        read_json(&path),
        golden("golden_fresh_http_daemon_down_deny.json")
    );
}

#[test]
fn no_installed_hook_has_on_failure_by_default_or_continue_only() {
    // security.md 12 #8: the installed golden has no onFailure, or "continue"
    let g = golden("golden_fresh_http.json");
    for (event, groups) in g["hooks"].as_object().unwrap() {
        for group in groups.as_array().unwrap() {
            for h in group["hooks"].as_array().unwrap() {
                match h.get("onFailure") {
                    None => {}
                    Some(v) => assert_eq!(v, "continue", "{event}"),
                }
            }
        }
    }
    // and nothing in the golden carries a scope-expanding key
    let text = g.to_string();
    for forbidden in [
        "updatedInput",
        "updatedPermissions",
        "allow_for_session",
        "disableAllHooks",
    ] {
        assert!(!text.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn install_then_uninstall_round_trips_an_existing_user_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let original: Value = serde_json::json!({
        "model": "opus",
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "lint"}]}]}
    });
    std::fs::write(&path, original.to_string()).unwrap();
    install(&path, &opts(false)).unwrap();
    assert_ne!(read_json(&path), original);
    uninstall(&path).unwrap();
    assert_eq!(read_json(&path), original);
}
