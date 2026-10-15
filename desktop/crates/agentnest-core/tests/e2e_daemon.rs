//! Daemon lifecycle and the desktop command surface against a real daemon: files, restart persistence, hooks install,
//! settings, token rotation, identity regeneration, the event stream.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use agentnest_core::daemon::{CommandError, DaemonCommand, HooksMode};
use agentnest_core::events::{DaemonEvent, DeviceUiEvent, PairingUiEvent};
use agentnest_protocol::{Decision, ErrorCode, Message};
use common::e2e::*;
use common::harness::permission_request;
use serde_json::{json, Value};

fn fast(o: &mut agentnest_core::daemon::DaemonOptions, _: &mut agentnest_core::config::AppConfig) {
    o.timing.auth_fail_delay_ms = 50;
    o.timing.preauth_ms = 2_000;
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_json_carries_ports_and_token_and_is_readable_by_the_owner_only() {
    let e = E2e::start_with(fast).await;
    let path = e.dm.paths().daemon_json.clone();
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(v["hook_port"], e.dm.hook_port());
    assert_eq!(v["wss_port"], e.link_addr().port());
    assert_eq!(v["hook_token"].as_str().unwrap(), e.token());
    assert!(e.token().starts_with("an_hk_"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "daemon.json holds the hook token");
        let key = e.dm.paths().identity_dir.join("server-key.pem");
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the TLS private key file");
    }
    // the token is in the database only as a hash
    let status = e.dm.status().await.unwrap();
    let text = serde_json::to_string(&status).unwrap();
    assert!(
        !text.contains(&e.token()),
        "daemon_status carries no secret"
    );
    assert!(status.running);
    assert_eq!(status.spki_pin, e.dm.spki_pin());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restart_keeps_the_identity_the_hook_token_and_the_paired_devices() {
    let e = E2e::start_with(fast).await;
    let (paired, ws) = e.pair_ready("Pixel").await;
    drop(ws);
    let (pin, token) = (e.dm.spki_pin(), e.token());
    let e = e.restart(fast).await;
    assert_eq!(e.dm.spki_pin(), pin, "the phone's pin stays valid");
    assert_eq!(e.token(), token, "settings.json stays valid");
    let devices = e.dm.devices_list().await.unwrap();
    assert_eq!(devices.len(), 1);
    // the old device token still opens a session on the new process
    let mut ws = e.connect_ready(&paired).await;
    let _ = &mut ws;
    // a restart does not carry any unanswered approval over
    assert!(e.dm.approvals_pending().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn rotating_the_hook_token_invalidates_the_old_one_at_once() {
    let e = E2e::start_with(fast).await;
    let old = e.token();
    let url = e.hook_url("/v1/hooks/claude-code");
    let body = json!({"hook_event_name": "Stop", "session_id": "s1", "cwd": "C:\\x"});
    let (s, _) = post_blocking(&url, &old, &body);
    assert_eq!(s, 204);
    e.dm.request(|reply| DaemonCommand::HookTokenRotate { reply })
        .await
        .unwrap();
    let new = e.token();
    assert_ne!(old, new);
    assert_eq!(post_blocking(&url, &old, &body).0, 401);
    assert_eq!(
        post_blocking(
            &url,
            &new,
            &json!({"hook_event_name": "Stop", "session_id": "s2", "cwd": "C:\\x"})
        )
        .0,
        204
    );
    let on_disk: Value =
        serde_json::from_str(&std::fs::read_to_string(&e.dm.paths().daemon_json).unwrap()).unwrap();
    assert_eq!(on_disk["hook_token"].as_str().unwrap(), new);
}

#[tokio::test(flavor = "multi_thread")]
async fn regenerating_the_identity_changes_the_pin_and_revokes_every_phone() {
    let e = E2e::start_with(fast).await;
    let (paired, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    let old_pin = e.dm.spki_pin();
    e.dm.request(|reply| DaemonCommand::IdentityRegenerate { reply })
        .await
        .unwrap();
    assert_ne!(e.dm.spki_pin(), old_pin);
    let f = ws.recv_type("bye").await;
    let Message::Bye(b) = f.message else {
        unreachable!()
    };
    assert_eq!(b.reason, agentnest_protocol::ByeReason::DeviceRevoked);
    // a phone with the old pin refuses the new certificate
    assert!(Phone::connect(e.link_addr(), &old_pin).await.is_err());
    // and its token is revoked even on the new identity
    let mut ws = e.hello(&paired, 0, true).await;
    let f = ws.recv_type("error").await;
    let Message::Error(err) = f.message else {
        unreachable!()
    };
    assert_eq!(err.code, ErrorCode::DeviceRevoked);
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_are_validated_persisted_and_applied() {
    let e = E2e::start_with(fast).await;
    let mut cfg = e.dm.settings_get().await.unwrap();
    assert_eq!(cfg.approval.ttl_s, 120);
    // out-of-range values are refused and change nothing
    let mut bad = cfg.clone();
    bad.approval.ttl_s = 10;
    assert!(matches!(
        e.dm.settings_set(bad).await,
        Err(CommandError::Invalid(_))
    ));
    let mut bad = cfg.clone();
    bad.link.private_sources_only = false;
    assert!(matches!(
        e.dm.settings_set(bad).await,
        Err(CommandError::Invalid(_))
    ));
    assert_eq!(e.dm.settings_get().await.unwrap().approval.ttl_s, 120);
    // a valid change applies at once: the next welcome announces the TTL
    cfg.approval.ttl_s = 90;
    cfg.approval.deny_requires_auth = true;
    e.dm.settings_set(cfg).await.unwrap();
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    drop(ws.ws.close(None));
    let paired2 = e.pair("Second").await;
    let mut ws2 = e.hello(&paired2, 0, true).await;
    let f = ws2.recv_type("welcome").await;
    let Message::Welcome(w) = f.message else {
        unreachable!()
    };
    assert_eq!(w.limits.approval_ttl_s, 90);
    assert!(w.policy.deny_requires_auth);
    // persisted: a restart reads it back
    drop(ws2);
    let e = e.restart(fast).await;
    assert_eq!(e.dm.settings_get().await.unwrap().approval.ttl_s, 90);
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_install_merges_into_the_users_settings_and_uninstall_removes_only_ours() {
    let e = E2e::start_with(fast).await;
    let settings = e.dir.path().join("claude").join("settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    std::fs::write(
        &settings,
        serde_json::to_string_pretty(&json!({
            "model": "opus",
            "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter"}]}]}
        }))
        .unwrap(),
    )
    .unwrap();
    let report = e.dm.hooks_install(HooksMode::Http).await.unwrap();
    assert!(report.installed);
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(v["model"], "opus", "foreign keys survive");
    let pre = v["hooks"]["PreToolUse"].as_array().unwrap();
    assert!(
        pre.iter().any(|g| g.to_string().contains("my-linter")),
        "the user's own hook survives"
    );
    assert!(pre.iter().any(|g| g
        .to_string()
        .contains(&format!("127.0.0.1:{}", e.dm.hook_port()))));
    let perm = v["hooks"]["PermissionRequest"].to_string();
    assert!(
        perm.contains(&e.token()),
        "settings.json carries the live token"
    );
    assert!(
        perm.contains("\"timeout\":150") || perm.contains("\"timeout\": 150"),
        "{perm}"
    );
    assert!(report.hook_timeout_s == Some(150));
    // the real round trip: the installed URL and token work against this daemon
    let (s, _) = post_blocking(
        &format!("http://127.0.0.1:{}/v1/hooks/claude-code", e.dm.hook_port()),
        &e.token(),
        &json!({"hook_event_name": "Stop", "session_id": "s9", "cwd": "C:\\x"}),
    );
    assert_eq!(s, 204);
    // uninstall removes ours and keeps the user's
    let report = e.dm.hooks_uninstall().await.unwrap();
    assert!(!report.installed);
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert!(v["hooks"]["PreToolUse"].to_string().contains("my-linter"));
    assert!(!v.to_string().contains("127.0.0.1"));
    assert!(!v.to_string().contains(&e.token()));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_event_stream_reports_pairing_devices_and_approvals() {
    let e = E2e::start_with(fast).await;
    let mut rx = e.dm.subscribe();
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    let held = e.hold(permission_request("s1", "cargo test"));
    let (card, _) = ws.recv_card().await;
    assert!(
        ws.decide(Phone::decision_for(&card, Decision::Allow))
            .await
            .accepted
    );
    held.await.unwrap();
    let mut seen = std::collections::BTreeSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Ok(ev)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            {
                let tag = match &ev {
                    DaemonEvent::Pairing(PairingUiEvent::Started { .. }) => "pairing_started",
                    DaemonEvent::Pairing(PairingUiEvent::ConfirmRequested { .. }) => {
                        "pairing_confirm"
                    }
                    DaemonEvent::Pairing(PairingUiEvent::Ended { outcome, .. })
                        if outcome == "paired" =>
                    {
                        "pairing_paired"
                    }
                    DaemonEvent::Device(DeviceUiEvent::Online { .. }) => "device_online",
                    DaemonEvent::Approval(agentnest_core::events::ApprovalUiEvent::Opened {
                        ..
                    }) => "approval_opened",
                    DaemonEvent::Approval(agentnest_core::events::ApprovalUiEvent::Resolved {
                        ..
                    }) => "approval_resolved",
                    DaemonEvent::SessionState(_) => "session_state",
                    _ => continue,
                };
                seen.insert(tag);
            }
        }
    }
    for want in [
        "device_online",
        "approval_opened",
        "approval_resolved",
        "session_state",
    ] {
        assert!(seen.contains(want), "{want} missing in {seen:?}");
    }
    // pairing events were emitted before this subscription started to listen? they were not: the receiver existed first
    assert!(
        seen.contains("pairing_started")
            && seen.contains("pairing_confirm")
            && seen.contains("pairing_paired"),
        "{seen:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_database_never_gets_a_token_secret_or_card_nonce_in_clear_in_its_tables() {
    let e = E2e::start_with(fast).await;
    let (paired, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    let held = e.hold(permission_request("s1", "cargo test"));
    let (card, _) = ws.recv_card().await;
    let nonce = card.nonce_b64.expose().to_owned();
    assert!(
        ws.decide(Phone::decision_for(&card, Decision::Deny))
            .await
            .accepted
    );
    held.await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    // every text column of every table
    let dump: String = e
        .dm
        .store()
        .read(|c| {
            let mut out = String::new();
            let tables: Vec<String> = c
                .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")?
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<_, _>>()?;
            for t in tables {
                let mut st = c.prepare(&format!("SELECT * FROM {t}"))?;
                let n = st.column_count();
                let rows = st.query_map([], |r| {
                    let mut line = String::new();
                    for i in 0..n {
                        match r.get_ref(i)? {
                            rusqlite::types::ValueRef::Text(b) => line.push_str(&String::from_utf8_lossy(b)),
                            rusqlite::types::ValueRef::Blob(b) => line.push_str(&hex::encode(b)),
                            _ => {}
                        }
                        line.push('|');
                    }
                    Ok(line)
                })?;
                for l in rows {
                    out.push_str(&l?);
                    out.push('\n');
                }
            }
            Ok(out)
        })
        .unwrap();
    assert!(!dump.contains(&paired.token), "device token");
    assert!(!dump.contains(&e.token()), "hook token");
    // The nonce is a per-request binding value (not a credential). The approvals table keeps it as raw bytes; the only
    // place its base64 text appears is the replay stream, which must be able to re-send the card to a reconnecting phone.
    for line in dump.lines().filter(|l| l.contains(&nonce)) {
        assert!(
            line.contains("|approval_request|"),
            "nonce text outside the replay stream: {}",
            &line[..line.len().min(120)]
        );
    }
}

// ---- review: token rotation re-merges settings.json (security.md 10) -----------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn rotating_the_hook_token_re_merges_the_installed_http_hooks() {
    let e = E2e::start_with(fast).await;
    let settings = e.dir.path().join("claude").join("settings.json");
    e.dm.hooks_install(HooksMode::Http).await.unwrap();
    let old = e.token();
    assert!(std::fs::read_to_string(&settings).unwrap().contains(&old));
    e.dm.request(|reply| DaemonCommand::HookTokenRotate { reply })
        .await
        .unwrap();
    let new = e.token();
    assert_ne!(old, new);
    let text = std::fs::read_to_string(&settings).unwrap();
    assert!(
        text.contains(&new),
        "the installed hooks carry the NEW token"
    );
    assert!(!text.contains(&old), "and no longer the old one");
    // what Claude Code would send now is accepted; the old token is not
    let v: Value = serde_json::from_str(&text).unwrap();
    let header_token = v["hooks"]["PermissionRequest"][0]["hooks"][0]["headers"]
        ["X-AgentNest-Token"]
        .as_str()
        .unwrap()
        .to_owned();
    let body = json!({"hook_event_name": "Stop", "session_id": "s7", "cwd": "C:\\x"});
    let url = e.hook_url("/v1/hooks/claude-code");
    assert_eq!(post_blocking(&url, &header_token, &body).0, 204);
    assert_eq!(post_blocking(&url, &old, &body).0, 401);
    // the user's own settings and the hook count survive the re-merge
    let installed = agentnest_core::adapters::claude_code::install::inspect(&settings);
    assert!(installed.fully_installed());
}

#[tokio::test(flavor = "multi_thread")]
async fn rotating_without_installed_http_hooks_does_not_touch_settings_json() {
    let e = E2e::start_with(fast).await;
    let settings = e.dir.path().join("claude").join("settings.json");
    e.dm.request(|reply| DaemonCommand::HookTokenRotate { reply })
        .await
        .unwrap();
    assert!(!settings.exists(), "nothing installed, nothing written");
}

// ---- review item 1: the hook port -----------------------------------------------------------------------------------------

fn install_http_hooks_for(settings: &std::path::Path, port: u16) {
    use agentnest_core::adapters::claude_code::install::{install, HookMode, InstallOptions};
    install(
        settings,
        &InstallOptions {
            mode: HookMode::Http,
            hook_port: port,
            hook_token: "an_hk_old_token_for_the_squatted_port_000",
            approval_ttl_s: 120,
            daemon_down_deny: false,
            install_statusline: false,
            hook_cli: "agentnest-hook",
            backup_stamp: Some("t"),
        },
    )
    .unwrap();
}

async fn heard_hook_port_unavailable(e: &mut E2e) -> bool {
    for _ in 0..50 {
        match tokio::time::timeout(Duration::from_millis(100), e.dm.events.recv()).await {
            Ok(Ok(DaemonEvent::Error { message }))
                if message.starts_with("hook_port_unavailable") =>
            {
                return true
            }
            Ok(Ok(_)) => continue,
            _ => return false,
        }
    }
    false
}

/// A squatter holds the port the HTTP hooks were installed for. The daemon must not keep serving approvals for hooks that
/// point at the squatter's port, must say so, and repoints the hooks only if the user opted in.
#[tokio::test(flavor = "multi_thread")]
async fn a_port_squatter_disables_http_approvals_and_reports_hook_port_unavailable() {
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let held_port = squatter.local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("claude").join("settings.json");
    install_http_hooks_for(&settings, held_port);
    let mut e = E2e::start_in(dir, |o, _| {
        o.timing.auth_fail_delay_ms = 50;
        o.hook_port = held_port;
    })
    .await;
    let bound = e.dm.hook_port();
    assert_ne!(bound, held_port);
    let problem = e.dm.hook_port_problem().expect("hook_port_unavailable");
    assert_eq!((problem.wanted, problem.bound), (held_port, bound));
    assert!(
        heard_hook_port_unavailable(&mut e).await,
        "no DaemonEvent::Error(hook_port_unavailable)"
    );
    assert!(e.dm.status().await.unwrap().hook_port_mismatch);
    let report =
        e.dm.request(|reply| DaemonCommand::HooksStatus {
            agent: agentnest_core::daemon::HookAgent::ClaudeCode,
            reply,
        })
        .await
        .unwrap();
    assert!(
        report.warnings.iter().any(|w| w.contains("HTTP")),
        "{:?}",
        report.warnings
    );
    // settings.json was NOT touched without the opt-in
    assert!(std::fs::read_to_string(&settings)
        .unwrap()
        .contains(&format!(":{held_port}/")));

    let (_p, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    // an HTTP-hook PermissionRequest is not answered: 204 at once, no card
    let (s, body) = e
        .hook_post(
            "/v1/hooks/claude-code",
            permission_request("s1", "cargo test"),
        )
        .await;
    assert_eq!((s, body.as_str()), (204, ""));
    assert!(
        matches!(ws.next(Duration::from_millis(400)).await, Got::Timeout),
        "no card reaches the phone"
    );
    // the command-hook channel authenticates both ways and is not gated: it opens a card
    let url = e.hook_url("/v1/hooks/claude-code");
    let token = e.token();
    let held = tokio::task::spawn_blocking(move || {
        request_blocking(
            "POST",
            &url,
            &[
                ("X-AgentNest-Token", token.as_str()),
                ("X-AgentNest-Via", "cli"),
            ],
            Some(
                permission_request("s2", "cargo build")
                    .to_string()
                    .into_bytes(),
            ),
        )
    });
    let (card, _) = ws.recv_card().await;
    assert!(
        ws.decide(Phone::decision_for(&card, Decision::Deny))
            .await
            .accepted
    );
    assert_eq!(held.await.unwrap().0, 200);
    // the user reinstalls the HTTP hooks for the real port: HTTP approvals work again
    e.dm.hooks_install(HooksMode::Http).await.unwrap();
    assert!(!e.dm.status().await.unwrap().hook_port_mismatch);
    let held = e.hold(permission_request("s3", "cargo fmt"));
    let (card, _) = ws.recv_card().await;
    assert!(
        ws.decide(Phone::decision_for(&card, Decision::Deny))
            .await
            .accepted
    );
    assert_eq!(held.await.unwrap().0, 200);
    drop(squatter);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_hooks_are_repointed_only_when_the_user_opted_in() {
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let held_port = squatter.local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("claude").join("settings.json");
    install_http_hooks_for(&settings, held_port);
    let e = E2e::start_in(dir, |o, c| {
        o.hook_port = held_port;
        c.hooks.auto_reinstall_on_port_change = true;
    })
    .await;
    let bound = e.dm.hook_port();
    assert_ne!(bound, held_port);
    let text = std::fs::read_to_string(&settings).unwrap();
    assert!(
        text.contains(&format!(":{bound}/")) && !text.contains(&format!(":{held_port}/")),
        "{text}"
    );
    assert!(!e.dm.status().await.unwrap().hook_port_mismatch);
    assert!(e
        .dm
        .store()
        .list_audit_log(50)
        .unwrap()
        .iter()
        .any(|a| a.action == "hooks_repointed"));
    drop(squatter);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_conflict_nothing_is_reported_and_http_approvals_work() {
    let e = E2e::start_with(fast).await;
    assert!(e.dm.hook_port_problem().is_none());
    e.dm.hooks_install(HooksMode::Http).await.unwrap();
    assert!(!e.dm.status().await.unwrap().hook_port_mismatch);
}
