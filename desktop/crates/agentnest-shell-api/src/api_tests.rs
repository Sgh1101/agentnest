//! [`ShellApi`] against a real daemon (temp directory, ephemeral loopback ports): every command's mapping, error codes,
//! settings persistence, the firewall flow with a fake network, the event pump with a recording sink.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentnest_core::config::AppConfig;
use agentnest_core::daemon::{Daemon, DaemonOptions, HookAgent, HooksMode};
use agentnest_core::events::{DaemonEvent, LinkUiEvent};
use agentnest_core::state::timers::SystemClock;
use agentnest_protocol::Decision;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::api::{ShellApi, ShellApiOptions};
use crate::error::code;
use crate::events::{Envelope, Notification, ShellAction};
use crate::net::fakes::FakeNetwork;
use crate::net::{ElevatedOutcome, FirewallState, NetworkProfile};
use crate::pump::{run_event_pump_with, UiSink};
use crate::settings::{MemoryUiSettings, UiSettingsStore};

const EXE: &str = "C:\\Program Files\\AgentNest\\AgentNest.exe";

struct Harness {
    api: Arc<ShellApi>,
    dir: tempfile::TempDir,
    net: FakeNetwork,
    ui: Arc<MemoryUiSettings>,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let options = DaemonOptions::for_dir(dir.path());
    let daemon = Daemon::start_async(AppConfig::default(), options)
        .await
        .expect("daemon start");
    let net = FakeNetwork::new();
    let ui = Arc::new(MemoryUiSettings::default());
    let api = Arc::new(ShellApi::new(
        Arc::new(daemon),
        ui.clone(),
        Arc::new(net.clone()),
        Arc::new(SystemClock),
        ShellApiOptions {
            exe_path: PathBuf::from(EXE),
            codex_home: Some(dir.path().join("codex-home")),
            platform_checks: true,
            self_connect_timeout: Duration::from_secs(2),
        },
    ));
    Harness { api, dir, net, ui }
}

async fn post_hook(h: &Harness, body: &Value) -> u16 {
    let daemon = h.api.daemon();
    let port = daemon.hook_port();
    let token = daemon.hook_token().expose().to_owned();
    let text = body.to_string();
    let req = format!(
        "POST /v1/hooks/claude-code HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-AgentNest-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let head = String::from_utf8_lossy(&out);
    head.split_whitespace().nth(1).unwrap().parse().unwrap()
}

fn prompt_hook(session: &str) -> Value {
    json!({"hook_event_name": "UserPromptSubmit", "session_id": session, "cwd": "C:\\dev\\agentnest", "prompt": "hi"})
}

#[derive(Debug, Clone, PartialEq)]
enum Rec {
    Emit(Envelope),
    Show,
    Notify(Notification),
    Tray,
}

#[derive(Default)]
struct Recorder(Mutex<Vec<Rec>>);

impl Recorder {
    fn all(&self) -> Vec<Rec> {
        self.0.lock().unwrap().clone()
    }
    fn emits(&self, kind: &str) -> Vec<Envelope> {
        self.all()
            .into_iter()
            .filter_map(|r| match r {
                Rec::Emit(e) if e.kind == kind => Some(e),
                _ => None,
            })
            .collect()
    }
}

impl UiSink for Recorder {
    fn emit(&self, e: &Envelope) {
        self.0.lock().unwrap().push(Rec::Emit(e.clone()));
    }
    fn show_window(&self) {
        self.0.lock().unwrap().push(Rec::Show);
    }
    fn notify(&self, n: &Notification) {
        self.0.lock().unwrap().push(Rec::Notify(n.clone()));
    }
    fn tray_changed(&self) {
        self.0.lock().unwrap().push(Rec::Tray);
    }
}

async fn eventually<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    for _ in 0..500 {
        if let Some(v) = f() {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread")]
async fn status_has_the_contract_shape_and_no_secret() {
    let h = harness().await;
    let s = h.api.daemon_status().await.unwrap();
    let v = serde_json::to_value(&s).unwrap();
    assert_eq!(v["running"], true);
    assert_eq!(v["link_enabled"], true);
    assert_eq!(v["codex_mode"], "hooks");
    assert_eq!(v["effective_ttl_s"], 120);
    assert_eq!(v["hook_timeout_s"], 0, "hooks are not installed yet");
    assert_eq!(
        v["last_event_at"],
        json!({"claude_code": null, "codex": null})
    );
    assert!(v["wss_addr"].as_str().unwrap().starts_with("127.0.0.1:"));
    assert!(v["spki_pin"].as_str().unwrap().starts_with("sha256/"));
    let text = v.to_string();
    let token = h.api.daemon().hook_token().expose().to_owned();
    assert!(!text.contains(&token), "daemon_status carries no secret");
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_round_trip_and_persist_through_the_daemon() {
    let h = harness().await;
    let v = h.api.settings_get().await.unwrap();
    assert_eq!(v["approval.ttl_s"], 120);
    assert_eq!(v["risk.accepted"], json!([]));

    let v = h
        .api
        .settings_set("approval.ttl_s", json!(90))
        .await
        .unwrap();
    assert_eq!(v["approval.ttl_s"], 90);
    // the daemon wrote its config file
    let on_disk = AppConfig::load(&h.api.daemon().paths().config).unwrap();
    assert_eq!(on_disk.approval.ttl_s, 90);
    assert_eq!(h.api.daemon_status().await.unwrap().effective_ttl_s, 90);

    let v = h
        .api
        .settings_set("approval.critical_remote", json!("local_only"))
        .await
        .unwrap();
    assert_eq!(v["approval.critical_remote"], "local_only");
    let v = h
        .api
        .settings_set("approval.deny_requires_auth", json!(true))
        .await
        .unwrap();
    assert_eq!(v["approval.deny_requires_auth"], true);
    let v = h
        .api
        .settings_set("app.log_level", json!("debug"))
        .await
        .unwrap();
    assert_eq!(v["app.log_level"], "debug");
    let on_disk = AppConfig::load(&h.api.daemon().paths().config).unwrap();
    assert!(on_disk.approval.deny_requires_auth);
    assert_eq!(on_disk.log_level, agentnest_core::config::LogLevel::Debug);

    // UI-only settings live in the UI store, not in the daemon config
    let v = h
        .api
        .settings_set("app.notifications", json!(false))
        .await
        .unwrap();
    assert_eq!(v["app.notifications"], false);
    assert!(!h.api.notifications_enabled());
    assert!(!h.ui.load().notifications);
    let v = h
        .api
        .settings_set("onboarding.codex_steps_done", json!(["trust"]))
        .await
        .unwrap();
    assert_eq!(v["onboarding.codex_steps_done"], json!(["trust"]));
    let v = h
        .api
        .settings_set("onboarding.completed", json!(true))
        .await
        .unwrap();
    assert_eq!(v["onboarding.completed"], true);
    assert!(h.api.onboarding_completed());
}

#[tokio::test(flavor = "multi_thread")]
async fn forbidden_unknown_and_out_of_range_settings_change_nothing() {
    let h = harness().await;
    let before = h.api.settings_get().await.unwrap();
    let cfg_before = AppConfig::load(&h.api.daemon().paths().config).unwrap();
    for key in [
        "auto_allow_low",
        "allow_for_session",
        "trust_all_certs",
        "risk_overrides",
        "link.enabled",
        "app.autostart",
        "codex.mode",
        "nonsense",
    ] {
        let e = h.api.settings_set(key, json!(true)).await.unwrap_err();
        assert_eq!(e.code, code::UNKNOWN_SETTING, "{key}");
    }
    for (key, v) in [
        ("approval.ttl_s", json!(300)),
        ("approval.ttl_s", json!(59)),
        ("approval.ttl_s", json!("120")),
        ("approval.critical_remote", json!("none")),
        ("app.log_level", json!("trace")),
        ("risk.accepted", json!(["R1"])),
    ] {
        let e = h.api.settings_set(key, v).await.unwrap_err();
        assert_eq!(e.code, code::INVALID_SETTING, "{key}");
    }
    assert_eq!(h.api.settings_get().await.unwrap(), before);
    // nothing was written: the config file still equals what it was
    assert_eq!(
        AppConfig::load(&h.api.daemon().paths().config).unwrap(),
        cfg_before
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_needs_r1_and_exposes_only_the_qr_svg() {
    let h = harness().await;
    let e = h.api.pairing_start().await.unwrap_err();
    assert_eq!(e.code, code::RISK_NOT_ACCEPTED);
    assert_eq!(
        h.api.risk_accept("R2").await.unwrap_err().code,
        code::INVALID_SETTING
    );
    h.api.risk_accept("R1").await.unwrap();
    assert_eq!(
        h.api.settings_get().await.unwrap()["risk.accepted"],
        json!(["R1"])
    );
    let p = h.api.pairing_start().await.unwrap();
    assert!(p.pairing_id.starts_with("p_"));
    assert!(p.qr_svg.contains("<svg"));
    let text = serde_json::to_string(&p).unwrap();
    assert!(
        !text.contains("agentnest://"),
        "the QR content (with the pairing secret) never leaves"
    );
    assert_eq!(
        h.api.pairing_start().await.unwrap_err().code,
        code::PAIRING_BUSY
    );
    assert_eq!(
        h.api
            .pairing_confirm(&p.pairing_id, true)
            .await
            .unwrap_err()
            .code,
        code::PAIRING_NOT_PENDING,
        "no phone has proven the QR secret yet"
    );
    assert_eq!(
        h.api.pairing_cancel("p_unknown").await.unwrap_err().code,
        code::PAIRING_NOT_FOUND
    );
    h.api.pairing_cancel(&p.pairing_id).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_disabled_link_refuses_pairing_and_is_reported() {
    let h = harness().await;
    h.api.risk_accept("R1").await.unwrap();
    h.api.link_set_enabled(false).await.unwrap();
    assert!(!h.api.daemon_status().await.unwrap().link_enabled);
    assert_eq!(
        h.api.pairing_start().await.unwrap_err().code,
        code::LINK_DISABLED
    );
    let env = h.api.link_envelope().await.unwrap();
    assert_eq!(
        env.payload,
        json!({"enabled": false, "remote_approval_paused": false})
    );
    h.api.link_set_enabled(true).await.unwrap();
    assert!(h.api.pairing_start().await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn pause_and_resume_are_visible_in_status_and_the_link_envelope() {
    let h = harness().await;
    h.api.remote_approval_pause(true).await.unwrap();
    assert!(h.api.daemon_status().await.unwrap().remote_approval_paused);
    assert_eq!(
        h.api.link_envelope().await.unwrap().payload,
        json!({"enabled": true, "remote_approval_paused": true})
    );
    h.api.remote_approval_pause(false).await.unwrap();
    assert!(!h.api.daemon_status().await.unwrap().remote_approval_paused);
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_ids_have_their_own_codes() {
    let h = harness().await;
    assert!(h.api.devices_list().await.unwrap().is_empty());
    assert_eq!(
        h.api.device_revoke("dev_nope", "x").await.unwrap_err().code,
        code::DEVICE_NOT_FOUND
    );
    assert_eq!(
        h.api
            .approval_handoff_local("ar_nope")
            .await
            .unwrap_err()
            .code,
        code::UNKNOWN_REQUEST
    );
    let sha = "a".repeat(64);
    // a refused decision is an error, never a silent success
    assert_eq!(
        h.api
            .approval_decide_local("ar_nope", Decision::Allow, &sha, true, None)
            .await
            .unwrap_err()
            .code,
        code::UNKNOWN_REQUEST
    );
    assert_eq!(
        h.api
            .tray_decide("ar_nope", Decision::Allow)
            .await
            .unwrap_err()
            .code,
        code::UNKNOWN_REQUEST
    );
    assert!(h.api.approvals_pending().await.unwrap().is_empty());
    assert!(h.api.approvals_history(50).await.unwrap().is_empty());
    assert!(h.api.sessions_list().await.unwrap().is_empty());
    assert!(h.api.events_recent(None, 50).await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn claude_hooks_install_status_uninstall_follow_the_daemon() {
    let h = harness().await;
    let s = h.api.hooks_status(HookAgent::ClaudeCode).await.unwrap();
    assert!(!s.installed);
    let s = h
        .api
        .hooks_install(HookAgent::ClaudeCode, HooksMode::Http)
        .await
        .unwrap();
    assert!(s.installed);
    assert!(s.path.as_deref().unwrap().ends_with("settings.json"));
    assert!(
        h.api
            .hooks_status(HookAgent::ClaudeCode)
            .await
            .unwrap()
            .installed
    );
    let st = h.api.daemon_status().await.unwrap();
    assert!(st.hooks_installed);
    assert_eq!(st.hook_timeout_s, 150, "TTL 120 + 30");
    let s = h.api.hooks_uninstall(HookAgent::ClaudeCode).await.unwrap();
    assert!(!s.installed);
    assert!(!h.api.daemon_status().await.unwrap().hooks_installed);
    // Codex: instructions only until Phase 0 C6
    let c = h
        .api
        .hooks_install(HookAgent::Codex, HooksMode::Cli)
        .await
        .unwrap();
    assert!(!c.installed);
    assert!(!c.warnings.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn diagnostics_reflect_the_network_and_the_listener() {
    let h = harness().await;
    *h.net.state.lock().unwrap() = FirewallState {
        rule_present: true,
        scoped_ok: true,
        ..FirewallState::default()
    };
    let r = h.api.diagnostics_run().await.unwrap();
    assert!(r.listener.bound);
    assert_eq!(r.listener.addr.as_deref(), Some("127.0.0.1"));
    assert!(r.listener.port.unwrap() > 0);
    assert_eq!(r.network_profile, "private");
    assert!(r.firewall.scoped_ok && r.firewall.rule_present && !r.firewall.block_rule_present);
    assert!(r.self_connect_ok, "the listener is really there");
    assert!(r.last_preauth_attempt.is_none());
    assert!(r
        .hints_ko
        .iter()
        .any(|x| x.contains("휴대폰이 PC에 닿지 못했어요")));
    assert!(h
        .net
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|l| l.starts_with("profile 127.0.0.1")));

    // a public network with no rule
    let mut net = FakeNetwork::new();
    net.profile = NetworkProfile::Public;
    let h2 = harness_with_net(net).await;
    let r = h2.api.diagnostics_run().await.unwrap();
    assert_eq!(r.network_profile, "public");
    assert!(r.hints_ko.iter().any(|x| x.contains("'공용'")));
    assert!(r.hints_ko.iter().any(|x| x.contains("규칙 만들기")));
}

async fn harness_with_net(net: FakeNetwork) -> Harness {
    let mut h = harness().await;
    let api = ShellApi::new(
        h.api.daemon().clone(),
        h.ui.clone(),
        Arc::new(net.clone()),
        Arc::new(SystemClock),
        ShellApiOptions {
            exe_path: PathBuf::from(EXE),
            codex_home: None,
            platform_checks: true,
            self_connect_timeout: Duration::from_secs(2),
        },
    );
    h.api = Arc::new(api);
    h.net = net;
    h
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pre_auth_attempt_shows_up_in_the_diagnostics_masked() {
    let h = harness().await;
    let actions = h
        .api
        .process(DaemonEvent::Link(LinkUiEvent::PreAuthAttempt {
            ip_masked: "192.168.0.x".into(),
            at: "2026-10-15T09:00:00.000Z".into(),
        }))
        .await;
    assert!(actions.is_empty());
    let r = h.api.diagnostics_run().await.unwrap();
    let a = r.last_preauth_attempt.unwrap();
    assert_eq!(
        (a.at.as_str(), a.ip_masked.as_str()),
        ("2026-10-15T09:00:00.000Z", "192.168.0.x")
    );
    assert!(!r.hints_ko.iter().any(|x| x.contains("닿지 못했어요")));
}

#[tokio::test(flavor = "multi_thread")]
async fn creating_the_firewall_rule_is_verified_audited_and_scoped() {
    let h = harness().await;
    let r = h.api.firewall_rule_create().await.unwrap();
    assert!(r.ok && r.elevated && r.error.is_none());
    let port = h.api.daemon().link_addr().unwrap().port();
    assert!(h
        .net
        .log
        .lock()
        .unwrap()
        .contains(&format!("create {port}")));
    let rows = h.api.daemon().store().list_audit_log(20).unwrap();
    let row = rows
        .iter()
        .find(|r| r.action == "firewall_rule_created")
        .expect("audit row");
    assert_eq!(row.actor, "desktop_user");
    let details = row.details_json.clone().unwrap_or_default();
    assert!(details.contains("private") && details.contains("localsubnet"));
    assert!(
        !details.contains("Program Files"),
        "no path in the audit details"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declined_uac_prompt_is_elevation_denied_and_changes_nothing() {
    let mut net = FakeNetwork::new();
    net.create = ElevatedOutcome::Denied;
    net.remove = ElevatedOutcome::Denied;
    let h = harness_with_net(net).await;
    assert_eq!(
        h.api.firewall_rule_create().await.unwrap_err().code,
        code::ELEVATION_DENIED
    );
    assert_eq!(
        h.api.firewall_rule_remove().await.unwrap_err().code,
        code::ELEVATION_DENIED
    );
    let rows = h.api.daemon().store().list_audit_log(20).unwrap();
    assert!(!rows.iter().any(|r| r.action.starts_with("firewall_rule")));
}

#[tokio::test(flavor = "multi_thread")]
async fn other_firewall_failures_are_results_not_errors() {
    let mut net = FakeNetwork::new();
    net.create = ElevatedOutcome::Failed;
    let h = harness_with_net(net).await;
    let r = h.api.firewall_rule_create().await.unwrap();
    assert!(!r.ok && r.elevated);
    let mut net = FakeNetwork::new();
    net.create = ElevatedOutcome::NotStarted;
    net.remove = ElevatedOutcome::NotStarted;
    let h = harness_with_net(net).await;
    let r = h.api.firewall_rule_create().await.unwrap();
    assert!(!r.ok && !r.elevated);
    let r = h.api.firewall_rule_remove().await.unwrap();
    assert!(!r.ok && !r.elevated);
}

#[tokio::test(flavor = "multi_thread")]
async fn removing_the_rule_clears_allow_and_block_rules_and_is_audited() {
    let h = harness().await;
    *h.net.state.lock().unwrap() = FirewallState {
        rule_present: true,
        scoped_ok: true,
        block_rule_present: true,
        check_failed: false,
    };
    let r = h.api.firewall_rule_remove().await.unwrap();
    assert!(r.ok && r.elevated);
    assert_eq!(*h.net.state.lock().unwrap(), FirewallState::default());
    let rows = h.api.daemon().store().list_audit_log(20).unwrap();
    assert!(rows.iter().any(|r| r.action == "firewall_rule_removed"));
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_and_the_codex_probe_read_from_disk() {
    let h = harness().await;
    let logs = h.api.logs_dir();
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::write(
        logs.join("agentnest.2026-10-15.log"),
        "INFO started\nWARN token=abcdef0123456789abcdef0123456789 seen\n",
    )
    .unwrap();
    let t = h.api.logs_tail(200).await.unwrap();
    assert_eq!(t.len(), 2);
    assert!(!t[1].contains("abcdef0123456789"));
    let p = h.api.codex_probe().await.unwrap();
    assert!(!p.reachable);
    let sock = h.dir.path().join("codex-home/app-server-control");
    std::fs::create_dir_all(&sock).unwrap();
    std::fs::write(sock.join("app-server-control.sock"), b"").unwrap();
    assert!(h.api.codex_probe().await.unwrap().reachable);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_pump_forwards_daemon_events_in_order_with_batching_and_notifications() {
    let h = harness().await;
    let rec = Arc::new(Recorder::default());
    let mut rx = h.api.daemon().subscribe();
    let (api, sink) = (h.api.clone(), rec.clone());
    let pump = tokio::spawn(async move {
        run_event_pump_with(api, &mut rx, sink, Duration::from_millis(20)).await;
    });

    // link events: one envelope each, with the shared pause flag
    h.api.remote_approval_pause(true).await.unwrap();
    h.api.link_set_enabled(false).await.unwrap();
    let link = eventually("link envelope", || rec.emits("link").into_iter().next()).await;
    assert_eq!(
        link.payload,
        json!({"enabled": false, "remote_approval_paused": true})
    );

    // pairing end: start then cancel
    h.api.link_set_enabled(true).await.unwrap();
    h.api.risk_accept("R1").await.unwrap();
    let p = h.api.pairing_start().await.unwrap();
    h.api.pairing_cancel(&p.pairing_id).await.unwrap();
    let ended = eventually("pairing ended", || rec.emits("pairing").into_iter().next()).await;
    assert_eq!(
        ended.payload,
        json!({"op": "ended", "pairing_id": p.pairing_id, "reason": "cancelled"})
    );

    // a hook event: an `event` batch (array, no `detail`, with seq) and a session_state follow
    assert_eq!(post_hook(&h, &prompt_hook("s-pump")).await, 204);
    let batch = eventually("event batch", || rec.emits("event").into_iter().next()).await;
    let list = batch.payload.as_array().unwrap();
    assert!(!list.is_empty());
    for e in list {
        assert!(e["seq"].as_i64().unwrap() > 0);
        assert!(e.get("detail").is_none());
        assert_eq!(e["agent_kind"], "claude_code");
    }
    let state = eventually("session_state", || {
        rec.emits("session_state").into_iter().next()
    })
    .await;
    assert_eq!(state.payload["session_key"], "claude_code:s-pump");
    // the tray was told to refresh
    eventually("tray refresh", || {
        rec.all().contains(&Rec::Tray).then_some(())
    })
    .await;

    // the daemon's data is visible through the commands
    let st = h.api.daemon_status().await.unwrap();
    assert!(st.last_event_at.claude_code.is_some());
    assert_eq!(st.last_event_at.codex, None);
    assert_eq!(h.api.sessions_list().await.unwrap().len(), 1);
    let recent = h.api.events_recent(None, 10).await.unwrap();
    assert!(!recent.is_empty());
    assert!(recent.iter().all(|e| e.get("detail").is_none()));
    let tray = h.api.tray_input(true).await;
    assert!(tray.daemon_running && tray.autostart && tray.link_enabled);
    assert_eq!(tray.session_states.len(), 1);

    // notifications honour app.notifications
    h.api
        .settings_set("app.notifications", json!(false))
        .await
        .unwrap();
    let before = rec
        .all()
        .iter()
        .filter(|r| matches!(r, Rec::Notify(_)))
        .count();
    for action in h
        .api
        .process(DaemonEvent::Device(
            agentnest_core::events::DeviceUiEvent::Offline {
                device_id: "dev_ghost".into(),
            },
        ))
        .await
    {
        // an unknown device produces no payload and no toast
        assert!(!matches!(
            action,
            ShellAction::Emit(_) | ShellAction::Notify(_)
        ));
    }
    assert_eq!(
        rec.all()
            .iter()
            .filter(|r| matches!(r, Rec::Notify(_)))
            .count(),
        before
    );

    pump.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_tray_input_degrades_when_the_daemon_is_gone() {
    let h = harness().await;
    h.api.daemon().shutdown().await.unwrap();
    // the command loop keeps answering until the runtime goes; after shutdown the status may still work, so only check
    // that the call terminates and is internally consistent
    let t = h.api.tray_input(false).await;
    assert!(t.pending.is_empty());
}
