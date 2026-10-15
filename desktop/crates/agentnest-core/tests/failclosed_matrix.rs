//! The fail-closed matrix: one test per row of docs/security.md 7 ("every failure ends as no decision or deny; no path
//! allows"). Every row asserts what the agent receives (never an allow unless a valid decision said so), what the database
//! says, and what the phone is told. Row numbers follow the table order; `row_07` points at the hook CLI test that lives in
//! the `agentnest-hook` crate (the daemon is not running there, so it cannot be a daemon test).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use agentnest_adapter_api::{AbandonReason, AgentCloseReason};
use agentnest_core::approvals::broker::{default_classifier, OpenOutcome};
use agentnest_core::events::ApprovalChannel;
use agentnest_core::risk::classify::classify_with_injected_fault;
use agentnest_core::risk::RiskInput;
use agentnest_protocol::{
    Decision, DecisionResultReason, ErrorCode, Frame, Message, ProtocolError, RemoteApproval,
};
use common::e2e::{E2e, Phone};
use common::harness::*;
use serde_json::{json, Value};

/// What the agent must see when there is "no decision": an empty 204, or a deny body. Never an allow.
fn assert_no_allow(status: u16, body: &str) {
    match status {
        204 => assert!(body.is_empty(), "204 carries no body"),
        200 => {
            let v: Value = serde_json::from_str(body).expect("a JSON body");
            assert_eq!(
                v["hookSpecificOutput"]["decision"]["behavior"], "deny",
                "a 200 must be a deny: {body}"
            );
        }
        other => panic!("unexpected status {other}"),
    }
    assert!(
        !body.contains("\"allow\""),
        "an allow must never appear: {body}"
    );
}

fn assert_empty_204(status: u16, body: &str) {
    assert_eq!((status, body), (204, ""));
}

async fn start_held(t: &Arc<HttpHarness>, command: &str) -> tokio::task::JoinHandle<(u16, String)> {
    let already = t.h.store.list_pending_approvals(None).unwrap().len();
    let t2 = t.clone();
    let body = permission_request("s1", command);
    let handle = tokio::spawn(async move { t2.post("/v1/hooks/claude-code", body).await });
    let t3 = t.clone();
    eventually("a held request", move || {
        let held = t3.h.store.list_pending_approvals(None).unwrap();
        (held.len() > already).then_some(())
    })
    .await;
    handle
}

fn status_of(t: &HttpHarness, request_id: &str) -> (String, Option<String>) {
    let row = t.h.store.get_approval(request_id).unwrap().unwrap();
    (row.status, row.resolved_by)
}

// ---- 1. no online device -------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_01_no_online_device_is_an_immediate_empty_2xx_and_a_system_hand_off() {
    let t = HttpHarness::new().await;
    let mut stream = t.h.registry.subscribe();
    let began = Instant::now();
    let (s, b) = t
        .post(
            "/v1/hooks/claude-code",
            permission_request("s1", "cargo test"),
        )
        .await;
    assert_empty_204(s, &b);
    assert!(began.elapsed() < Duration::from_secs(2));
    let row =
        t.h.store
            .read(|c| {
                Ok(
                    c.query_row("SELECT status, resolved_by FROM approvals", [], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                    })?,
                )
            })
            .unwrap();
    assert_eq!(row, ("handed_off_local".to_owned(), "system".to_owned()));
    let msgs = Harness::drain(&mut stream);
    assert!(
        msgs.iter().all(|m| m.1 != "approval_request"),
        "no card for a hand-off"
    );
    assert_eq!(
        t.h.broker.pending_cards().await.len(),
        0,
        "a reconnecting phone's snapshot has no such card"
    );
}

// ---- 2. TTL --------------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_02_ttl_expiry_is_an_empty_2xx_expired_and_the_card_is_closed_on_the_phone() {
    let t = Arc::new(HttpHarness::new().await);
    let _phone = t.h.add_phone("Galaxy");
    let mut stream = t.h.registry.subscribe();
    let held = start_held(&t, "cargo test").await;
    let card = t.h.broker.pending_cards().await.remove(0);
    t.h.advance(119_999).await;
    assert!(!held.is_finished());
    t.h.advance(1).await;
    let (s, b) = held.await.unwrap();
    assert_empty_204(s, &b);
    assert_eq!(
        status_of(&t, &card.request_id),
        ("expired".to_owned(), Some("timeout".to_owned()))
    );
    let msgs = Harness::drain(&mut stream);
    let resolved = msgs
        .iter()
        .find(|m| m.1 == "approval_resolved")
        .expect("approval_resolved{expired}");
    assert_eq!(resolved.2["outcome"], "expired");
}

// ---- 3. phone disconnect -------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_03_a_disconnected_phone_gets_ten_seconds_then_an_empty_2xx_hand_off() {
    let t = Arc::new(HttpHarness::new().await);
    let phone = t.h.add_phone("Galaxy");
    let held = start_held(&t, "cargo test").await;
    let card = t.h.broker.pending_cards().await.remove(0);
    t.h.disconnect(&phone).await;
    t.h.advance(9_999).await;
    assert!(!held.is_finished(), "inside the grace period");
    assert_eq!(status_of(&t, &card.request_id).0, "pending");
    t.h.advance(1).await;
    let (s, b) = held.await.unwrap();
    assert_empty_204(s, &b);
    assert_eq!(status_of(&t, &card.request_id).0, "handed_off_local");
    // the remaining TTL is shorter than the grace: the request ends with the TTL, not later
    let t = Arc::new(
        HttpHarness::with(Harness::with(default_classifier(), 60, 10, false, false)).await,
    );
    let phone = t.h.add_phone("Galaxy");
    let held = start_held(&t, "cargo test").await;
    let card = t.h.broker.pending_cards().await.remove(0);
    t.h.advance(55_000).await;
    t.h.disconnect(&phone).await;
    t.h.advance(5_000).await;
    let (s, b) = held.await.unwrap();
    assert_empty_204(s, &b);
    assert_ne!(status_of(&t, &card.request_id).0, "pending");
}

// ---- 4. validation failure ----------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_04_a_failed_validation_is_refused_and_the_request_stays_pending_for_retries() {
    let t = Arc::new(HttpHarness::new().await);
    let phone = t.h.add_phone("Galaxy");
    let held = start_held(&t, "rm -rf /").await;
    let card = t.h.broker.pending_cards().await.remove(0);
    let mut cases: Vec<(
        &str,
        agentnest_core::approvals::validator::DecisionInput,
        DecisionResultReason,
    )> = Vec::new();
    let mut d = t.h.phone_decision(&card, &phone.device_id, Decision::Allow);
    d.nonce_b64 = Some(agentnest_protocol::Secret::new(b64(&[3u8; 16])));
    cases.push(("nonce", d, DecisionResultReason::BindingMismatch));
    let mut d = t.h.phone_decision(&card, &phone.device_id, Decision::Allow);
    d.session_key = Some("claude_code:other".into());
    cases.push(("session", d, DecisionResultReason::BindingMismatch));
    let mut d = t.h.phone_decision(&card, &phone.device_id, Decision::Allow);
    d.tool_input_sha256 = "0".repeat(64);
    cases.push(("hash", d, DecisionResultReason::InputHashMismatch));
    let mut d = t.h.phone_decision(&card, &phone.device_id, Decision::Allow);
    d.extra_confirmation = None;
    cases.push((
        "extra confirmation",
        d,
        DecisionResultReason::ExtraConfirmationRequired,
    ));
    let mut d = t.h.phone_decision(&card, &phone.device_id, Decision::Allow);
    d.request_id = "ar_does_not_exist".into();
    cases.push(("unknown request", d, DecisionResultReason::UnknownRequest));
    for (what, d, want) in cases {
        let out = t.h.broker.apply_decision(d).await;
        assert!(!out.accepted, "{what}");
        assert_eq!(out.reason, want, "{what}");
        assert!(!held.is_finished(), "{what}: the agent keeps waiting");
        assert_eq!(status_of(&t, &card.request_id).0, "pending", "{what}");
    }
    // retry until the TTL: a valid decision is still accepted
    assert!(
        t.h.broker
            .apply_decision(t.h.phone_decision(&card, &phone.device_id, Decision::Allow))
            .await
            .accepted
    );
    let (s, _) = held.await.unwrap();
    assert_eq!(s, 200);
}

// ---- 5. internal error / panic --------------------------------------------------------------------------------------------

fn exploding_classifier(input: &RiskInput<'_>) -> agentnest_protocol::Risk {
    // a bug OUTSIDE the guarded classifier: the panic escapes into the broker
    if input.tool_input.to_string().contains("EXPLODE") {
        panic!("simulated internal bug");
    }
    default_classifier()(input)
}

#[tokio::test(flavor = "multi_thread")]
async fn row_05_an_internal_error_or_a_panic_ends_as_an_empty_2xx_and_the_daemon_keeps_working() {
    // a failing database
    let t = HttpHarness::new().await;
    let _phone = t.h.add_phone("Galaxy");
    t.h.store
        .run(|c| Ok(c.execute_batch("DROP TABLE approvals")?))
        .unwrap();
    let (s, b) = t
        .post(
            "/v1/hooks/claude-code",
            permission_request("s1", "cargo test"),
        )
        .await;
    assert_empty_204(s, &b);
    assert_eq!(t.h.broker.pending_count().await, 0);

    // a panic inside the broker open path
    let t = Arc::new(
        HttpHarness::with(Harness::with(exploding_classifier, 120, 10, false, false)).await,
    );
    let phone = t.h.add_phone("Galaxy");
    let (s, b) = t
        .post(
            "/v1/hooks/claude-code",
            permission_request("s1", "echo EXPLODE"),
        )
        .await;
    assert_empty_204(s, &b);
    assert_eq!(
        t.h.broker.pending_count().await,
        0,
        "nothing is left half open"
    );
    // the next request works normally (the broker lock is not poisoned or held)
    let held = start_held(&t, "cargo test").await;
    let card = t.h.broker.pending_cards().await.remove(0);
    assert!(
        t.h.broker
            .apply_decision(t.h.phone_decision(&card, &phone.device_id, Decision::Deny))
            .await
            .accepted
    );
    let (s, b) = held.await.unwrap();
    assert_no_allow(s, &b);
}

// ---- 6. daemon restart ----------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_06_a_restarted_daemon_expires_every_pending_request_and_cannot_answer_old_connections()
{
    let t = Arc::new(HttpHarness::new().await);
    let phone = t.h.add_phone("Galaxy");
    let held = start_held(&t, "cargo test").await;
    let card = t.h.broker.pending_cards().await.remove(0);
    // "restart": a fresh broker over the same database
    let registry = Arc::new(agentnest_core::link::registry::Registry::new());
    let mut stream = registry.subscribe();
    let bus = agentnest_core::events::EventBus::new(16);
    let pipeline = Arc::new(agentnest_core::pipeline::Pipeline::new(
        t.h.store.clone(),
        t.h.clock.clone(),
        registry.clone(),
        bus.clone(),
    ));
    let broker = agentnest_core::approvals::broker::Broker::new(
        agentnest_core::approvals::broker::BrokerDeps {
            store: t.h.store.clone(),
            clock: t.h.clock.clone(),
            pipeline,
            registry,
            bus,
            audit: t.h.audit.clone(),
            devices: t.h.devices.clone(),
            env: t.h.env.clone(),
            settings: t.h.settings.clone(),
            classifier: default_classifier(),
        },
    );
    assert_eq!(broker.recover_on_startup().await, 1);
    assert_eq!(
        status_of(&t, &card.request_id),
        ("expired".to_owned(), Some("system".to_owned()))
    );
    let msgs = Harness::drain(&mut stream);
    assert!(msgs
        .iter()
        .any(|m| m.1 == "approval_resolved" && m.2["outcome"] == "expired"));
    // a decision for the old request is refused by the new broker and the old handle is never answered by it
    let out = broker
        .apply_decision(t.h.phone_decision(&card, &phone.device_id, Decision::Allow))
        .await;
    assert!(!out.accepted);
    assert!(
        !held.is_finished(),
        "the old connection is not answered by the new process (it just goes away)"
    );
    t.h.broker.shutdown().await;
    let (s, b) = held.await.unwrap();
    assert_empty_204(s, &b);
}

// ---- 7. daemon not running -------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_07_a_stopped_daemon_refuses_connections_and_the_cli_answers_nothing() {
    // Claude Code sees a failed connection = a non-blocking error. The CLI half of the row (daemon down -> empty stdout,
    // exit 0) is `agentnest-hook/tests/cli.rs::daemon_down_gives_empty_stdout_and_exit_0`.
    let e = E2e::start().await;
    let url = e.hook_url("/v1/health");
    let (s, _) = request_blocking_get(&url);
    assert_eq!(s, 200);
    e.dm.shutdown().await.unwrap();
    let port = e.dm.hook_port();
    let mut refused = false;
    for _ in 0..100 {
        if std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(200),
        )
        .is_err()
        {
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(refused, "the collector port closes with the daemon");
}

fn request_blocking_get(url: &str) -> (u16, String) {
    common::e2e::request_blocking("GET", url, &[], None)
}

// ---- 8. hook timeout / clamp --------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_08_when_the_broker_does_not_answer_in_time_the_handler_answers_no_decision_and_supersedes(
) {
    let t = Arc::new(HttpHarness::new().await);
    let _phone = t.h.add_phone("Galaxy");
    // an abnormal case: the broker timer never runs (manual clock, no tick) so only the handler's own limit remains
    t.h.settings.set_ttl_ms(300);
    t.settings
        .hold_slack_ms
        .store(300, std::sync::atomic::Ordering::Relaxed);
    let began = Instant::now();
    let (s, b) = t
        .post(
            "/v1/hooks/claude-code",
            permission_request("s1", "cargo test"),
        )
        .await;
    assert_empty_204(s, &b);
    assert!(
        began.elapsed() >= Duration::from_millis(550),
        "{:?}",
        began.elapsed()
    );
    let t2 = t.clone();
    eventually("superseded by the guard", move || {
        let rows: Vec<String> =
            t2.h.store
                .read(|c| {
                    let mut st = c.prepare("SELECT status FROM approvals")?;
                    let v = st
                        .query_map([], |r| r.get::<_, String>(0))?
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(v)
                })
                .unwrap();
        (rows == vec!["superseded".to_owned()]).then_some(())
    })
    .await;
    // the configured TTL can never exceed what the installed hook timeout allows (minus 30 s)
    use agentnest_core::adapters::claude_code::install::effective_ttl_s;
    assert_eq!(effective_ttl_s(180, Some(150)), 120);
    assert_eq!(effective_ttl_s(120, Some(100)), 70);
    assert_eq!(
        effective_ttl_s(120, Some(10)),
        agentnest_core::adapters::claude_code::install::MIN_EFFECTIVE_TTL_S,
        "never below the minimum"
    );
}

// ---- 9. Claude closes first ---------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_09_when_claude_closes_first_the_drop_guard_supersedes_and_a_late_decision_is_refused()
{
    use std::io::Write;
    use std::net::TcpStream;
    let t = Arc::new(HttpHarness::new().await);
    let phone = t.h.add_phone("Galaxy");
    let body = permission_request("s1", "cargo test").to_string();
    let mut sock = TcpStream::connect(("127.0.0.1", t.port)).unwrap();
    write!(
        sock,
        "POST /v1/hooks/claude-code HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-AgentNest-Token: {HOOK_TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        t.port,
        body.len()
    )
    .unwrap();
    sock.flush().unwrap();
    let t2 = t.clone();
    eventually("held", move || {
        (!t2.h.store.list_pending_approvals(None).unwrap().is_empty()).then_some(())
    })
    .await;
    let card = t.h.broker.pending_cards().await.remove(0);
    drop(sock);
    let (t3, id) = (t.clone(), card.request_id.clone());
    eventually("superseded", move || {
        (status_of(&t3, &id).0 == "superseded").then_some(())
    })
    .await;
    assert_eq!(status_of(&t, &card.request_id).1.as_deref(), Some("agent"));
    let out =
        t.h.broker
            .apply_decision(t.h.phone_decision(&card, &phone.device_id, Decision::Allow))
            .await;
    assert!(!out.accepted);
    assert_eq!(out.reason, DecisionResultReason::AlreadyResolved);
    assert!(t
        .h
        .audit_actions(&card.request_id)
        .contains(&"late_decision".to_owned()));
}

// ---- 10. Codex serverRequest/resolved first --------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_10_when_codex_resolves_first_the_request_is_superseded_and_the_late_decision_is_audited(
) {
    let h = Harness::new();
    let phone = h.add_phone("Galaxy");
    let draft = h.draft("Bash", json!({"command": "cargo test"}));
    let binding = draft.binding.clone();
    let (o, mut rx) = h.open(draft).await;
    let OpenOutcome::Opened { request_id } = o else {
        panic!("{o:?}")
    };
    let card = h.broker.pending_card(&request_id).await.unwrap();
    h.broker
        .agent_closed(&binding, AgentCloseReason::ResolvedByAgent)
        .await;
    assert_eq!(
        try_seen(&mut rx),
        Some(Seen::Abandoned(AbandonReason::Superseded)),
        "no response is sent to Codex"
    );
    assert_eq!(h.row(&request_id).status, "superseded");
    let out = h
        .broker
        .apply_decision(h.phone_decision(&card, &phone.device_id, Decision::Allow))
        .await;
    assert!(!out.accepted);
    assert!(h
        .audit_actions(&request_id)
        .contains(&"late_decision".to_owned()));
    assert_eq!(try_seen(&mut rx), None, "still nothing sent");
}

// ---- 11. permission modes without PermissionRequest ------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_11_bypass_dont_ask_and_auto_modes_are_unavailable_and_never_held() {
    let t = Arc::new(HttpHarness::new().await);
    let _phone = t.h.add_phone("Galaxy");
    for mode in ["bypassPermissions", "dontAsk", "auto"] {
        let mut body = permission_request("s-mode", "cargo test");
        body["permission_mode"] = json!(mode);
        let began = Instant::now();
        let (s, b) = t.post("/v1/hooks/claude-code", body).await;
        assert_empty_204(s, &b);
        assert!(began.elapsed() < Duration::from_secs(2), "{mode}: not held");
        assert_eq!(t.h.broker.pending_count().await, 0);
    }
    // the session shows the badge once an observed event carries the mode
    let (s, _) = t
        .post(
            "/v1/hooks/claude-code",
            json!({"hook_event_name": "UserPromptSubmit", "session_id": "s-mode", "cwd": "C:\\dev\\agentnest", "permission_mode": "bypassPermissions", "prompt": "hi"}),
        )
        .await;
    assert_eq!(s, 204);
    let key = "claude_code:s-mode";
    let h = &t.h;
    let mut ok = false;
    for _ in 0..200 {
        if h.pipeline
            .session(key)
            .await
            .is_some_and(|s| s.remote_approval == RemoteApproval::Unavailable)
        {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(ok, "remote_approval: unavailable badge");
    // PermissionDenied is an event only
    let (s, _) = t
        .post(
            "/v1/hooks/claude-code",
            json!({"hook_event_name": "PermissionDenied", "session_id": "s-mode", "cwd": "C:\\dev\\agentnest", "permission_mode": "auto", "tool_name": "Bash", "tool_use_id": "t1", "tool_input": {"command": "x"}}),
        )
        .await;
    assert_eq!(s, 204);
    assert_eq!(t.h.broker.pending_count().await, 0);
}

// ---- 12. device revoked ------------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_12_a_revoked_device_decision_is_void_and_without_another_device_the_request_is_handed_off(
) {
    let t = Arc::new(HttpHarness::new().await);
    let phone = t.h.add_phone("Galaxy");
    let held = start_held(&t, "cargo test").await;
    let card = t.h.broker.pending_cards().await.remove(0);
    let d = t.h.phone_decision(&card, &phone.device_id, Decision::Allow);
    t.h.devices
        .revoke(&phone.device_id, "user_desktop")
        .unwrap();
    let out = t.h.broker.apply_decision(d).await;
    assert_eq!(out.reason, DecisionResultReason::DeviceRevoked);
    assert!(!held.is_finished());
    t.h.registry.kick_revoked(&phone.device_id);
    t.h.broker.device_revoked().await;
    let (s, b) = held.await.unwrap();
    assert_empty_204(s, &b);
    assert_eq!(status_of(&t, &card.request_id).0, "handed_off_local");
    // with a second online device the request stays alive for it
    let t = Arc::new(HttpHarness::new().await);
    let a = t.h.add_phone("A");
    let b2 = t.h.add_phone("B");
    let held = start_held(&t, "cargo test").await;
    let card = t.h.broker.pending_cards().await.remove(0);
    t.h.devices.revoke(&a.device_id, "user_desktop").unwrap();
    t.h.registry.kick_revoked(&a.device_id);
    t.h.broker.device_revoked().await;
    assert!(!held.is_finished());
    assert!(
        t.h.broker
            .apply_decision(t.h.phone_decision(&card, &b2.device_id, Decision::Deny))
            .await
            .accepted
    );
    let (s, body) = held.await.unwrap();
    assert_no_allow(s, &body);
}

// ---- 13. paused ---------------------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_13_paused_remote_approval_answers_new_requests_empty_and_refuses_pending_decisions() {
    let t = Arc::new(HttpHarness::new().await);
    let phone = t.h.add_phone("Galaxy");
    let held = start_held(&t, "cargo test").await;
    let card = t.h.broker.pending_cards().await.remove(0);
    t.h.broker.set_paused(true).await;
    let out =
        t.h.broker
            .apply_decision(t.h.phone_decision(&card, &phone.device_id, Decision::Allow))
            .await;
    assert_eq!(out.reason, DecisionResultReason::Paused);
    assert!(!held.is_finished());
    let (s, b) = t
        .post(
            "/v1/hooks/claude-code",
            permission_request("s2", "cargo build"),
        )
        .await;
    assert_empty_204(s, &b);
    // the pending one is still decidable after resume, or ends with the TTL
    t.h.advance(120_000).await;
    let (s, b) = held.await.unwrap();
    assert_empty_204(s, &b);
}

// ---- 14. classifier panic -----------------------------------------------------------------------------------------------------------

fn panicking_classifier(input: &RiskInput<'_>) -> agentnest_protocol::Risk {
    classify_with_injected_fault(input, true)
}

#[tokio::test(flavor = "multi_thread")]
async fn row_14_a_classifier_panic_means_critical_and_the_normal_flow_with_the_red_card() {
    let h = Harness::with(panicking_classifier, 120, 10, false, false);
    let phone = h.add_phone("Galaxy");
    let (card, rx) = h.open_low().await;
    assert_eq!(
        card.risk.level.effective(),
        agentnest_protocol::RiskLevel::Critical
    );
    assert!(
        card.risk.reasons.iter().any(|r| r == "classifier_error"),
        "{:?}",
        card.risk.reasons
    );
    assert_eq!(
        card.risk.extra_confirmation,
        agentnest_protocol::ExtraConfirmation::HoldAndReconfirm
    );
    // an allow without the re-confirmation is refused, the full one works
    let mut d = h.phone_decision(&card, &phone.device_id, Decision::Allow);
    d.extra_confirmation = None;
    assert_eq!(
        h.broker.apply_decision(d).await.reason,
        DecisionResultReason::ExtraConfirmationRequired
    );
    assert!(
        h.broker
            .apply_decision(h.phone_decision(&card, &phone.device_id, Decision::Allow))
            .await
            .accepted
    );
    assert_eq!(rx.await.unwrap(), Seen::Allow);
    // with critical-local-only the same panic never reaches the phone at all
    let h = Harness::with(panicking_classifier, 120, 10, true, false);
    let _phone = h.add_phone("Galaxy");
    let (o, rx) = h.open(h.draft("Bash", json!({"command": "echo hi"}))).await;
    assert!(
        matches!(
            o,
            OpenOutcome::HandedOff {
                channel: ApprovalChannel::LocalOnly,
                ..
            }
        ),
        "{o:?}"
    );
    assert_eq!(
        rx.await.unwrap(),
        Seen::Abandoned(AbandonReason::HandedOffToDesktop)
    );
}

// ---- 15. unknown decision value ---------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_15_an_unknown_decision_value_is_e_bad_message_and_the_request_keeps_waiting() {
    // the schema layer
    let text = r#"{"v":1,"type":"decision","id":"01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e5f","ts":"2026-10-15T09:12:33.120Z","payload":{"request_id":"ar_x","session_key":"s","nonce_b64":"AA==","tool_input_sha256":"00","decision":"allow_always","decided_at":"2026-10-15T09:12:33.120Z"}}"#;
    assert!(matches!(
        Frame::parse(text),
        Err(ProtocolError::BadMessage(_))
    ));
    // and over the real link
    let e = E2e::start_with(|o, _| {
        o.timing.auth_fail_delay_ms = 20;
    })
    .await;
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    let held = e.hold(permission_request("s1", "cargo test"));
    let (card, _) = ws.recv_card().await;
    ws.send_raw(&text.replace("ar_x", &card.request_id)).await;
    let f = ws.recv_type("error").await;
    let Message::Error(err) = f.message else {
        unreachable!()
    };
    assert_eq!(err.code, ErrorCode::BadMessage);
    assert!(!held.is_finished(), "the agent keeps waiting");
    assert_eq!(
        e.dm.store()
            .get_approval(&card.request_id)
            .unwrap()
            .unwrap()
            .status,
        "pending"
    );
    // a valid decision afterwards still works
    assert!(
        ws.decide(Phone::decision_for(&card, Decision::Deny))
            .await
            .accepted
    );
    let (s, b) = held.await.unwrap();
    assert_no_allow(s, &b);
}

// ---- 16. desktop "handle locally" ------------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_16_the_desktop_hand_off_is_an_immediate_empty_2xx_resolved_by_desktop() {
    let t = Arc::new(HttpHarness::new().await);
    let _phone = t.h.add_phone("Galaxy");
    let mut stream = t.h.registry.subscribe();
    let held = start_held(&t, "rm -rf /").await;
    let card = t.h.broker.pending_cards().await.remove(0);
    assert!(t.h.broker.handoff_local(&card.request_id).await);
    let (s, b) = held.await.unwrap();
    assert_empty_204(s, &b);
    assert_eq!(
        status_of(&t, &card.request_id),
        ("handed_off_local".to_owned(), Some("desktop".to_owned()))
    );
    let msgs = Harness::drain(&mut stream);
    let r = msgs.iter().find(|m| m.1 == "approval_resolved").unwrap();
    assert_eq!(
        (r.2["outcome"].as_str(), r.2["resolved_by"].as_str()),
        (Some("handed_off_local"), Some("desktop"))
    );
}

// ---- 17. desktop allow / deny ------------------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_17_desktop_allow_and_deny_use_the_same_transition_with_their_own_gates() {
    let t = Arc::new(HttpHarness::new().await);
    let _phone = t.h.add_phone("Galaxy");
    // gate 5: the echoed card hash
    let held = start_held(&t, "cargo test").await;
    let card = t.h.broker.pending_cards().await.remove(0);
    let out =
        t.h.broker
            .decide_local(
                &card.request_id,
                Decision::Allow,
                &"0".repeat(64),
                false,
                None,
            )
            .await;
    assert_eq!(out.reason, DecisionResultReason::InputHashMismatch);
    assert!(!held.is_finished());
    // gate 8: a critical allow needs the confirmation acknowledgement; a deny never does
    let held2 = start_held(&t, "rm -rf /").await;
    let cards = t.h.broker.pending_cards().await;
    let crit = cards
        .iter()
        .find(|c| c.risk.level.effective() == agentnest_protocol::RiskLevel::Critical)
        .unwrap()
        .clone();
    let out =
        t.h.broker
            .decide_local(
                &crit.request_id,
                Decision::Allow,
                &crit.tool_input_sha256,
                false,
                None,
            )
            .await;
    assert!(!out.accepted, "{out:?}");
    assert_eq!(status_of(&t, &crit.request_id).0, "pending");
    let out =
        t.h.broker
            .decide_local(
                &crit.request_id,
                Decision::Deny,
                &crit.tool_input_sha256,
                false,
                Some("no".into()),
            )
            .await;
    assert!(out.accepted);
    let (s, b) = held2.await.unwrap();
    assert_no_allow(s, &b);
    // a valid local allow is the same transition: one APPLIED row, actor desktop, audited
    let out =
        t.h.broker
            .decide_local(
                &card.request_id,
                Decision::Allow,
                &card.tool_input_sha256,
                false,
                None,
            )
            .await;
    assert!(out.accepted, "{out:?}");
    let (s, b) = held.await.unwrap();
    assert_eq!(s, 200);
    assert!(b.contains("\"allow\""));
    let decisions = t.h.store.list_decisions(&card.request_id).unwrap();
    assert!(
        decisions
            .iter()
            .any(|d| d.verify_result == "APPLIED" && d.actor == "desktop"),
        "{decisions:?}"
    );
    assert!(t
        .h
        .audit_actions(&card.request_id)
        .contains(&"decision_received".to_owned()));
    // and once resolved, a second local decision is refused
    let again =
        t.h.broker
            .decide_local(
                &card.request_id,
                Decision::Deny,
                &card.tool_input_sha256,
                false,
                None,
            )
            .await;
    assert!(!again.accepted);
}

// ---- 18. link disabled --------------------------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_18_disabling_the_link_hands_every_pending_request_off_resolved_by_desktop() {
    let t = Arc::new(HttpHarness::new().await);
    let _phone = t.h.add_phone("Galaxy");
    let held = start_held(&t, "cargo test").await;
    let card = t.h.broker.pending_cards().await.remove(0);
    assert_eq!(t.h.broker.link_disabled().await, 1);
    let (s, b) = held.await.unwrap();
    assert_empty_204(s, &b);
    assert_eq!(
        status_of(&t, &card.request_id),
        ("handed_off_local".to_owned(), Some("desktop".to_owned()))
    );
    // the full daemon version (bye + closed listener + audit) is e2e_link / e2e_approvals
}

// ---- 19. deny ------------------------------------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_19_deny_answers_a_deny_with_the_reason_and_never_an_allow() {
    let t = Arc::new(HttpHarness::new().await);
    let phone = t.h.add_phone("Galaxy");
    let held = start_held(&t, "cargo test").await;
    let card = t.h.broker.pending_cards().await.remove(0);
    let mut d = t.h.phone_decision(&card, &phone.device_id, Decision::Deny);
    d.reason = Some("not now".into());
    assert!(t.h.broker.apply_decision(d).await.accepted);
    let (s, b) = held.await.unwrap();
    assert_eq!(s, 200);
    assert_no_allow(s, &b);
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["hookSpecificOutput"]["decision"]["interrupt"], false);
    assert!(v["hookSpecificOutput"]["decision"]["message"]
        .as_str()
        .unwrap()
        .contains("not now"));
}

// ---- 20. deny and stop -------------------------------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn row_20_deny_and_stop_answers_deny_with_interrupt() {
    let t = Arc::new(HttpHarness::new().await);
    let phone = t.h.add_phone("Galaxy");
    let held = start_held(&t, "cargo test").await;
    let card = t.h.broker.pending_cards().await.remove(0);
    assert!(
        t.h.broker
            .apply_decision(t.h.phone_decision(&card, &phone.device_id, Decision::DenyAndStop))
            .await
            .accepted
    );
    let (s, b) = held.await.unwrap();
    assert_no_allow(s, &b);
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["hookSpecificOutput"]["decision"]["interrupt"], true);
    assert_eq!(
        t.h.row(&card.request_id).outcome.as_deref(),
        Some("denied_and_stopped")
    );
}

// ---- the table itself ------------------------------------------------------------------------------------------------------------------------------------

#[test]
fn the_matrix_has_one_test_per_row_of_the_security_table() {
    // 20 rows in docs/security.md 7; this file has row_01 .. row_20
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/failclosed_matrix.rs"),
    )
    .unwrap();
    for n in 1..=20 {
        assert!(
            src.contains(&format!("async fn row_{n:02}_")),
            "row {n} missing"
        );
    }
    let doc = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs/security.md"),
    )
    .unwrap();
    let section = doc.split("## 7. Fail-closed").nth(1).expect("section 7");
    let section = section.split("\n## 8.").next().unwrap();
    let rows = section
        .lines()
        .filter(|l| l.starts_with("| ") && !l.starts_with("| ---") && !l.starts_with("| 상황"))
        .count();
    assert_eq!(rows, 20, "the security table changed: update the matrix");
}
