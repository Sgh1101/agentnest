//! The whole approval path against a real daemon: held `PermissionRequest` over loopback HTTP, the card over the pinned
//! WSS link, the decision back, the JSON the agent receives (docs/security.md 6, 7, I4-I6; claude-code.md 4.1).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::{Duration, Instant};

use agentnest_protocol::{ApprovalOutcome, Decision, DecisionResultReason, Message, ResolvedBy};
use common::e2e::*;
use common::harness::{eventually, permission_request};
use serde_json::{json, Value};

fn fast(o: &mut agentnest_core::daemon::DaemonOptions, _: &mut agentnest_core::config::AppConfig) {
    o.timing.auth_fail_delay_ms = 50;
    o.timing.preauth_ms = 2_000;
    o.tick_ms = 25;
}

fn allow_body() -> Value {
    json!({"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "allow"}}})
}

async fn wait_pending(e: &E2e, n: usize) {
    for _ in 0..500 {
        if e.dm.approvals_pending().await.map(|v| v.len()).unwrap_or(0) == n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {n} pending approvals");
}

fn status_of(e: &E2e, request_id: &str) -> String {
    e.dm.store()
        .get_approval(request_id)
        .unwrap()
        .unwrap()
        .status
}

// ---- the happy paths ---------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn hold_card_decision_http_json_for_allow_deny_and_deny_and_stop() {
    let e = E2e::start_with(fast).await;
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;

    // allow
    let held = e.hold(permission_request("s1", "cargo test -p agentnest-core"));
    let (card, _seq) = ws.recv_card().await;
    assert_eq!(card.tool_name, "Bash");
    assert!(card.expires_at > card.created_at);
    assert!(!held.is_finished(), "the agent waits while nobody decided");
    let r = ws.decide(Phone::decision_for(&card, Decision::Allow)).await;
    assert!(r.accepted, "{r:?}");
    assert_eq!(r.reason, DecisionResultReason::Applied);
    let (status, body) = held.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        allow_body(),
        "no updatedInput, no updatedPermissions"
    );
    let f = ws.recv_type("approval_resolved").await;
    let Message::ApprovalResolved(res) = f.message else {
        unreachable!()
    };
    assert_eq!(res.request_id, card.request_id);
    assert_eq!(res.outcome, ApprovalOutcome::Allowed);
    assert_eq!(res.resolved_by, ResolvedBy::Phone);
    assert_eq!(res.delivery, agentnest_protocol::Delivery::Delivered);
    let row =
        e.dm.store()
            .get_approval(&card.request_id)
            .unwrap()
            .unwrap();
    assert_eq!(
        (row.status.as_str(), row.outcome.as_deref()),
        ("resolved", Some("allowed"))
    );

    // deny with a reason
    let held = e.hold(permission_request("s1", "cargo build --release"));
    let (card, _) = ws.recv_card().await;
    let mut d = Phone::decision_for(&card, Decision::Deny);
    d.reason = Some("nicht jetzt".into());
    assert!(ws.decide(d).await.accepted);
    let (status, body) = held.await.unwrap();
    assert_eq!(status, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    let dec = &v["hookSpecificOutput"]["decision"];
    assert_eq!(dec["behavior"], "deny");
    assert_eq!(dec["interrupt"], false);
    assert!(dec["message"].as_str().unwrap().contains("nicht jetzt"));
    assert!(dec.get("updatedInput").is_none());

    // deny and stop
    let held = e.hold(permission_request("s1", "cargo bench"));
    let (card, _) = ws.recv_card().await;
    assert!(
        ws.decide(Phone::decision_for(&card, Decision::DenyAndStop))
            .await
            .accepted
    );
    let (status, body) = held.await.unwrap();
    assert_eq!(status, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["hookSpecificOutput"]["decision"]["behavior"], "deny");
    assert_eq!(v["hookSpecificOutput"]["decision"]["interrupt"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replayed_decision_changes_nothing_and_the_agent_hears_one_answer() {
    let e = E2e::start_with(fast).await;
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    let held = e.hold(permission_request("s1", "cargo test"));
    let (card, _) = ws.recv_card().await;
    let d = Phone::decision_for(&card, Decision::Allow);
    // the very same envelope text sent twice (a network-level replay) plus a re-built decision
    let id = ws.send(Message::Decision(d.clone())).await;
    let first = ws.recv_type("decision_result").await;
    let Message::DecisionResult(first) = first.message else {
        unreachable!()
    };
    assert!(first.accepted);
    assert_eq!(first.in_reply_to, id);
    let second = ws.decide(d.clone()).await;
    assert!(!second.accepted);
    assert_eq!(second.reason, DecisionResultReason::AlreadyResolved);
    // and a flipped decision for the same card
    let flip = ws.decide(Phone::decision_for(&card, Decision::Deny)).await;
    assert!(!flip.accepted);
    let (status, body) = held.await.unwrap();
    assert_eq!(
        (status, serde_json::from_str::<Value>(&body).unwrap()),
        (200, allow_body())
    );
    let decisions = e.dm.store().list_decisions(&card.request_id).unwrap();
    assert_eq!(
        decisions
            .iter()
            .filter(|d| d.verify_result == "APPLIED")
            .count(),
        1
    );
    assert_eq!(
        e.dm.store()
            .get_approval(&card.request_id)
            .unwrap()
            .unwrap()
            .outcome
            .as_deref(),
        Some("allowed")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn binding_and_confirmation_failures_keep_the_request_pending_until_a_valid_decision() {
    let e = E2e::start_with(fast).await;
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    let held = e.hold(permission_request("s1", "rm -rf /"));
    let (card, _) = ws.recv_card().await;
    assert_eq!(
        card.risk.level.effective(),
        agentnest_protocol::RiskLevel::Critical
    );
    // wrong nonce
    let mut d = Phone::decision_for(&card, Decision::Allow);
    d.nonce_b64 = agentnest_protocol::Secret::new(agentnest_protocol::qr::b64_encode(&[9u8; 16]));
    assert_eq!(
        ws.decide(d).await.reason,
        DecisionResultReason::BindingMismatch
    );
    // wrong tool input hash
    let mut d = Phone::decision_for(&card, Decision::Allow);
    d.tool_input_sha256 = "0".repeat(64);
    assert_eq!(
        ws.decide(d).await.reason,
        DecisionResultReason::InputHashMismatch
    );
    // missing extra confirmation on a critical allow
    let mut d = Phone::decision_for(&card, Decision::Allow);
    d.extra_confirmation = None;
    assert_eq!(
        ws.decide(d).await.reason,
        DecisionResultReason::ExtraConfirmationRequired
    );
    assert!(!held.is_finished());
    assert_eq!(status_of(&e, &card.request_id), "pending");
    let decisions = e.dm.store().list_decisions(&card.request_id).unwrap();
    assert_eq!(decisions.len(), 3, "every attempt is recorded");
    assert!(decisions.iter().all(|d| d.verify_result != "APPLIED"));
    // the fully confirmed decision still works
    assert!(
        ws.decide(Phone::decision_for(&card, Decision::Allow))
            .await
            .accepted
    );
    let (status, _) = held.await.unwrap();
    assert_eq!(status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn two_devices_racing_exactly_one_wins_and_the_agent_gets_exactly_that_answer() {
    let e = E2e::start_with(fast).await;
    let (_a, mut wa) = e.pair_ready("Phone A").await;
    let (_b, mut wb) = e.pair_ready("Phone B").await;
    e.wait_online(2).await;
    let held = e.hold(permission_request("s1", "cargo test"));
    let (ca, _) = wa.recv_card().await;
    let (cb, _) = wb.recv_card().await;
    assert_eq!(ca.request_id, cb.request_id);
    let da = Phone::decision_for(&ca, Decision::Allow);
    let db = Phone::decision_for(&cb, Decision::Deny);
    let (ra, rb) = tokio::join!(wa.decide(da), wb.decide(db));
    assert_eq!(
        [&ra, &rb].iter().filter(|r| r.accepted).count(),
        1,
        "{ra:?} {rb:?}"
    );
    let loser = if ra.accepted { &rb } else { &ra };
    assert_eq!(loser.reason, DecisionResultReason::AlreadyResolved);
    let (status, body) = held.await.unwrap();
    assert_eq!(status, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    let row = e.dm.store().get_approval(&ca.request_id).unwrap().unwrap();
    match row.outcome.as_deref() {
        Some("allowed") => assert_eq!(v, allow_body()),
        Some("denied") => assert_eq!(v["hookSpecificOutput"]["decision"]["behavior"], "deny"),
        other => panic!("unexpected outcome {other:?}"),
    }
    // both phones learn the result
    for ws in [&mut wa, &mut wb] {
        let f = ws.recv_type("approval_resolved").await;
        let Message::ApprovalResolved(r) = f.message else {
            unreachable!()
        };
        assert_eq!(r.request_id, ca.request_id);
    }
}

// ---- fail-closed over the real stack ---------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn with_no_online_device_the_hold_is_an_immediate_empty_204() {
    let e = E2e::start_with(fast).await;
    let began = Instant::now();
    let (s, b) = e
        .hook_post(
            "/v1/hooks/claude-code",
            permission_request("s1", "cargo test"),
        )
        .await;
    assert_eq!((s, b.as_str()), (204, ""));
    assert!(began.elapsed() < Duration::from_secs(2));
    // a paired but offline phone is the same
    let (_p, ws) = e.pair_ready("Pixel").await;
    drop(ws);
    for _ in 0..200 {
        if e.dm.debug_online_devices().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (s, b) = e
        .hook_post(
            "/v1/hooks/claude-code",
            permission_request("s2", "cargo test"),
        )
        .await;
    assert_eq!((s, b.as_str()), (204, ""));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unanswered_card_expires_with_an_empty_204_and_the_phone_is_told() {
    let e = E2e::start_with(|o, c| {
        fast(o, c);
        o.ttl_override_ms = Some(1_200);
    })
    .await;
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    let began = Instant::now();
    let held = e.hold(permission_request("s1", "cargo test"));
    let (card, _) = ws.recv_card().await;
    let (status, body) = held.await.unwrap();
    assert_eq!((status, body.as_str()), (204, ""));
    assert!(
        began.elapsed() >= Duration::from_millis(1_000),
        "not before the TTL: {:?}",
        began.elapsed()
    );
    let f = ws.recv_type("approval_resolved").await;
    let Message::ApprovalResolved(r) = f.message else {
        unreachable!()
    };
    assert_eq!(r.outcome, ApprovalOutcome::Expired);
    assert_eq!(r.resolved_by, ResolvedBy::Timeout);
    // a late decision is refused and never reaches the agent
    let late = ws.decide(Phone::decision_for(&card, Decision::Allow)).await;
    assert!(!late.accepted);
    assert!(
        matches!(
            late.reason,
            DecisionResultReason::Expired | DecisionResultReason::AlreadyResolved
        ),
        "{:?}",
        late.reason
    );
    assert_eq!(status_of(&e, &card.request_id), "expired");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_phone_that_disconnects_hands_the_request_off_after_the_grace_period() {
    let e = E2e::start_with(|o, c| {
        fast(o, c);
        o.grace_override_ms = Some(500);
    })
    .await;
    let (paired, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    let held = e.hold(permission_request("s1", "cargo test"));
    let (card, _) = ws.recv_card().await;
    let gone = Instant::now();
    ws.close().await;
    let (status, body) = held.await.unwrap();
    assert_eq!((status, body.as_str()), (204, ""));
    assert!(
        gone.elapsed() >= Duration::from_millis(400),
        "{:?}",
        gone.elapsed()
    );
    let row =
        e.dm.store()
            .get_approval(&card.request_id)
            .unwrap()
            .unwrap();
    assert_eq!(
        (row.status.as_str(), row.resolved_by.as_deref()),
        ("handed_off_local", Some("system"))
    );

    // a phone that returns inside the grace period keeps the request alive
    let mut ws = e.connect_ready(&paired).await;
    e.wait_online(1).await;
    let held = e.hold(permission_request("s2", "cargo build"));
    let (card, _) = ws.recv_card().await;
    ws.close().await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let mut ws2 = e.hello(&paired, 0, true).await;
    ws2.recv_type("welcome").await;
    let snap = ws2.recv_type("snapshot").await;
    let Message::Snapshot(s) = snap.message else {
        unreachable!()
    };
    assert!(
        s.pending_approval_ids_complete.contains(&card.request_id),
        "the pending card survives in the snapshot"
    );
    let card2 = s
        .pending_approvals
        .iter()
        .find(|c| c.request_id == card.request_id)
        .expect("card inside the snapshot")
        .clone();
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(!held.is_finished(), "still held: the phone is back");
    assert!(
        ws2.decide(Phone::decision_for(&card2, Decision::Allow))
            .await
            .accepted
    );
    assert_eq!(held.await.unwrap().0, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_restart_expires_every_pending_request_and_nothing_is_ever_allowed() {
    let e = E2e::start_with(fast).await;
    let (paired, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    let held = e.hold_result(permission_request("s1", "cargo test"));
    let (card, _) = ws.recv_card().await;
    assert_eq!(status_of(&e, &card.request_id), "pending");
    // crash: no shutdown command, the hook connection just dies
    let e = e.crash_and_restart(fast).await;
    let result = held.await.unwrap();
    match result {
        Err(_) => {}
        Ok((status, body)) => assert!(
            status == 204 && body.is_empty(),
            "never an answer: {status} {body}"
        ),
    }
    let row =
        e.dm.store()
            .get_approval(&card.request_id)
            .unwrap()
            .unwrap();
    assert_eq!(row.status, "expired");
    assert_eq!(row.resolved_by.as_deref(), Some("system"));
    assert!(e.dm.approvals_pending().await.unwrap().is_empty());
    // the phone reconnects: the snapshot has no pending card, an old decision is refused
    let mut ws2 = e.hello(&paired, 0, true).await;
    ws2.recv_type("welcome").await;
    let snap = ws2.recv_type("snapshot").await;
    let Message::Snapshot(s) = snap.message else {
        unreachable!()
    };
    assert!(s.pending_approvals.is_empty());
    assert!(s.pending_approval_ids_complete.is_empty());
    let r = ws2
        .decide(Phone::decision_for(&card, Decision::Allow))
        .await;
    assert!(!r.accepted);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_graceful_shutdown_hands_pending_requests_to_the_local_prompt() {
    let e = E2e::start_with(fast).await;
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    let held = e.hold_result(permission_request("s1", "cargo test"));
    let (card, _) = ws.recv_card().await;
    e.dm.shutdown().await.unwrap();
    match held.await.unwrap() {
        Err(_) => {}
        Ok((status, body)) => assert!(status == 204 && body.is_empty(), "{status} {body}"),
    }
    let row =
        e.dm.store()
            .get_approval(&card.request_id)
            .unwrap()
            .unwrap();
    assert_ne!(row.status, "pending");
    assert_ne!(row.outcome.as_deref(), Some("allowed"));
}

#[tokio::test(flavor = "multi_thread")]
async fn revoking_the_only_online_device_hands_the_pending_request_off_with_no_decision() {
    let e = E2e::start_with(fast).await;
    let (paired, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    let held = e.hold(permission_request("s1", "cargo test"));
    let (card, _) = ws.recv_card().await;
    e.dm.device_revoke(&paired.device_id, "Pixel")
        .await
        .unwrap();
    let (status, body) = held.await.unwrap();
    assert_eq!((status, body.as_str()), (204, ""));
    assert_eq!(status_of(&e, &card.request_id), "handed_off_local");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_desktop_can_hand_a_request_off_or_decide_it_through_the_same_transition() {
    let e = E2e::start_with(fast).await;
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    // hand off
    let held = e.hold(permission_request("s1", "cargo test"));
    let (card, _) = ws.recv_card().await;
    e.dm.approval_handoff_local(&card.request_id).await.unwrap();
    let (status, body) = held.await.unwrap();
    assert_eq!((status, body.as_str()), (204, ""));
    let f = ws.recv_type("approval_resolved").await;
    let Message::ApprovalResolved(r) = f.message else {
        unreachable!()
    };
    assert_eq!(
        (r.outcome, r.resolved_by),
        (ApprovalOutcome::HandedOffLocal, ResolvedBy::Desktop)
    );
    // desktop allow of a low-risk card
    let held = e.hold(permission_request("s1", "cargo build"));
    let (card, _) = ws.recv_card().await;
    let out =
        e.dm.approval_decide_local(
            &card.request_id,
            Decision::Allow,
            &card.tool_input_sha256,
            false,
            None,
        )
        .await
        .unwrap();
    assert!(out.accepted, "{out:?}");
    let (status, body) = held.await.unwrap();
    assert_eq!(
        (status, serde_json::from_str::<Value>(&body).unwrap()),
        (200, allow_body())
    );
    let f = ws.recv_type("approval_resolved").await;
    let Message::ApprovalResolved(r) = f.message else {
        unreachable!()
    };
    assert_eq!(
        (r.outcome, r.resolved_by),
        (ApprovalOutcome::Allowed, ResolvedBy::Desktop)
    );
    // a wrong echoed hash is refused and the request stays pending
    let held = e.hold(permission_request("s1", "cargo bench"));
    let (card, _) = ws.recv_card().await;
    let out =
        e.dm.approval_decide_local(
            &card.request_id,
            Decision::Allow,
            &"0".repeat(64),
            false,
            None,
        )
        .await
        .unwrap();
    assert!(!out.accepted);
    assert_eq!(status_of(&e, &card.request_id), "pending");
    e.dm.approval_handoff_local(&card.request_id).await.unwrap();
    assert_eq!(held.await.unwrap().0, 204);
}

#[tokio::test(flavor = "multi_thread")]
async fn pausing_remote_approval_hands_new_requests_off_and_refuses_pending_decisions() {
    let e = E2e::start_with(fast).await;
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    let held = e.hold(permission_request("s1", "cargo test"));
    let (card, _) = ws.recv_card().await;
    e.dm.remote_approval_pause(true).await.unwrap();
    let r = ws.decide(Phone::decision_for(&card, Decision::Allow)).await;
    assert_eq!(r.reason, DecisionResultReason::Paused);
    assert!(!held.is_finished());
    let (s, b) = e
        .hook_post(
            "/v1/hooks/claude-code",
            permission_request("s2", "cargo build"),
        )
        .await;
    assert_eq!((s, b.as_str()), (204, ""));
    e.dm.remote_approval_pause(false).await.unwrap();
    assert!(
        ws.decide(Phone::decision_for(&card, Decision::Allow))
            .await
            .accepted
    );
    assert_eq!(held.await.unwrap().0, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn disabling_the_link_hands_every_pending_request_to_the_local_prompt() {
    let e = E2e::start_with(fast).await;
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    let h1 = e.hold(permission_request("s1", "cargo test"));
    let h2 = e.hold(permission_request("s2", "cargo build"));
    let _ = ws.recv_card().await;
    let _ = ws.recv_card().await;
    wait_pending(&e, 2).await;
    e.dm.link_set_enabled(false).await.unwrap();
    for h in [h1, h2] {
        let (s, b) = h.await.unwrap();
        assert_eq!((s, b.as_str()), (204, ""));
    }
    let rows = e.dm.store().list_pending_approvals(None).unwrap();
    assert!(rows.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn when_claude_hangs_up_first_the_request_is_superseded_and_a_late_decision_never_answers() {
    use std::io::Write;
    use std::net::TcpStream;
    let e = E2e::start_with(fast).await;
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    let body = permission_request("s1", "cargo test").to_string();
    let port = e.dm.hook_port();
    let token = e.token();
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        sock,
        "POST /v1/hooks/claude-code HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-AgentNest-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    sock.flush().unwrap();
    let (card, _) = ws.recv_card().await;
    drop(sock);
    let id = card.request_id.clone();
    let st = e.dm.store().clone();
    eventually("superseded", move || {
        let row = st.get_approval(&id).unwrap().unwrap();
        (row.status == "superseded").then_some(())
    })
    .await;
    let f = ws.recv_type("approval_resolved").await;
    let Message::ApprovalResolved(r) = f.message else {
        unreachable!()
    };
    assert_eq!(
        (r.outcome, r.resolved_by),
        (ApprovalOutcome::Superseded, ResolvedBy::Agent)
    );
    let late = ws.decide(Phone::decision_for(&card, Decision::Allow)).await;
    assert!(!late.accepted);
    assert_eq!(late.reason, DecisionResultReason::AlreadyResolved);
}

// ---- guards over the real daemon ----------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn the_collector_checks_token_and_origin_and_is_loopback_only() {
    let e = E2e::start_with(fast).await;
    let url = e.hook_url("/v1/hooks/claude-code");
    let body = permission_request("s1", "cargo test")
        .to_string()
        .into_bytes();
    let (s, b) = request_blocking("POST", &url, &[], Some(body.clone()));
    assert_eq!((s, b.as_str()), (401, ""));
    let (s, _) = request_blocking(
        "POST",
        &url,
        &[("X-AgentNest-Token", "an_hk_wrong")],
        Some(body.clone()),
    );
    assert_eq!(s, 401);
    let token = e.token();
    for h in [
        ("Origin", "http://evil.example"),
        ("Sec-Fetch-Site", "cross-site"),
    ] {
        let (s, _) = request_blocking(
            "POST",
            &url,
            &[("X-AgentNest-Token", &token), h],
            Some(body.clone()),
        );
        assert_eq!(s, 403, "{h:?}");
    }
    let (s, b) = request_blocking("GET", &e.hook_url("/v1/health"), &[], None);
    assert_eq!(s, 200);
    assert!(!b.contains(&token));
    // loopback only: the machine's other addresses refuse the connection
    let port = e.dm.hook_port();
    for ip in local_ip_address::list_afinet_netifas()
        .unwrap_or_default()
        .into_iter()
        .map(|(_, ip)| ip)
    {
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        let addr = std::net::SocketAddr::new(ip, port);
        assert!(
            std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_err(),
            "the collector answers on {ip}"
        );
    }
    // the link listens on the configured LAN address, never on the unspecified one
    assert!(!e.link_addr().ip().is_unspecified());
}

#[tokio::test(flavor = "multi_thread")]
async fn no_secret_and_no_raw_hook_body_reaches_the_database_or_the_wire_frames() {
    let e = E2e::start_with(fast).await;
    let started = e.begin_qr().await;
    let pairing_secret = started.payload.pairing_secret.expose().to_owned();
    let mut a = e.pair_with(started, "Pixel", Tweak::None).await;
    let _ = a.pending_sas().await;
    e.dm.pairing_confirm(&a.pairing_id, true).await.unwrap();
    let mut paired = a.finish().await;
    let mut ws = paired.ws.take().unwrap();
    ws.recv_type("welcome").await;
    ws.recv_type("snapshot").await;
    e.wait_online(1).await;
    // observation hooks carrying bodies that must never be stored
    let marker = "RAWBODY_MARKER_7f3a9c";
    let file_body = format!("{marker} {}", "x".repeat(6_000));
    let (s, _) = e
        .hook_post(
            "/v1/hooks/claude-code",
            json!({
                "hook_event_name": "PostToolUse", "session_id": "s1", "cwd": "C:\\dev\\p", "permission_mode": "default",
                "tool_name": "Write", "tool_use_id": "toolu_w1",
                "tool_input": {"file_path": "C:\\dev\\p\\a.txt", "content": file_body},
                "tool_response": {"filePath": "C:\\dev\\p\\a.txt", "success": true, "stdout": format!("{marker}-stdout")}
            }),
        )
        .await;
    assert_eq!(s, 204);
    // a held approval with a token-looking value in the command
    let secret_cmd =
        "curl -H 'Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz0123' https://example.test";
    let held = e.hold(permission_request("s1", secret_cmd));
    let (card, _) = ws.recv_card().await;
    assert!(
        ws.decide(Phone::decision_for(&card, Decision::Deny))
            .await
            .accepted
    );
    held.await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut hay = std::fs::read(e.dir.path().join("agentnest.db")).unwrap();
    for ext in ["agentnest.db-wal", "agentnest.db-shm"] {
        hay.extend(std::fs::read(e.dir.path().join(ext)).unwrap_or_default());
    }
    let must_not_appear = [
        ("hook token", e.token()),
        ("device token", paired.token.clone()),
        ("pairing secret", pairing_secret),
        ("raw file content", marker.to_owned()),
        ("api key", "sk-abcdefghijklmnopqrstuvwxyz0123".to_owned()),
    ];
    for (what, needle) in must_not_appear {
        let found = hay.windows(needle.len()).any(|w| w == needle.as_bytes());
        assert!(!found, "{what} is in the database");
    }
    // the frames the PC sent never repeat the device token or the hook token
    let all = ws.raw.join("\n");
    let with_token: Vec<&String> = ws
        .raw
        .iter()
        .filter(|f| f.contains(&paired.token))
        .collect();
    assert_eq!(with_token.len(), 1, "the device token travels exactly once");
    assert!(with_token[0].contains("\"type\":\"pair_result\""));
    assert!(!all.contains(&e.token()));
    assert!(!all.contains(marker), "raw bodies never go to the phone");
    // the pairing connection's own frames carried the token exactly once
    // (pair_result), which `finish()` consumed before `ws` took over
}

/// Review item 6 (protocol.md 8.4 "a dead card is never revived"): a phone that never acked a card must not get it again
/// after the request was resolved. The un-acked tracking used to survive `approval_resolved` and re-sent the card up to
/// three times.
#[tokio::test(flavor = "multi_thread")]
async fn a_resolved_card_is_not_resent_to_a_phone_that_never_acked_it() {
    let e = E2e::start_with(|o, c| {
        fast(o, c);
        o.timing.ack_retry_ms = 100; // the session re-checks every 500 ms
    })
    .await;
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    let held = e.hold(permission_request("s1", "cargo test"));
    // the card arrives; the phone does NOT ack it
    let f = ws.recv_type("approval_request").await;
    let Message::ApprovalRequest(card) = f.message else {
        unreachable!()
    };
    e.dm.approval_handoff_local(&card.request_id).await.unwrap();
    assert_eq!(held.await.unwrap().0, 204);
    let resolved = ws.recv_type("approval_resolved").await;
    assert!(matches!(resolved.message, Message::ApprovalResolved(_)));
    // 2.5 s = several re-send rounds: nothing but quiet (or other frames) may arrive, never the dead card again
    let end = Instant::now() + Duration::from_millis(2500);
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match ws.next(left).await {
            Got::Frame(f) => assert_ne!(
                f.message.type_name(),
                "approval_request",
                "a resolved card was re-sent"
            ),
            Got::Timeout => break,
            Got::Closed(c) => panic!("the connection closed: {c:?}"),
        }
    }
}
