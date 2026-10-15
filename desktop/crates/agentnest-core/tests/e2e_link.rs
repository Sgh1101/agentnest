//! The WSS link against a real daemon: pairing, authentication, pre-auth behaviour, close codes, resync, paging, rate
//! limits and the connection caps (docs/protocol.md 1-9, docs/security.md 4, 5, 11, I1, I6, I7).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::{Duration, Instant};

use agentnest_core::daemon::CommandError;
use agentnest_core::state::timers::ManualClock;
use agentnest_protocol::{
    ByeReason, ErrorCode, EventsRequestPayload, Message, PingPayload, ResyncMode,
    SnapshotRequestPayload, UnpairPayload,
};
use common::e2e::*;
use serde_json::{json, Value};

fn fast(o: &mut agentnest_core::daemon::DaemonOptions, _: &mut agentnest_core::config::AppConfig) {
    o.timing.auth_fail_delay_ms = 50;
    o.timing.preauth_ms = 800;
    o.timing.pair_confirm_ms = 3_000;
}

fn read_all(dir: &std::path::Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).unwrap_or_default()
}

fn contains(hay: &[u8], needle: &str) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

// ---- pairing ----------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn pairing_happy_path_sas_agrees_and_the_token_is_stored_as_a_hash_only() {
    let e = E2e::start_with(fast).await;
    let mut attempt = e.pair_attempt("Pixel 9").await;
    let phone_sas = attempt.pending_sas().await;
    let pc_sas = attempt.pc_sas().await;
    assert_eq!(
        phone_sas, attempt.want_sas,
        "the SAS the PC sent is the one the phone computes"
    );
    assert_eq!(pc_sas, phone_sas, "the PC UI shows the same SAS");
    // nothing is registered before the PC user confirms (I7)
    assert!(e.dm.devices_list().await.unwrap().is_empty());
    e.dm.pairing_confirm(&attempt.pairing_id, true)
        .await
        .unwrap();
    let mut paired = attempt.finish().await;
    assert!(paired.device_id.starts_with("dev_"));
    assert!(paired.token.len() >= 40);
    let devices = e.dm.devices_list().await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name, "Pixel 9");
    assert!(devices[0].revoked_at.is_none());
    // the pairing connection goes on as an authenticated session
    let mut ws = paired.ws.take().unwrap();
    let w = ws.recv_type("welcome").await;
    let Message::Welcome(w) = w.message else {
        unreachable!()
    };
    assert_eq!(w.resync.mode, ResyncMode::Snapshot);
    assert_eq!(w.protocol.version, 1);
    assert_eq!(w.hosts.port, e.link_addr().port());
    assert!(w.capabilities.iter().any(|c| c == "approvals"));
    assert_eq!(w.limits.approval_ttl_s, 120);
    ws.recv_type("snapshot").await;
    // the token reached the phone exactly once and is nowhere on the PC in clear
    e.dm.shutdown().await.unwrap();
    let db = read_all(e.dir.path(), "agentnest.db");
    let wal = read_all(e.dir.path(), "agentnest.db-wal");
    assert!(
        !contains(&db, &paired.token) && !contains(&wal, &paired.token),
        "device token stored in clear"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_used_qr_cannot_pair_a_second_phone() {
    let e = E2e::start_with(fast).await;
    let started = e.begin_qr().await;
    let first = e.pair_with(started.clone(), "A", Tweak::None).await;
    let mut first = first;
    let _ = first.pending_sas().await;
    e.dm.pairing_confirm(&first.pairing_id, true).await.unwrap();
    let paired = first.finish().await;
    assert!(!paired.device_id.is_empty());
    let second = e.pair_with(started, "B", Tweak::None).await;
    let (code, close) = second.expect_failure().await;
    assert_eq!(code, Some(ErrorCode::PairFailed));
    assert_eq!(close, 4002);
    assert_eq!(e.dm.devices_list().await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_proof_fails_with_4002_registers_nothing_and_the_qr_survives_one_failure() {
    let e = E2e::start_with(fast).await;
    let started = e.begin_qr().await;
    let bad = e
        .pair_with(started.clone(), "Mallory", Tweak::WrongProof)
        .await;
    let began = Instant::now();
    let (code, close) = bad.expect_failure().await;
    assert_eq!((code, close), (Some(ErrorCode::PairFailed), 4002));
    assert!(began.elapsed() < Duration::from_secs(3));
    assert!(e.dm.devices_list().await.unwrap().is_empty());
    // the legitimate phone still pairs with the same QR
    let mut good = e.pair_with(started, "Pixel", Tweak::None).await;
    let _ = good.pending_sas().await;
    e.dm.pairing_confirm(&good.pairing_id, true).await.unwrap();
    good.finish().await;
    assert_eq!(e.dm.devices_list().await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn three_failed_proofs_burn_the_qr_even_for_the_right_phone() {
    let e = E2e::start_with(fast).await;
    let started = e.begin_qr().await;
    for i in 0..3 {
        let tweak = if i == 1 {
            Tweak::WrongChallenge
        } else {
            Tweak::WrongProof
        };
        let a = e.pair_with(started.clone(), "Mallory", tweak).await;
        let (code, close) = a.expect_failure().await;
        assert_eq!(
            (code, close),
            (Some(ErrorCode::PairFailed), 4002),
            "attempt {i}"
        );
    }
    let right = e.pair_with(started, "Pixel", Tweak::None).await;
    let (code, close) = right.expect_failure().await;
    assert_eq!(
        (code, close),
        (Some(ErrorCode::PairFailed), 4002),
        "the QR is burned"
    );
    assert!(e.dm.devices_list().await.unwrap().is_empty());
    let st = e.dm.status().await.unwrap();
    assert!(!st.pairing_active);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_pairing_id_never_burns_the_real_qr() {
    let e = E2e::start_with(fast).await;
    let started = e.begin_qr().await;
    for _ in 0..3 {
        let a = e
            .pair_with(started.clone(), "Mallory", Tweak::UnknownPairingId)
            .await;
        let (code, _) = a.expect_failure().await;
        assert_eq!(code, Some(ErrorCode::PairFailed));
    }
    let mut good = e.pair_with(started, "Pixel", Tweak::None).await;
    let _ = good.pending_sas().await;
    e.dm.pairing_confirm(&good.pairing_id, true).await.unwrap();
    good.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_pc_user_can_reject_the_pairing_after_comparing_the_sas() {
    let e = E2e::start_with(fast).await;
    let mut a = e.pair_attempt("Suspicious").await;
    let _ = a.pending_sas().await;
    e.dm.pairing_confirm(&a.pairing_id, false).await.unwrap();
    let (code, close) = a.expect_failure().await;
    assert_eq!((code, close), (Some(ErrorCode::PairRejected), 4002));
    assert!(e.dm.devices_list().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unanswered_confirmation_times_out_as_a_rejection() {
    let e = E2e::start_with(|o, _| {
        o.timing.auth_fail_delay_ms = 20;
        o.timing.pair_confirm_ms = 400;
    })
    .await;
    let mut a = e.pair_attempt("Slow").await;
    let _ = a.pending_sas().await;
    let (code, close) = a.expect_failure().await;
    assert_eq!((code, close), (Some(ErrorCode::PairRejected), 4002));
    assert!(e.dm.devices_list().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_qr_is_refused() {
    let clock = std::sync::Arc::new(ManualClock::new(1_792_055_553_120));
    let c2 = clock.clone();
    let e = E2e::start_with(move |o, c| {
        fast(o, c);
        o.clock = c2;
    })
    .await;
    let started = e.begin_qr().await;
    clock.advance(121_000);
    let a = e.pair_with(started, "Late", Tweak::None).await;
    let (code, close) = a.expect_failure().await;
    assert_eq!((code, close), (Some(ErrorCode::PairFailed), 4002));
    assert!(e.dm.devices_list().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_needs_the_risk_acceptance_first() {
    let e = E2e::start_with(fast).await;
    assert_eq!(
        e.dm.pairing_start().await.unwrap_err(),
        CommandError::RiskNotAccepted
    );
    e.dm.risk_accept().await.unwrap();
    let started = e.dm.pairing_start().await.unwrap();
    assert!(started.uri.starts_with("agentnest://pair?d="));
    assert_eq!(
        e.dm.pairing_start().await.unwrap_err(),
        CommandError::PairingBusy
    );
}

// ---- hello ------------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn hello_with_the_device_token_is_welcomed_and_a_new_session_supersedes_the_old_one() {
    let e = E2e::start_with(fast).await;
    let (paired, mut first) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    let mut second = e.connect_ready(&paired).await;
    // the older connection learns why it ends
    let bye = first.recv_type("bye").await;
    let Message::Bye(b) = bye.message else {
        unreachable!()
    };
    assert_eq!(b.reason, ByeReason::SupersededConnection);
    assert_eq!(first.expect_close().await, 4009);
    // the new one works
    let id = second
        .send(Message::Ping(PingPayload { sent_at: now_iso() }))
        .await;
    let pong = second.recv_type("pong").await;
    let Message::Pong(p) = pong.message else {
        unreachable!()
    };
    assert_eq!(p.in_reply_to, id);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_hello_always_looks_the_same_and_is_answered_after_the_delay() {
    let e = E2e::start_with(|o, _| {
        o.timing.auth_fail_delay_ms = 300;
        o.timing.preauth_ms = 2_000;
    })
    .await;
    let (paired, ws) = e.pair_ready("Pixel").await;
    drop(ws);
    let mut wrong_token = paired.token.clone();
    wrong_token.replace_range(0..4, "AAAA");
    let cases: Vec<(&str, String, String, bool)> = vec![
        ("wrong token", paired.device_id.clone(), wrong_token, false),
        (
            "unknown device",
            "dev_unknown".to_owned(),
            paired.token.clone(),
            false,
        ),
        (
            "wrong challenge",
            paired.device_id.clone(),
            paired.token.clone(),
            true,
        ),
    ];
    for (what, device_id, token, bad_challenge) in cases {
        let mut ws = Phone::connect(e.link_addr(), &e.dm.spki_pin())
            .await
            .unwrap();
        let ch = ws.expect_challenge().await;
        let began = Instant::now();
        ws.send(Message::Hello(agentnest_protocol::HelloPayload {
            device_id,
            device_token: agentnest_protocol::Secret::new(token),
            challenge_b64: if bad_challenge {
                agentnest_protocol::qr::b64_encode(&[1u8; 16])
            } else {
                ch.challenge_b64
            },
            protocol: 1,
            app_version: None,
            last_seq: 0,
            wants_snapshot: false,
            signature_b64: None,
        }))
        .await;
        let f = ws.recv_type("error").await;
        let Message::Error(err) = f.message else {
            unreachable!()
        };
        assert_eq!(err.code, ErrorCode::AuthFailed, "{what}");
        assert!(err.fatal);
        assert!(
            began.elapsed() >= Duration::from_millis(250),
            "{what}: answered after the fixed delay"
        );
        assert_eq!(ws.expect_close().await, 4002, "{what}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn five_failed_authentications_block_the_address_even_for_valid_credentials() {
    let e = E2e::start_with(fast).await;
    let (paired, ws) = e.pair_ready("Pixel").await;
    drop(ws);
    for _ in 0..5 {
        let mut ws = Phone::connect(e.link_addr(), &e.dm.spki_pin())
            .await
            .unwrap();
        let ch = ws.expect_challenge().await;
        ws.send(Message::Hello(agentnest_protocol::HelloPayload {
            device_id: "dev_nobody".into(),
            device_token: agentnest_protocol::Secret::new("x"),
            challenge_b64: ch.challenge_b64,
            protocol: 1,
            app_version: None,
            last_seq: 0,
            wants_snapshot: false,
            signature_b64: None,
        }))
        .await;
        assert_eq!(ws.expect_close().await, 4002);
    }
    // blocked: no challenge, just the close
    let mut ws = Phone::connect(e.link_addr(), &e.dm.spki_pin())
        .await
        .unwrap();
    assert_eq!(ws.expect_silent_close().await, 4005);
    let _ = paired;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_device_is_told_with_4003_and_an_online_one_is_kicked_with_bye() {
    let e = E2e::start_with(fast).await;
    let (paired, mut online) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    // typed name must match
    assert_eq!(
        e.dm.device_revoke(&paired.device_id, "wrong")
            .await
            .unwrap_err(),
        CommandError::NameMismatch
    );
    e.dm.device_revoke(&paired.device_id, "Pixel")
        .await
        .unwrap();
    let f = online.recv_type("bye").await;
    let Message::Bye(b) = f.message else {
        unreachable!()
    };
    assert_eq!(b.reason, ByeReason::DeviceRevoked);
    assert!(!b.reconnect);
    assert_eq!(online.expect_close().await, 4003);
    // the token no longer opens a session: valid credentials of a revoked device get E_DEVICE_REVOKED + 4003
    let mut ws = e.hello(&paired, 0, true).await;
    let f = ws.recv_type("error").await;
    let Message::Error(err) = f.message else {
        unreachable!()
    };
    assert_eq!(err.code, ErrorCode::DeviceRevoked);
    assert_eq!(ws.expect_close().await, 4003);
    let devices = e.dm.devices_list().await.unwrap();
    assert!(devices[0].revoked_at.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn unpair_from_the_phone_removes_the_device_and_closes() {
    let e = E2e::start_with(fast).await;
    let (paired, mut ws) = e.pair_ready("Pixel").await;
    ws.send(Message::Unpair(UnpairPayload {
        device_id: Some(paired.device_id.clone()),
        pairing_id: None,
    }))
    .await;
    let f = ws.recv_type("bye").await;
    let Message::Bye(b) = f.message else {
        unreachable!()
    };
    assert_eq!(b.reason, ByeReason::Unpaired);
    let _ = ws.expect_close().await;
    let mut again = e.hello(&paired, 0, true).await;
    let _ = again.expect_close().await;
}

// ---- pre-auth silence (I1) --------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn before_authentication_the_pc_sends_the_challenge_and_nothing_else() {
    let e = E2e::start_with(fast).await;
    // every forbidden first frame ends in 4001 with no PC data
    let ping = json!({"v":1,"type":"ping","id":"01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e5f","ts":"2026-10-15T09:12:33.120Z","payload":{"sent_at":"2026-10-15T09:12:33.120Z"}});
    let snapshot_req = json!({"v":1,"type":"snapshot_request","id":"01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e5f","ts":"2026-10-15T09:12:33.120Z","payload":{}});
    let future = json!({"v":1,"type":"from_the_future","id":"01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e5f","ts":"2026-10-15T09:12:33.120Z","payload":{}});
    let server_type = json!({"v":1,"type":"welcome","id":"01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e5f","ts":"2026-10-15T09:12:33.120Z","seq":1,"payload":{}});
    for (what, text) in [
        ("ping", ping.to_string()),
        ("snapshot_request", snapshot_req.to_string()),
        ("unknown type", future.to_string()),
        ("server type", server_type.to_string()),
        ("garbage", "not json at all".to_owned()),
        ("empty object", "{}".to_owned()),
    ] {
        let mut ws = Phone::connect(e.link_addr(), &e.dm.spki_pin())
            .await
            .unwrap();
        ws.expect_challenge().await;
        ws.send_raw(&text).await;
        assert_eq!(ws.expect_silent_close().await, 4001, "{what}");
        assert_eq!(ws.raw.len(), 1, "{what}: only the challenge was ever sent");
    }
    // binary
    let mut ws = Phone::connect(e.link_addr(), &e.dm.spki_pin())
        .await
        .unwrap();
    ws.expect_challenge().await;
    ws.send_binary(vec![1, 2, 3]).await;
    assert_eq!(ws.expect_silent_close().await, 1003);
    // wrong protocol major
    let mut ws = Phone::connect(e.link_addr(), &e.dm.spki_pin())
        .await
        .unwrap();
    ws.expect_challenge().await;
    ws.send_raw(&ping.to_string().replace("\"v\":1", "\"v\":2"))
        .await;
    assert_eq!(ws.expect_silent_close().await, 4010);
    // too big for a phone frame (32 KiB)
    let mut ws = Phone::connect(e.link_addr(), &e.dm.spki_pin())
        .await
        .unwrap();
    ws.expect_challenge().await;
    ws.send_raw(&format!("{{\"pad\":\"{}\"}}", "a".repeat(40 * 1024)))
        .await;
    assert_eq!(ws.expect_silent_close().await, 1009);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_silent_connection_is_closed_with_4001_after_the_five_second_default() {
    let e = E2e::start().await; // default timing: 5 s
    let mut ws = Phone::connect(e.link_addr(), &e.dm.spki_pin())
        .await
        .unwrap();
    ws.expect_challenge().await;
    let began = Instant::now();
    assert_eq!(ws.expect_silent_close().await, 4001);
    let waited = began.elapsed();
    assert!(
        waited >= Duration::from_millis(4_500) && waited < Duration::from_secs(8),
        "{waited:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_pin_mismatch_and_a_missing_subprotocol_are_refused() {
    let e = E2e::start_with(fast).await;
    assert!(Phone::connect(
        e.link_addr(),
        "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    .await
    .is_err());
    assert!(Phone::connect_with(e.link_addr(), &e.dm.spki_pin(), None)
        .await
        .is_err());
    assert!(
        Phone::connect_with(e.link_addr(), &e.dm.spki_pin(), Some("other.v1"))
            .await
            .is_err()
    );
    assert!(Phone::connect(e.link_addr(), &e.dm.spki_pin())
        .await
        .is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_without_frames_is_closed_with_4008() {
    let e = E2e::start_with(|o, _| {
        o.timing.idle_close_ms = 700;
        o.timing.auth_fail_delay_ms = 20;
    })
    .await;
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    assert_eq!(ws.expect_close().await, 4008);
}

// ---- resync, snapshot, paging ----------------------------------------------------------------------------------------

fn tool_event(event: &str, id: &str) -> Value {
    json!({
        "hook_event_name": event,
        "session_id": "sess-1",
        "cwd": "C:\\dev\\agentnest",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_use_id": id,
        "tool_input": {"command": format!("echo {id}")},
        "tool_response": {"stdout": "ok"}
    })
}

async fn produce_events(e: &E2e, from: usize, n: usize) {
    // the collector answers 204 first and normalises on a worker: wait until every event is stored
    let before = e.dm.store().recent_events(10_000).unwrap().len();
    for i in from..from + n {
        let (s, _) = e
            .hook_post(
                "/v1/hooks/claude-code",
                tool_event("PostToolUse", &format!("toolu_{i}")),
            )
            .await;
        assert_eq!(s, 204);
    }
    for _ in 0..500 {
        if e.dm.store().recent_events(10_000).unwrap().len() >= before + n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the events were not stored in time");
}

#[tokio::test(flavor = "multi_thread")]
async fn live_events_reach_the_phone_with_increasing_seq_and_replay_after_a_reconnect() {
    let e = E2e::start_with(fast).await;
    let (paired, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    produce_events(&e, 0, 3).await;
    let mut last = 0;
    let mut seen_events = 0;
    while seen_events < 3 {
        let f = ws.recv().await.expect("a live frame");
        if let Some(seq) = f.seq {
            assert!(seq > last, "seq increases: {seq} after {last}");
            last = seq;
        }
        if matches!(f.message, Message::Event(_)) {
            seen_events += 1;
        }
    }
    // the phone was away for two more events
    drop(ws);
    produce_events(&e, 10, 2).await;
    let mut ws2 = e.hello(&paired, last, false).await;
    let f = ws2.recv_type("welcome").await;
    let Message::Welcome(w) = f.message else {
        unreachable!()
    };
    assert_eq!(w.resync.mode, ResyncMode::Replay, "{:?}", w.resync);
    assert!(w.resync.from_seq.unwrap() > last);
    let mut replayed = 0;
    let to = w.resync.to_seq.unwrap();
    loop {
        let f = ws2.recv().await.expect("replayed frame");
        let seq = f.seq.expect("replayed frames carry their seq");
        assert!(seq > last && seq <= to);
        if matches!(f.message, Message::Event(_)) {
            replayed += 1;
        }
        if seq == to {
            break;
        }
    }
    assert_eq!(replayed, 2);
    // nothing missed: a third connection that is up to date gets resync none
    drop(ws2);
    let mut ws3 = e.hello(&paired, to, false).await;
    let f = ws3.recv_type("welcome").await;
    let Message::Welcome(w) = f.message else {
        unreachable!()
    };
    assert_eq!(w.resync.mode, ResyncMode::None);
    // wants_snapshot always snapshots
    drop(ws3);
    let mut ws4 = e.hello(&paired, to, true).await;
    let f = ws4.recv_type("welcome").await;
    let Message::Welcome(w) = f.message else {
        unreachable!()
    };
    assert_eq!(w.resync.mode, ResyncMode::Snapshot);
    let snap = ws4.recv_type("snapshot").await;
    let Message::Snapshot(s) = snap.message else {
        unreachable!()
    };
    assert_eq!(s.sessions.len(), 1);
    assert!(!s.recent_events.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_request_answers_with_a_snapshot_and_events_request_pages_backwards() {
    let e = E2e::start_with(fast).await;
    let (_paired, mut ws) = e.pair_ready("Pixel").await;
    produce_events(&e, 0, 7).await;
    ws.send(Message::SnapshotRequest(SnapshotRequestPayload {
        reason: Some("pull_to_refresh".into()),
    }))
    .await;
    let f = ws.recv_type("snapshot").await;
    let Message::Snapshot(s) = f.message else {
        unreachable!()
    };
    assert_eq!(s.sessions.len(), 1);
    let newest = s.recent_events.last().unwrap().seq.expect("event seq");
    // page 1: three events below the newest
    let id = ws
        .send(Message::EventsRequest(EventsRequestPayload {
            session_key: Some(s.sessions[0].session_key.clone()),
            before_seq: newest,
            limit: 3,
            kinds: None,
        }))
        .await;
    let f = ws.recv_type("events_page").await;
    let Message::EventsPage(p) = f.message else {
        unreachable!()
    };
    assert_eq!(p.in_reply_to, id);
    assert_eq!(p.events.len(), 3);
    assert!(p.has_more);
    let seqs: Vec<i64> = p.events.iter().map(|e| e.seq.unwrap()).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "ascending: {seqs:?}");
    assert!(seqs.iter().all(|s| *s < newest));
    let next = p.next_before_seq.expect("cursor");
    assert_eq!(next, seqs[0]);
    // an oversized limit is clamped, unknown kinds are ignored
    ws.send(Message::EventsRequest(EventsRequestPayload {
        session_key: None,
        before_seq: next,
        limit: 10_000,
        kinds: Some(vec!["no_such_kind".into()]),
    }))
    .await;
    let f = ws.recv_type("events_page").await;
    let Message::EventsPage(p) = f.message else {
        unreachable!()
    };
    assert!(p.events.len() <= 100);
}

// ---- rate limits, caps, link disable ----------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn per_device_rate_limits_answer_e_rate_limited_and_three_strikes_close_with_4005() {
    let e = E2e::start_with(fast).await;
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    for i in 0..6 {
        let id = ws
            .send(Message::Ping(PingPayload { sent_at: now_iso() }))
            .await;
        let f = ws.recv_type("pong").await;
        let Message::Pong(p) = f.message else {
            unreachable!()
        };
        assert_eq!(p.in_reply_to, id, "ping {i}");
    }
    for strike in 1..=2 {
        ws.send(Message::Ping(PingPayload { sent_at: now_iso() }))
            .await;
        let f = ws.recv_type("error").await;
        let Message::Error(err) = f.message else {
            unreachable!()
        };
        assert_eq!(err.code, ErrorCode::RateLimited, "strike {strike}");
        assert!(!err.fatal);
    }
    ws.send(Message::Ping(PingPayload { sent_at: now_iso() }))
        .await;
    assert_eq!(ws.expect_close().await, 4005);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_decision_flood_is_rate_limited_and_unknown_requests_are_refused() {
    let e = E2e::start_with(fast).await;
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    let fake = |n: usize| agentnest_protocol::DecisionPayload {
        request_id: format!("ar_unknown_{n}"),
        session_key: "claude_code:x".into(),
        nonce_b64: agentnest_protocol::Secret::new(agentnest_protocol::qr::b64_encode(&[1u8; 16])),
        tool_input_sha256: "0".repeat(64),
        decision: agentnest_protocol::Decision::Allow,
        reason: None,
        decided_at: now_iso(),
        auth: None,
        extra_confirmation: None,
        signature_b64: None,
    };
    for n in 0..10 {
        let r = ws.decide(fake(n)).await;
        assert!(!r.accepted);
        assert_eq!(
            r.reason,
            agentnest_protocol::DecisionResultReason::UnknownRequest
        );
    }
    ws.send(Message::Decision(fake(11))).await;
    let f = ws.recv_type("error").await;
    let Message::Error(err) = f.message else {
        unreachable!()
    };
    assert_eq!(err.code, ErrorCode::RateLimited);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn the_connection_caps_answer_1013_four_pre_auth_per_address_and_sixteen_in_total() {
    use tokio::net::TcpSocket;
    let e = E2e::start_with(|o, _| {
        o.timing.preauth_ms = 20_000;
    })
    .await;
    let addr = e.link_addr();
    let pin = e.dm.spki_pin();
    async fn open_from(src: &str, addr: std::net::SocketAddr, pin: &str) -> Result<Phone, String> {
        let sock = TcpSocket::new_v4().map_err(|e| e.to_string())?;
        sock.bind(format!("{src}:0").parse().unwrap())
            .map_err(|e| e.to_string())?;
        let tcp = sock.connect(addr).await.map_err(|e| e.to_string())?;
        Phone::over_tcp(tcp, addr, pin).await
    }
    // per address: the fifth pre-auth connection gets 1013 and no frame
    let mut held = Vec::new();
    for _ in 0..4 {
        let mut p = open_from("127.0.0.2", addr, &pin).await.unwrap();
        p.expect_challenge().await;
        held.push(p);
    }
    let mut fifth = open_from("127.0.0.2", addr, &pin).await.unwrap();
    assert_eq!(fifth.expect_silent_close().await, 1013);
    // total: three more addresses with four each make 16; the next address is over the cap
    for src in ["127.0.0.3", "127.0.0.4", "127.0.0.5"] {
        for _ in 0..4 {
            let mut p = open_from(src, addr, &pin).await.unwrap();
            p.expect_challenge().await;
            held.push(p);
        }
    }
    assert_eq!(held.len(), 16);
    let mut over = open_from("127.0.0.6", addr, &pin).await.unwrap();
    assert_eq!(over.expect_silent_close().await, 1013);
    // closing one frees a slot
    held.pop().unwrap().close().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut again = open_from("127.0.0.6", addr, &pin).await.unwrap();
    again.expect_challenge().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn disabling_the_link_says_bye_without_reconnect_and_closes_the_listener() {
    let e = E2e::start_with(fast).await;
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    e.wait_online(1).await;
    e.dm.link_set_enabled(false).await.unwrap();
    let f = ws.recv_type("bye").await;
    let Message::Bye(b) = f.message else {
        unreachable!()
    };
    assert_eq!(b.reason, ByeReason::Shutdown);
    assert!(!b.reconnect, "the phone must back off");
    let _ = ws.expect_close().await;
    assert!(e.dm.link_addr().is_none());
    e.dm.link_set_enabled(true).await.unwrap();
    assert!(e.dm.link_addr().is_some());
    let mut again = Phone::connect(e.link_addr(), &e.dm.spki_pin())
        .await
        .unwrap();
    again.expect_challenge().await;
}

// ---- hosts_update -----------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn hosts_update_goes_to_every_connected_phone() {
    use agentnest_core::auth::challenge::AdmissionControl;
    use agentnest_core::auth::pairing::PairingManager;
    use agentnest_core::link::registry::ConnCommand;
    use agentnest_core::link::{LinkContext, LinkPolicy, PcInfo, Timing};
    use common::harness::Harness;
    use std::sync::{Arc, RwLock};
    let h = Harness::new();
    let phone = h.add_phone("Pixel");
    let mut phone = phone;
    let ctx = LinkContext {
        store: h.store.clone(),
        clock: h.clock.clone(),
        registry: h.registry.clone(),
        pipeline: h.pipeline.clone(),
        broker: h.broker.clone(),
        devices: h.devices.clone(),
        pairing: PairingManager::new(
            h.store.clone(),
            h.clock.clone(),
            h.audit.clone(),
            h.bus.clone(),
        ),
        admission: AdmissionControl::new(h.clock.clone()),
        audit: h.audit.clone(),
        bus: h.bus.clone(),
        pc: RwLock::new(PcInfo {
            pc_id: "pc_1".into(),
            name: "PC".into(),
            hosts: vec!["192.168.0.5".into()],
            port: 47832,
        }),
        policy: Arc::new(LinkPolicy::new(false, false, 120)),
        timing: Timing::default(),
        private_sources_only: true,
    };
    ctx.set_hosts(vec!["192.168.0.9".into(), "10.0.0.4".into()]);
    match phone.rx.recv().await {
        Some(ConnCommand::Send(Message::HostsUpdate(u))) => {
            assert_eq!(
                u.addresses,
                vec!["192.168.0.9".to_owned(), "10.0.0.4".to_owned()]
            );
            assert_eq!(u.port, 47832);
        }
        other => panic!("expected hosts_update, got {:?}", other.is_some()),
    }
    assert_eq!(ctx.pc_info().hosts.len(), 2);
}

// ---- unknown decision value over the real link --------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_decision_value_is_e_bad_message_and_nothing_else_happens() {
    let e = E2e::start_with(fast).await;
    let (_p, mut ws) = e.pair_ready("Pixel").await;
    let bad = json!({"v":1,"type":"decision","id":"01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e5f","ts":"2026-10-15T09:12:33.120Z","payload":{
        "request_id":"ar_x","session_key":"claude_code:x","nonce_b64":"AAAAAAAAAAAAAAAAAAAAAA==","tool_input_sha256":"00",
        "decision":"allow_always","decided_at":"2026-10-15T09:12:33.120Z"}});
    ws.send_raw(&bad.to_string()).await;
    let f = ws.recv_type("error").await;
    let Message::Error(err) = f.message else {
        unreachable!()
    };
    assert_eq!(err.code, ErrorCode::BadMessage);
}
