//! The loopback hook collector against real sockets (docs/security.md I8, docs/integrations/claude-code.md 4/6):
//! guard, observation replies, `PreToolUse` ask-only, the held `PermissionRequest`, disconnects, rate limit.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use agentnest_core::http::MAX_BODY_BYTES;
use agentnest_protocol::Decision;
use common::harness::*;
use serde_json::{json, Value};

fn bash_hook(event: &str, session: &str, tool_use_id: &str, command: &str) -> Value {
    json!({
        "hook_event_name": event,
        "session_id": session,
        "cwd": "C:\\dev\\agentnest",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_use_id": tool_use_id,
        "tool_input": {"command": command}
    })
}

// ---- I8: the guard -----------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_health_needs_no_token_everything_else_does() {
    let t = HttpHarness::new().await;
    let (s, body) = t.request("GET", "/v1/health", &[], None).await;
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ok"], true);
    assert!(v["version"].is_string());
    assert!(!body.contains(HOOK_TOKEN), "health carries no secret");
    for (m, p) in [("GET", "/v1/daemon"), ("POST", "/v1/hooks/claude-code"), ("POST", "/v1/hooks/codex"), ("POST", "/v1/statusline/claude-code")] {
        let (s, body) = t.request(m, p, &[], Some(b"{}".to_vec())).await;
        assert_eq!(s, 401, "{p}");
        assert!(body.is_empty(), "401 has an empty body");
    }
    let (s, body) = t.request("GET", "/v1/daemon", &[("X-AgentNest-Token", HOOK_TOKEN)], None).await;
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["wss_port"], 47832);
    assert!(v["uptime_s"].is_u64());
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_token_mismatch_is_401_for_every_wrong_value() {
    let t = HttpHarness::new().await;
    for bad in ["", "an_hk_test_token_012345678", "an_hk_test_token_01234567890", "AN_HK_TEST_TOKEN_0123456789", "x"] {
        let (s, _) = t
            .request("POST", "/v1/hooks/claude-code", &[("X-AgentNest-Token", bad)], Some(b"{}".to_vec()))
            .await;
        assert_eq!(s, 401, "{bad:?}");
    }
    // nothing was queued or stored by a rejected request
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(t.h.store.recent_events(10).unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_browser_headers_are_forbidden_even_with_a_valid_token() {
    let t = HttpHarness::new().await;
    let body = bash_hook("PostToolUse", "s1", "toolu_1", "ls").to_string().into_bytes();
    for hdr in [
        ("Origin", "http://evil.example"),
        ("Origin", "null"),
        ("Sec-Fetch-Site", "cross-site"),
        ("Sec-Fetch-Site", "same-origin"),
    ] {
        let (s, _) = t
            .request("POST", "/v1/hooks/claude-code", &[("X-AgentNest-Token", HOOK_TOKEN), hdr], Some(body.clone()))
            .await;
        assert_eq!(s, 403, "{hdr:?}");
    }
    let (s, _) = t.request("GET", "/v1/health", &[("Origin", "http://evil.example")], None).await;
    assert_eq!(s, 403, "health is guarded against browsers too");
    // a rebinding style Host header
    let (s, _) = t
        .request("POST", "/v1/hooks/claude-code", &[("X-AgentNest-Token", HOOK_TOKEN), ("Host", "evil.example:47831")], Some(body))
        .await;
    assert_eq!(s, 403);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(t.h.store.recent_events(10).unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_a_body_over_one_mebibyte_is_413() {
    let t = HttpHarness::new().await;
    let big = vec![b' '; MAX_BODY_BYTES + 1];
    let (s, _) = t
        .request("POST", "/v1/hooks/claude-code", &[("X-AgentNest-Token", HOOK_TOKEN)], Some(big))
        .await;
    assert_eq!(s, 413);
    // exactly at the limit is accepted by the guard (and rejected as malformed JSON, which is a different status)
    let at = vec![b' '; MAX_BODY_BYTES];
    let (s, _) = t
        .request("POST", "/v1/hooks/claude-code", &[("X-AgentNest-Token", HOOK_TOKEN)], Some(at))
        .await;
    assert_eq!(s, 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_malformed_bodies_are_400_and_change_nothing() {
    let t = HttpHarness::new().await;
    for body in ["", "not json", "[1,2,3]", "\"x\"", "{"] {
        let (s, _) = t
            .request("POST", "/v1/hooks/claude-code", &[("X-AgentNest-Token", HOOK_TOKEN)], Some(body.as_bytes().to_vec()))
            .await;
        assert_eq!(s, 400, "{body:?}");
    }
    // a JSON object that is not a hook is accepted and ignored (no session can be attributed)
    let (s, _) = t.post("/v1/hooks/claude-code", json!({"hello": "world"})).await;
    assert_eq!(s, 204);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(t.h.store.recent_events(10).unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_the_collector_is_bound_to_loopback_only() {
    let t = HttpHarness::new().await;
    let server = t.server.as_ref().unwrap();
    assert!(!server.addrs.is_empty());
    for a in &server.addrs {
        assert!(a.ip().is_loopback(), "{a} must be loopback");
    }
    // a connection through any non-loopback address of this machine is refused
    for ip in agentnest_core::identity::lan_addresses() {
        if ip.is_ipv4() {
            let r = TcpStream::connect_timeout(&std::net::SocketAddr::new(ip, t.port), Duration::from_millis(500));
            assert!(r.is_err(), "{ip}:{} must not accept connections", t.port);
        }
    }
    let (v4, v6) = agentnest_core::http::bind_loopback(0).unwrap();
    assert!(v4.local_addr().unwrap().ip().is_loopback());
    if let Some(v6) = v6 {
        assert!(v6.local_addr().unwrap().ip().is_loopback());
    }
}

// ---- observation hooks --------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_observation_hooks_return_204_fast_and_are_stored_and_published() {
    let t = HttpHarness::new().await;
    let mut stream = t.h.registry.subscribe();
    let started = Instant::now();
    let (s, body) = t
        .post("/v1/hooks/claude-code", bash_hook("PostToolUse", "s1", "toolu_1", "ls -la"))
        .await;
    let elapsed = started.elapsed();
    assert_eq!(s, 204);
    assert!(body.is_empty());
    assert!(elapsed < Duration::from_millis(250), "observation reply took {elapsed:?}");
    let events = eventually("the event", || {
        let e = t.h.store.recent_events(10).unwrap();
        (!e.is_empty()).then_some(e)
    })
    .await;
    assert_eq!(events[0].kind.as_str(), "command_completed");
    assert_eq!(events[0].session_key, "claude_code:s1");
    let msgs = {
        let mut out = Vec::new();
        for _ in 0..100 {
            out.extend(Harness::drain(&mut stream));
            if out.iter().any(|m| m.1 == "event") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        out
    };
    assert!(msgs.iter().any(|m| m.1 == "event"));
    // the session exists
    assert!(t.h.pipeline.session("claude_code:s1").await.is_some());
    // the adapter is reported as connected
    let adapters = t.h.pipeline.adapters().await;
    assert_eq!(adapters[0].agent_kind.as_str(), "claude_code");
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_an_identical_hook_within_two_seconds_is_stored_once() {
    let t = HttpHarness::new().await;
    let hook = bash_hook("PostToolUse", "s1", "toolu_dup", "ls");
    assert_eq!(t.post("/v1/hooks/claude-code", hook.clone()).await.0, 204);
    assert_eq!(t.post("/v1/hooks/claude-code", hook.clone()).await.0, 204);
    eventually("the first event", || (!t.h.store.recent_events(10).unwrap().is_empty()).then_some(())).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(t.h.store.recent_events(10).unwrap().len(), 1);
    // after the window the same tool_use_id is still the same call: the unique key keeps it at one row
    t.h.clock.advance(5_000);
    assert_eq!(t.post("/v1/hooks/claude-code", hook).await.0, 204);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(t.h.store.recent_events(10).unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_no_raw_hook_body_or_secret_text_reaches_the_database() {
    let t = HttpHarness::new().await;
    let mut hook = bash_hook("PostToolUse", "s9", "toolu_9", "echo hello");
    hook["tool_input"] = json!({"command": "echo hello", "content": "SUPER-SECRET-FILE-BODY-0123456789"});
    hook["tool_response"] = json!({"stdout": format!("{}password=hunter2hunter2", "x ".repeat(2000)), "exit_code": 0});
    hook["prompt"] = json!("my private prompt text that must not be stored");
    assert_eq!(t.post("/v1/hooks/claude-code", hook).await.0, 204);
    eventually("event", || (!t.h.store.recent_events(10).unwrap().is_empty()).then_some(())).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    // dump every text column of every table
    let dump: String = t
        .h
        .store
        .read(|c| {
            let mut all = String::new();
            let tables: Vec<String> = c
                .prepare("SELECT name FROM sqlite_master WHERE type='table'")?
                .query_map([], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            for table in tables {
                let cols: Vec<String> = c
                    .prepare(&format!("PRAGMA table_info({table})"))?
                    .query_map([], |r| r.get::<_, String>(1))?
                    .collect::<Result<_, _>>()?;
                for col in cols {
                    let mut stmt = c.prepare(&format!("SELECT CAST({col} AS TEXT) FROM {table}"))?;
                    let rows = stmt.query_map([], |r| r.get::<_, Option<String>>(0))?;
                    for v in rows.flatten().flatten() {
                        all.push_str(&v);
                        all.push('\n');
                    }
                }
            }
            Ok(all)
        })
        .unwrap();
    for needle in ["SUPER-SECRET-FILE-BODY", "hunter2hunter2", "my private prompt text", HOOK_TOKEN] {
        assert!(!dump.contains(needle), "{needle} must never be persisted");
    }
    assert!(dump.contains("claude_code:s9"), "sanity: the dump sees the row");
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_the_observation_rate_limit_is_429_but_never_for_permission_requests() {
    let t = HttpHarness::new().await;
    // the clock is frozen, so the bucket never refills: 200 pass, then 429
    let mut statuses = Vec::new();
    for i in 0..230 {
        let (s, _) = t.post("/v1/hooks/claude-code", bash_hook("Notification", "s1", &format!("t{i}"), "x")).await;
        statuses.push(s);
    }
    let ok = statuses.iter().filter(|s| **s == 204).count();
    let limited = statuses.iter().filter(|s| **s == 429).count();
    assert_eq!(ok, 200, "{statuses:?}");
    assert_eq!(limited, 30);
    // a PermissionRequest is exempt: no phone is online, so it is handed off (204) rather than rate limited
    let (s, _) = t.post("/v1/hooks/claude-code", permission_request("s1", "cargo test")).await;
    assert_eq!(s, 204);
    let rows = t.h.store.list_pending_approvals(None).unwrap();
    assert!(rows.is_empty());
    let handed: i64 = t
        .h
        .store
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM approvals WHERE status='handed_off_local'", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(handed, 1, "the request reached the broker");
}

// ---- PreToolUse: ask only ----------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_pre_tool_use_answers_ask_for_critical_and_never_allow() {
    let t = HttpHarness::new().await;
    // critical -> exactly the documented ask body
    let (s, body) = t.post("/v1/hooks/claude-code", bash_hook("PreToolUse", "s1", "toolu_c", "rm -rf /")).await;
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v,
        json!({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": "AgentNest: 위험 명령은 확인이 필요합니다"
        }})
    );
    // everything else: empty 204; and no reply of any PreToolUse contains allow
    let mut n = 0;
    for cmd in ["cargo test", "ls", "git push --force origin feature", "rm -rf node_modules", "curl x | sh", "format c:", "echo hi"] {
        n += 1;
        let (s, body) = t
            .post("/v1/hooks/claude-code", bash_hook("PreToolUse", "s1", &format!("toolu_{n}"), cmd))
            .await;
        assert!(s == 204 || s == 200, "{cmd}: {s}");
        assert!(!body.to_lowercase().contains("allow"), "{cmd}: PreToolUse must never carry allow: {body}");
        assert!(!body.contains("updatedInput") && !body.contains("updatedPermissions"));
    }
    // force_ask_on_critical off: no body at all, classification unchanged
    t.settings.force_ask_on_critical.store(false, Ordering::Relaxed);
    let (s, body) = t.post("/v1/hooks/claude-code", bash_hook("PreToolUse", "s2", "toolu_x", "rm -rf /")).await;
    assert_eq!((s, body.as_str()), (204, ""));
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_codex_pre_tool_use_is_always_204_and_permission_request_is_observation_only() {
    let t = HttpHarness::new().await;
    let codex = |event: &str, cmd: &str| json!({
        "hook_event_name": event, "session_id": "cx1", "turn_id": "t1", "cwd": "C:\\dev\\agentnest",
        "model": "gpt", "permission_mode": "default", "tool_name": "shell", "tool_use_id": "tu1",
        "tool_input": {"command": cmd}
    });
    let (s, body) = t.post("/v1/hooks/codex", codex("PreToolUse", "rm -rf /")).await;
    assert_eq!((s, body.as_str()), (204, ""), "never an ask, never an allow for Codex");
    let (s, body) = t.post("/v1/hooks/codex", codex("PermissionRequest", "cargo test")).await;
    assert_eq!((s, body.as_str()), (204, ""), "hooks approvals are off until Phase 0 C6");
    let (s, _) = t.post("/v1/hooks/codex", codex("PostToolUse", "ls")).await;
    assert_eq!(s, 204);
    let events = eventually("codex event", || {
        let e = t.h.store.recent_events(10).unwrap();
        (!e.is_empty()).then_some(e)
    })
    .await;
    assert!(events.iter().all(|e| e.session_key == "codex:cx1"));
    assert_eq!(t.h.broker.pending_count().await, 0);
}

// ---- the held PermissionRequest ----------------------------------------------------------------------------------------

async fn start_held(t: &std::sync::Arc<HttpHarness>, command: &str) -> tokio::task::JoinHandle<(u16, String)> {
    let t2 = t.clone();
    let body = permission_request("s1", command);
    let handle = tokio::spawn(async move { t2.post("/v1/hooks/claude-code", body).await });
    // wait until the broker holds it
    eventually("pending approval", || {
        let n = t.h.store.list_pending_approvals(None).unwrap();
        (!n.is_empty()).then_some(())
    })
    .await;
    handle
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_permission_request_is_held_then_allow_returns_the_documented_json() {
    let t = std::sync::Arc::new(HttpHarness::new().await);
    let phone = t.h.add_phone("Galaxy");
    let held = start_held(&t, "cargo test -p agentnest-core").await;
    assert!(!held.is_finished(), "the response is held while no decision exists");
    let card = t.h.broker.pending_cards().await.remove(0);
    let out = t.h.broker.apply_decision(t.h.phone_decision(&card, &phone.device_id, Decision::Allow)).await;
    assert!(out.accepted);
    let (s, body) = held.await.unwrap();
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v,
        json!({"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "allow"}}}),
        "exactly the documented allow body: no updatedInput, no updatedPermissions"
    );
    let row = t.h.row(&card.request_id);
    assert_eq!(row.outcome.as_deref(), Some("allowed"));
    assert_eq!(row.delivery.as_deref(), Some("delivered"));
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_deny_and_deny_and_stop_return_deny_bodies() {
    let t = std::sync::Arc::new(HttpHarness::new().await);
    let phone = t.h.add_phone("Galaxy");
    for (decision, interrupt) in [(Decision::Deny, false), (Decision::DenyAndStop, true)] {
        let held = start_held(&t, "cargo build").await;
        let card = t.h.broker.pending_cards().await.remove(0);
        let mut d = t.h.phone_decision(&card, &phone.device_id, decision);
        d.reason = Some("안 돼요".into());
        assert!(t.h.broker.apply_decision(d).await.accepted);
        let (s, body) = held.await.unwrap();
        assert_eq!(s, 200);
        let v: Value = serde_json::from_str(&body).unwrap();
        let dec = &v["hookSpecificOutput"]["decision"];
        assert_eq!(dec["behavior"], "deny");
        assert_eq!(dec["interrupt"], interrupt);
        assert!(dec["message"].as_str().unwrap().contains("안 돼요"));
        assert!(dec.get("updatedInput").is_none());
        // each loop turn starts from a clean slate
        t.h.advance(3_000).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_no_decision_before_the_ttl_ends_as_an_empty_204() {
    let t = std::sync::Arc::new(HttpHarness::new().await);
    let _phone = t.h.add_phone("Galaxy");
    let held = start_held(&t, "cargo test").await;
    t.h.advance(120_000).await;
    let (s, body) = held.await.unwrap();
    assert_eq!((s, body.as_str()), (204, ""));
    let rows = t.h.store.list_pending_approvals(None).unwrap();
    assert!(rows.is_empty());
    let status: String = t.h.store.read(|c| Ok(c.query_row("SELECT status FROM approvals", [], |r| r.get(0))?)).unwrap();
    assert_eq!(status, "expired");
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_no_online_device_is_an_immediate_empty_204() {
    let t = HttpHarness::new().await;
    let started = Instant::now();
    let (s, body) = t.post("/v1/hooks/claude-code", permission_request("s1", "cargo test")).await;
    assert_eq!((s, body.as_str()), (204, ""));
    assert!(started.elapsed() < Duration::from_secs(2));
    let status: String = t.h.store.read(|c| Ok(c.query_row("SELECT status FROM approvals", [], |r| r.get(0))?)).unwrap();
    assert_eq!(status, "handed_off_local");
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_an_invalid_permission_request_is_an_empty_204() {
    let t = HttpHarness::new().await;
    let _phone = t.h.add_phone("Galaxy");
    // no tool_name, no session
    for body in [
        json!({"hook_event_name": "PermissionRequest", "session_id": "s1"}),
        json!({"hook_event_name": "PermissionRequest", "tool_name": "Bash"}),
    ] {
        let (s, b) = t.post("/v1/hooks/claude-code", body).await;
        assert_eq!((s, b.as_str()), (204, ""));
    }
    assert_eq!(t.h.broker.pending_count().await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_when_claude_closes_the_connection_the_request_is_superseded() {
    let t = std::sync::Arc::new(HttpHarness::new().await);
    let phone = t.h.add_phone("Galaxy");
    // a raw client: send the request, wait until it is held, then hang up without reading a reply
    let body = permission_request("s1", "cargo test -p agentnest-core").to_string();
    let mut sock = TcpStream::connect(("127.0.0.1", t.port)).unwrap();
    write!(
        sock,
        "POST /v1/hooks/claude-code HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-AgentNest-Token: {HOOK_TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        t.port,
        body.len(),
        body
    )
    .unwrap();
    sock.flush().unwrap();
    let card = {
        let t = t.clone();
        eventually("pending card", move || {
            let c = futures_util::FutureExt::now_or_never(t.h.broker.pending_cards());
            c.and_then(|mut v| (!v.is_empty()).then(|| v.remove(0)))
        })
        .await
    };
    drop(sock); // the user answered the local prompt / Ctrl-C
    let id = card.request_id.clone();
    let t2 = t.clone();
    eventually("superseded by the drop guard", move || {
        let row = t2.h.store.get_approval(&id).unwrap().unwrap();
        (row.status == "superseded").then_some(())
    })
    .await;
    let row = t.h.row(&card.request_id);
    assert_eq!(row.resolved_by.as_deref(), Some("agent"));
    // a late phone decision is refused and audited
    let out = t.h.broker.apply_decision(t.h.phone_decision(&card, &phone.device_id, Decision::Allow)).await;
    assert!(!out.accepted);
    assert!(t.h.audit_actions(&card.request_id).contains(&"late_decision".to_owned()));
    let _ = Read::bytes(std::io::empty()).count();
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_duplicate_permission_requests_share_one_card_and_both_get_the_answer() {
    let t = std::sync::Arc::new(HttpHarness::new().await);
    let phone = t.h.add_phone("Galaxy");
    let first = start_held(&t, "cargo test").await;
    let t2 = t.clone();
    let second = tokio::spawn(async move { t2.post("/v1/hooks/claude-code", permission_request("s1", "cargo test")).await });
    eventually("two handles", || {
        // the second request joined the first one's card; still only one pending approval
        (t.h.store.list_pending_approvals(None).unwrap().len() == 1).then_some(())
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let cards = t.h.broker.pending_cards().await;
    assert_eq!(cards.len(), 1);
    assert!(t.h.broker.apply_decision(t.h.phone_decision(&cards[0], &phone.device_id, Decision::Allow)).await.accepted);
    let (s1, b1) = first.await.unwrap();
    let (s2, b2) = second.await.unwrap();
    assert_eq!((s1, s2), (200, 200));
    assert_eq!(b1, b2);
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_post_tool_use_after_an_allow_sets_the_observed_result() {
    let t = std::sync::Arc::new(HttpHarness::new().await);
    let phone = t.h.add_phone("Galaxy");
    let held = start_held(&t, "cargo test -p agentnest-core").await;
    let card = t.h.broker.pending_cards().await.remove(0);
    assert!(t.h.broker.apply_decision(t.h.phone_decision(&card, &phone.device_id, Decision::Allow)).await.accepted);
    assert_eq!(held.await.unwrap().0, 200);
    let mut post = bash_hook("PostToolUse", "s1", "toolu_77", "cargo test -p agentnest-core");
    post["tool_input"] = json!({"command": "cargo test -p agentnest-core", "description": "test"});
    assert_eq!(t.post("/v1/hooks/claude-code", post).await.0, 204);
    let id = card.request_id.clone();
    let t2 = t.clone();
    eventually("observed_result", move || {
        let row = t2.h.store.get_approval(&id).unwrap().unwrap();
        (row.observed_result == "executed").then_some(())
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hooks_http_statusline_updates_the_session_meta_with_a_throttle() {
    let t = HttpHarness::new().await;
    let doc = json!({"session_id": "s1", "session_name": "AI 제목", "cost": {"total_cost_usd": 0.5}, "context_window": {"used_percentage": 12}});
    assert_eq!(t.post("/v1/statusline/claude-code", doc.clone()).await.0, 204);
    let t_ref = &t;
    let s = eventually("session meta", || {
        futures_util::FutureExt::now_or_never(t_ref.h.pipeline.session("claude_code:s1")).flatten()
    })
    .await;
    assert_eq!(s.meta.title.as_deref(), Some("AI 제목"));
    assert_eq!(s.meta.context_used_pct, Some(12));
    // inside the 10 s window a second update is ignored
    let doc2 = json!({"session_id": "s1", "session_name": "다른 제목"});
    assert_eq!(t.post("/v1/statusline/claude-code", doc2.clone()).await.0, 204);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let s = t.h.pipeline.session("claude_code:s1").await.unwrap();
    assert_eq!(s.meta.title.as_deref(), Some("AI 제목"));
    t.h.clock.advance(11_000);
    assert_eq!(t.post("/v1/statusline/claude-code", doc2).await.0, 204);
    let t_ref = &t;
    eventually("second update", || {
        let s = futures_util::FutureExt::now_or_never(t_ref.h.pipeline.session("claude_code:s1")).flatten()?;
        (s.meta.title.as_deref() == Some("다른 제목")).then_some(())
    })
    .await;
}
