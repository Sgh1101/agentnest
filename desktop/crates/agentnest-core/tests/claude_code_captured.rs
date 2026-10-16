//! Real Claude Code hook payloads (Phase 0, docs/integrations/claude-code.md 9 / docs/phase0-checklist.md A-series).
//!
//! `protocol/fixtures/claude-code/captured/*.json` are **bodies captured from a real `claude` 2.1.301** (`claude -p`, hooks
//! pointed at a local capture server on 2026-10-16) with the user-specific values replaced (paths, session / prompt /
//! tool-use / agent ids). Unlike `tests/fixtures/claude_code/` (derived from the documentation) nothing here was written by
//! hand, so these tests catch drift between what Claude Code really sends and what the collector assumes.
//!
//! The last test, `a_real_claude_reaches_the_collector`, runs the real CLI against the real HTTP collector. It is
//! `#[ignore]`d (needs `claude` and a model API) - run it with
//! `AGENTNEST_REAL_CLAUDE=1 cargo test -p agentnest-core --test claude_code_captured -- --ignored --nocapture`.

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use agentnest_adapter_api::RawObservation;
use agentnest_core::adapters::claude_code::install::{self, HookMode, InstallOptions};
use agentnest_core::adapters::claude_code::{
    hook_event_name, normalize, permission_request_draft, NormalizeCtx,
};
use agentnest_protocol::canonical::tool_input_sha256;
use agentnest_protocol::{AgentEvent, AgentState, Decision};
use common::harness::*;
use common::*;
use serde_json::{json, Value};

fn captured_dir() -> PathBuf {
    protocol_dir().join("fixtures/claude-code/captured")
}

fn all() -> BTreeMap<String, Value> {
    json_files(&captured_dir())
        .into_iter()
        .map(|p| (p.file_stem().unwrap().to_string_lossy().into_owned(), read_json(&p)))
        .collect()
}

fn cap(name: &str) -> Value {
    read_json(&captured_dir().join(format!("{name}.json")))
}

fn events(hook: &Value) -> Vec<AgentEvent> {
    let env = golden_env(golden_fs());
    let ctx = NormalizeCtx::http(&env);
    normalize(hook, &ctx)
        .into_iter()
        .filter_map(|o| match o {
            RawObservation::Event(e) => Some(e),
            _ => None,
        })
        .collect()
}

// ---- the capture set itself --------------------------------------------------------------------------------------------

#[test]
fn the_captured_set_is_complete_and_contains_no_private_values() {
    let set = all();
    assert!(set.len() >= 25, "capture set shrank: {}", set.len());
    // every event class that a real `claude -p` run produced is represented
    let names: std::collections::BTreeSet<&str> = set
        .values()
        .filter_map(|v| hook_event_name(v))
        .collect();
    for want in [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PermissionRequest",
        "PostToolUse",
        "PostToolUseFailure",
        "SubagentStart",
        "SubagentStop",
        "Stop",
        "SessionEnd",
    ] {
        assert!(names.contains(want), "no captured {want}");
    }
    let forbidden = [
        "/root",
        "ccb789a3",
        "agentnest-hook",
        "sk-ant",
        "ghp_",
        "Bearer ",
        "toolu_01",
        "model-redacted-x",
        "@",
    ];
    for (name, v) in &set {
        for key in ["session_id", "transcript_path", "cwd", "hook_event_name"] {
            assert!(v.get(key).and_then(Value::as_str).is_some(), "{name}: {key}");
        }
        let text = v.to_string();
        for bad in forbidden {
            assert!(!text.contains(bad), "{name}: contains {bad:?}");
        }
        // ids are the obvious fakes of the redaction script
        assert!(
            v["cwd"] == "/home/user/demo",
            "{name}: cwd must be the redacted demo directory"
        );
    }
}

/// What a real Claude Code adds on top of the documented common fields (observed in 2.1.301).
#[test]
fn real_payloads_carry_scratchpad_dir_effort_and_prompt_id_which_the_collector_ignores() {
    let pre = cap("pre_tool_use_bash");
    assert!(pre["scratchpad_dir"].is_string());
    assert_eq!(pre["effort"]["level"], "medium");
    assert!(pre["prompt_id"].is_string());
    assert!(pre["tool_use_id"].is_string());
    // lifecycle hooks carry no effort (the Claude Code schema says so) and `SessionEnd` has no permission_mode
    let end = cap("session_end_other");
    assert!(end.get("effort").is_none());
    assert!(end.get("permission_mode").is_none());
    assert_eq!(end["reason"], "other");
    // the unknown fields must not break normalisation
    assert_eq!(events(&pre).len(), 1);
    assert_eq!(events(&end).len(), 1);
}

// ---- normalisation of real payloads ------------------------------------------------------------------------------------

#[test]
fn real_hooks_normalise_to_the_documented_events() {
    let schemas = Schemas::load();
    let validator = schemas.validator("model/agent_event.schema.json");
    // (fixture, kind, state_hint)
    let table: &[(&str, &str, Option<AgentState>)] = &[
        ("session_start_startup", "session_started", Some(AgentState::Idle)),
        ("user_prompt_submit", "prompt_submitted", Some(AgentState::Working)),
        ("pre_tool_use_read", "file_read", Some(AgentState::Reviewing)),
        ("post_tool_use_read", "tool_completed", None),
        ("pre_tool_use_bash", "command_started", Some(AgentState::Working)),
        ("post_tool_use_bash", "command_completed", None),
        ("pre_tool_use_bash_in_subagent", "command_started", Some(AgentState::Working)),
        ("post_tool_use_bash_in_subagent", "command_completed", None),
        ("post_tool_use_failure_bash_in_subagent", "command_failed", Some(AgentState::Error)),
        ("pre_tool_use_agent", "tool_started", Some(AgentState::Working)),
        ("post_tool_use_agent_async", "tool_completed", None),
        ("subagent_start", "subagent_started", None),
        ("subagent_stop", "subagent_stopped", None),
        ("pre_tool_use_write", "tool_started", Some(AgentState::WritingCode)),
        ("post_tool_use_write", "file_modified", Some(AgentState::WritingCode)),
        ("stop_done", "turn_completed", Some(AgentState::Completed)),
        ("stop_background_subagent_running", "turn_completed", Some(AgentState::Working)),
        ("session_end_other", "session_ended", None),
    ];
    for (name, kind, state) in table {
        let hook = cap(name);
        let evs = events(&hook);
        assert_eq!(evs.len(), 1, "{name}: {evs:?}");
        let ev = &evs[0];
        assert_eq!(ev.kind.as_str(), *kind, "{name}");
        assert_eq!(&ev.state_hint, state, "{name}");
        let errs = agent_event_errors(&validator, &serde_json::to_value(ev).unwrap());
        assert!(errs.is_empty(), "{name}: schema errors {errs:?}");
        assert_eq!(
            ev.source.native_ids.get("session_id").map(String::as_str),
            hook["session_id"].as_str(),
            "{name}: session id"
        );
    }
}

/// `SessionStart` of a real Claude Code 2.1.301 carries only `source` - no `model`, `permission_mode` or `session_title`.
#[test]
fn a_real_session_start_has_only_the_source_and_still_normalises() {
    let hook = cap("session_start_startup");
    assert_eq!(hook["source"], "startup");
    for absent in ["model", "permission_mode", "session_title", "prompt_id", "effort"] {
        assert!(hook.get(absent).is_none(), "{absent}");
    }
    let env = golden_env(golden_fs());
    let ctx = NormalizeCtx::http(&env);
    let obs = normalize(&hook, &ctx);
    assert_eq!(obs.len(), 1, "no meta patch when there is nothing to patch");
    let RawObservation::Event(ev) = &obs[0] else {
        panic!("event expected")
    };
    assert_eq!(ev.detail["source_reason"], "startup");
    assert!(ev.detail.get("model").is_none());
}

/// The sub-agent result of the `Agent` tool is asynchronous: the main thread's `Stop` arrives while the sub-agent is still
/// in `background_tasks`, and the sub-agent's own `Stop` event lists itself as running too.
#[test]
fn a_stop_with_a_running_background_subagent_is_not_completed() {
    let stop = cap("stop_background_subagent_running");
    assert_eq!(stop["background_tasks"][0]["type"], "subagent");
    assert_eq!(stop["background_tasks"][0]["status"], "running");
    let evs = events(&stop);
    assert_eq!(evs[0].state_hint, Some(AgentState::Working));
    assert_eq!(evs[0].detail["background_tasks"], 1);
    // the sub-agent's own SubagentStop still lists itself: that is not a main-thread completion
    let sub_stop = cap("subagent_stop");
    assert_eq!(sub_stop["agent_type"], "general-purpose");
    assert!(sub_stop["agent_transcript_path"].is_string());
    let evs = events(&sub_stop);
    assert_eq!(evs[0].kind.as_str(), "subagent_stopped");
    assert_eq!(evs[0].state_hint, None);
}

/// A finished background sub-agent wakes the main thread with a `UserPromptSubmit` whose prompt is a
/// `<task-notification>`: not a person's instruction (A11, true positive of the `<` heuristic).
#[test]
fn a_real_task_notification_prompt_is_an_automatic_turn_and_a_typed_prompt_is_not() {
    let auto = events(&cap("user_prompt_submit_task_notification"));
    assert_eq!(auto[0].detail["auto_turn_suspect"], true);
    let typed = events(&cap("user_prompt_submit"));
    assert_eq!(typed[0].detail["auto_turn_suspect"], false);
    // the raw prompt of the typed fixture has no `source` field in 2.1.301 `-p` (the schema lists it as optional)
    assert!(cap("user_prompt_submit").get("source").is_none());
    // the notification text never leaks the (redacted-by-the-collector) output path
    let text = serde_json::to_string(&auto[0]).unwrap();
    assert!(!text.contains("/tmp/claude-1000"), "{text}");
}

#[test]
fn a_real_post_tool_use_failure_error_starts_with_the_exit_code() {
    let hook = cap("post_tool_use_failure_bash_in_subagent");
    assert!(hook["error"].as_str().unwrap().starts_with("Exit code 2\n"));
    assert_eq!(hook["agent_type"], "general-purpose");
    assert_eq!(hook["is_interrupt"], false);
    let ev = &events(&hook)[0];
    assert_eq!(ev.detail["exit_code"], 2);
    assert_eq!(ev.detail["error"], "Exit code 2");
    let actor = ev.actor.as_ref().expect("a sub-agent actor");
    assert!(actor.is_subagent);
    assert_eq!(actor.agent_id.as_deref(), Some("a00000000000fix01"));
    assert_eq!(actor.agent_type.as_deref(), Some("general-purpose"));
}

#[test]
fn a_real_write_reports_create_and_a_plan_mode_write_goes_to_the_plan_file() {
    let post = events(&cap("post_tool_use_write"));
    assert_eq!(post[0].detail["op"], "create");
    let plan = cap("pre_tool_use_write_plan");
    assert_eq!(plan["permission_mode"], "plan");
    assert!(plan["tool_input"]["file_path"]
        .as_str()
        .unwrap()
        .contains("/.claude/plans/"));
    // permission_mode strings of the real payloads
    assert_eq!(cap("pre_tool_use_bash_accept_edits")["permission_mode"], "acceptEdits");
    assert_eq!(cap("pre_tool_use_write_dont_ask")["permission_mode"], "dontAsk");
}

// ---- PermissionRequest ----------------------------------------------------------------------------------------------------

#[test]
fn real_permission_requests_build_drafts_without_tool_use_id() {
    let env = golden_env(golden_fs());
    let ctx = NormalizeCtx::http(&env);
    // (fixture, agent_id, suggestions)
    for (name, agent_id, suggestions, tool) in [
        ("permission_request_bash", None, 2u32, "Bash"),
        ("permission_request_bash_in_subagent", Some("a00000000000fix01"), 2, "Bash"),
        ("permission_request_write", None, 1, "Write"),
    ] {
        let hook = cap(name);
        assert!(hook.get("tool_use_id").is_none(), "{name}: PermissionRequest has no tool_use_id");
        assert_eq!(hook["agent_id"].as_str(), agent_id, "{name}");
        assert!(normalize(&hook, &ctx).is_empty(), "{name}");
        let d = permission_request_draft(&hook, &ctx).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(d.tool_name, tool);
        assert_eq!(d.agent_id.as_deref(), agent_id, "{name}");
        assert_eq!(d.permission_suggestions_count, Some(suggestions), "{name}");
        assert_eq!(d.permission_mode.as_deref(), Some("default"));
        assert_eq!(d.session_key, format!("claude_code:{}", hook["session_id"].as_str().unwrap()));
    }
    // the real suggestion shapes (not `addRules`): directories and a mode switch - they are only ever counted
    let s = &cap("permission_request_bash")["permission_suggestions"];
    assert_eq!(s[0]["type"], "addDirectories");
    assert_eq!(s[1]["type"], "setMode");
    assert_eq!(s[1]["mode"], "acceptEdits");
}

/// A7 on real data: the approval's `tool_input` hash equals the hash the `PreToolUse` and `PostToolUse` events of the same
/// call carry, which is what the correlation of "was it executed" relies on (there is no `tool_use_id` to join on).
#[test]
fn the_permission_request_input_hash_matches_the_pre_and_post_tool_use_of_the_same_call() {
    let env = golden_env(golden_fs());
    let ctx = NormalizeCtx::http(&env);
    for (perm, pre, post) in [
        ("permission_request_bash", "pre_tool_use_bash", "post_tool_use_bash"),
        ("permission_request_write", "pre_tool_use_write", "post_tool_use_write"),
    ] {
        let want = tool_input_sha256(&cap(perm)["tool_input"]);
        let d = permission_request_draft(&cap(perm), &ctx).unwrap();
        assert_eq!(d.binding.ids["tool_input_sha256"], want, "{perm}");
        for other in [pre, post] {
            let ev = &events(&cap(other))[0];
            assert_eq!(
                ev.source.native_ids.get("tool_input_sha256"),
                Some(&want),
                "{other} must correlate with {perm}"
            );
        }
    }
}

// ---- the real HTTP collector ------------------------------------------------------------------------------------------------

/// A real session (captured without any `SessionStart`: Claude Code never sends one over an HTTP hook) is followed from the
/// first `UserPromptSubmit` to `SessionEnd` through the real axum collector; observation hooks are 204.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_without_session_start_is_adopted_from_its_first_event() {
    let t = HttpHarness::new().await;
    let sid = cap("user_prompt_submit")["session_id"].as_str().unwrap().to_owned();
    for name in [
        "user_prompt_submit",
        "pre_tool_use_read",
        "post_tool_use_read",
        "stop_done",
        "session_end_other",
    ] {
        let (s, body) = t.post("/v1/hooks/claude-code", cap(name)).await;
        assert_eq!((s, body.as_str()), (204, ""), "{name}");
    }
    let rec = eventually("the session row", || {
        t.h.store
            .get_session(&format!("claude_code:{sid}"))
            .unwrap()
            .filter(|r| r.ended_at.is_some())
    })
    .await;
    assert_eq!(rec.permission_mode.as_deref(), Some("default"));
    assert_eq!(rec.end_reason.as_deref(), Some("other"));
    let kinds: Vec<String> = t
        .h
        .store
        .recent_events(20)
        .unwrap()
        .into_iter()
        .map(|e| e.kind.as_str().to_owned())
        .collect();
    for k in ["prompt_submitted", "file_read", "tool_completed", "turn_completed", "session_ended"] {
        assert!(kinds.iter().any(|x| x == k), "{k} missing in {kinds:?}");
    }
}

/// The real `PermissionRequest` over the real collector: held for a phone, `allow` answers with exactly the body Claude Code
/// accepted in the live run (`hookSpecificOutput.decision.behavior = allow`, nothing else).
#[tokio::test(flavor = "multi_thread")]
async fn a_real_permission_request_is_held_and_answered_with_the_body_claude_code_accepts() {
    let t = std::sync::Arc::new(HttpHarness::new().await);
    let phone = t.h.add_phone("Galaxy");
    let t2 = t.clone();
    let held = tokio::spawn(async move {
        t2.post("/v1/hooks/claude-code", cap("permission_request_bash")).await
    });
    eventually("pending approval", || {
        (!t.h.store.list_pending_approvals(None).unwrap().is_empty()).then_some(())
    })
    .await;
    let card = t.h.broker.pending_cards().await.remove(0);
    assert_eq!(card.tool_name, "Bash");
    assert!(t.h.broker.apply_decision(t.h.phone_decision(&card, &phone.device_id, Decision::Allow)).await.accepted);
    let (s, body) = held.await.unwrap();
    assert_eq!(s, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "allow"}}})
    );
}

/// With no phone online the real request is an immediate empty 204 (Claude Code then asks locally; `claude -p` denies - both
/// observed live), never an allow.
#[tokio::test(flavor = "multi_thread")]
async fn a_real_permission_request_without_a_phone_is_an_empty_204() {
    let t = HttpHarness::new().await;
    for name in ["permission_request_bash", "permission_request_bash_in_subagent", "permission_request_write"] {
        let (s, body) = t.post("/v1/hooks/claude-code", cap(name)).await;
        assert_eq!((s, body.as_str()), (204, ""), "{name}");
    }
}

/// What the real client sends: `axios` with only `content-type`/`accept`/`user-agent`/`x-agentnest-token`; no `Origin`, no
/// `Sec-Fetch-*` (the browser guard must not reject it) and a `Host` of `127.0.0.1:<port>`.
#[tokio::test(flavor = "multi_thread")]
async fn the_guard_accepts_the_header_set_a_real_claude_code_sends() {
    let t = HttpHarness::new().await;
    let body = cap("pre_tool_use_bash").to_string().into_bytes();
    let (s, _) = t
        .request(
            "POST",
            "/v1/hooks/claude-code",
            &[
                ("X-AgentNest-Token", HOOK_TOKEN),
                ("Accept", "application/json, text/plain, */*"),
                ("User-Agent", "axios/1.15.2"),
                ("Accept-Encoding", "gzip, compress, deflate, br"),
                ("Connection", "keep-alive"),
            ],
            Some(body),
        )
        .await;
    assert_eq!(s, 204);
}

// ---- installer vs. what Claude Code supports ----------------------------------------------------------------------------------

/// Claude Code 2.1.301 skips HTTP hooks for `SessionStart` (and `Setup`) - its own debug log says "HTTP hooks are not
/// supported for SessionStart". An HTTP `SessionStart` entry would be dead weight, so it is a command hook in every mode.
#[test]
fn session_start_is_always_a_command_hook_because_claude_code_skips_http_for_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let opts = InstallOptions {
        mode: HookMode::Http,
        hook_port: 47831,
        hook_token: "an_hk_TESTTOKEN",
        approval_ttl_s: 120,
        daemon_down_deny: false,
        install_statusline: false,
        hook_cli: "agentnest-hook",
        backup_stamp: Some("20261016T000000Z"),
    };
    install::install(&path, &opts).unwrap();
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let start = &v["hooks"]["SessionStart"][0]["hooks"][0];
    assert_eq!(start["type"], "command");
    assert_eq!(start["command"], "agentnest-hook");
    assert_eq!(start["args"], json!(["claude-code"]));
    assert!(start.get("headers").is_none(), "no token on a command hook");
    // every other event stays an HTTP hook
    for event in install::EVENTS.iter().filter(|e| **e != "SessionStart") {
        assert_eq!(v["hooks"][*event][0]["hooks"][0]["type"], "http", "{event}");
    }
    assert!(install::inspect(&path).fully_installed());
}

// ---- live: the real claude CLI against the real collector ----------------------------------------------------------------------

/// A scratch directory with `settings.json` (written by the installer under test) and the `daemon.json` the real
/// `agentnest-hook` reads, pointed at the harness collector.
struct Live {
    work: tempfile::TempDir,
}

impl Live {
    fn new(t: &HttpHarness) -> Self {
        let work = tempfile::tempdir().unwrap();
        std::fs::write(work.path().join("note.txt"), "hello from the e2e test\n").unwrap();
        // The command hook of SessionStart is the real `agentnest-hook` (`cargo build -p agentnest-hook`, then
        // AGENTNEST_HOOK_BIN=<path>). It finds the collector through daemon.json under XDG_DATA_HOME.
        let hook_bin =
            std::env::var("AGENTNEST_HOOK_BIN").expect("AGENTNEST_HOOK_BIN (path of agentnest-hook)");
        let data = work.path().join("xdg");
        std::fs::create_dir_all(data.join("AgentNest")).unwrap();
        std::fs::write(
            data.join("AgentNest/daemon.json"),
            json!({"hook_port": t.port, "wss_port": 47832, "hook_token": HOOK_TOKEN, "approval_ttl_s": 120})
                .to_string(),
        )
        .unwrap();
        install::install(
            &work.path().join("settings.json"),
            &InstallOptions {
                mode: HookMode::Http,
                hook_port: t.port,
                hook_token: HOOK_TOKEN,
                approval_ttl_s: 120,
                daemon_down_deny: false,
                install_statusline: false,
                hook_cli: &hook_bin,
                backup_stamp: Some("20261016T000000Z"),
            },
        )
        .unwrap();
        Self { work }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.work.path().join(name)
    }

    /// Runs `claude -p` (stream-json) in the scratch directory; returns (exit ok, stdout).
    fn spawn(&self, session: &str, prompt: &str) -> tokio::task::JoinHandle<(bool, String)> {
        let work = self.work.path().to_owned();
        let session = session.to_owned();
        let prompt = prompt.to_owned();
        tokio::task::spawn_blocking(move || {
            let out = std::process::Command::new("claude")
                .current_dir(&work)
                .env_remove("CLAUDE_CODE_SESSION_ID")
                .env_remove("CLAUDE_CODE_REMOTE_SESSION_ID")
                .env("XDG_DATA_HOME", work.join("xdg"))
                .args([
                    "-p",
                    &prompt,
                    "--settings",
                    work.join("settings.json").to_str().unwrap(),
                    "--setting-sources",
                    "project",
                    "--session-id",
                    &session,
                    "--model",
                    "haiku",
                    "--max-turns",
                    "5",
                    "--output-format",
                    "stream-json",
                    "--verbose",
                ])
                .stdin(std::process::Stdio::null())
                .output()
                .expect("spawn claude");
            (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
        })
    }
}

fn live_enabled() -> bool {
    let on = std::env::var("AGENTNEST_REAL_CLAUDE").as_deref() == Ok("1");
    if !on {
        eprintln!("AGENTNEST_REAL_CLAUDE is not 1: skipped");
    }
    on
}

fn event_kinds(t: &HttpHarness) -> Vec<String> {
    t.h.store
        .recent_events(100)
        .unwrap()
        .into_iter()
        .map(|e| e.kind.as_str().to_owned())
        .collect()
}

/// Runs a real `claude -p` (hooks installed by the installer under test) against the real collector and checks what the
/// daemon saw. Needs `claude` on `PATH` and a working model API, so it is ignored by default.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the claude CLI and a model API (AGENTNEST_REAL_CLAUDE=1)"]
async fn a_real_claude_reaches_the_collector() {
    if !live_enabled() {
        return;
    }
    let t = HttpHarness::new().await;
    let live = Live::new(&t);
    let sid = "eeeeeeee-0000-4000-8000-000000000001";
    let (ok, _) = live
        .spawn(sid, "Read the file note.txt in the current directory and reply with its content only.")
        .await
        .unwrap();
    assert!(ok);
    let kinds = eventually("the session end", || {
        let kinds = event_kinds(&t);
        kinds.iter().any(|k| k == "session_ended").then_some(kinds)
    })
    .await;
    // `session_started` only arrives through the command hook (HTTP hooks are skipped for SessionStart)
    for k in [
        "session_started",
        "prompt_submitted",
        "file_read",
        "tool_completed",
        "turn_completed",
        "session_ended",
    ] {
        assert!(kinds.iter().any(|x| x == k), "{k} missing in {kinds:?}");
    }
    let rec = t.h.store.get_session(&format!("claude_code:{sid}")).unwrap().expect("session row");
    assert_eq!(rec.permission_mode.as_deref(), Some("default"));
}

/// A12 on the real client: the phone's `allow` runs the command, a `deny` reaches Claude with the text, and without a phone
/// `claude -p` is refused (empty 204 = no decision = ask locally = nobody to ask in `-p` = denied). Never an allow by default.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the claude CLI and a model API (AGENTNEST_REAL_CLAUDE=1)"]
async fn a_real_claude_permission_request_is_decided_remotely_and_fails_closed() {
    if !live_enabled() {
        return;
    }
    let t = HttpHarness::new().await;
    let live = Live::new(&t);
    let prompt = |f: &str| format!("Use the Bash tool to run exactly: touch {f} . Then reply done.");

    // 1. no phone online: handed off to the local prompt; `claude -p` has none, so the command does not run
    let (_, out) = live.spawn("eeeeeeee-0000-4000-8000-000000000002", &prompt("nophone.txt")).await.unwrap();
    assert!(!live.path("nophone.txt").exists(), "no allow without a decision");
    assert!(out.contains("needs approval"), "claude -p refuses an undecided request: {out}");
    let status: String =
        t.h.store.read(|c| Ok(c.query_row("SELECT status FROM approvals ORDER BY rowid DESC LIMIT 1", [], |r| r.get(0))?)).unwrap();
    assert_eq!(status, "handed_off_local");

    // 2. phone allows
    let phone = t.h.add_phone("Galaxy");
    let run = live.spawn("eeeeeeee-0000-4000-8000-000000000003", &prompt("allowed.txt"));
    let card = eventually("the card of the real request", || {
        let c = futures_util::FutureExt::now_or_never(t.h.broker.pending_cards()).unwrap_or_default();
        c.into_iter().next()
    })
    .await;
    assert_eq!(card.tool_name, "Bash");
    assert!(t.h.broker.apply_decision(t.h.phone_decision(&card, &phone.device_id, Decision::Allow)).await.accepted);
    let (ok, _) = run.await.unwrap();
    assert!(ok);
    assert!(live.path("allowed.txt").exists(), "the allowed command ran");
    let row = t.h.row(&card.request_id);
    assert_eq!(row.outcome.as_deref(), Some("allowed"));

    // 3. phone denies with a reason: the command does not run and Claude is told why
    let run = live.spawn("eeeeeeee-0000-4000-8000-000000000004", &prompt("denied.txt"));
    let card = eventually("the second card", || {
        let c = futures_util::FutureExt::now_or_never(t.h.broker.pending_cards()).unwrap_or_default();
        c.into_iter().next()
    })
    .await;
    let mut d = t.h.phone_decision(&card, &phone.device_id, Decision::Deny);
    d.reason = Some("not now".into());
    assert!(t.h.broker.apply_decision(d).await.accepted);
    let (_, out) = run.await.unwrap();
    assert!(!live.path("denied.txt").exists(), "the denied command did not run");
    assert!(out.contains("not now"), "the deny message reaches Claude: {out}");
}
