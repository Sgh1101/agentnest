//! Golden tests of the Claude Code hook normaliser (docs/integrations/claude-code.md 5).
//!
//! The payloads under `tests/fixtures/claude_code/` are derived from the verified hook shapes in the research notes
//! (`"_source": "doc-derived"`); Phase 0 A1 replaces them with real captures. Each fixture lists the expected events
//! (subset match on the fields that matter), optional forbidden substrings (secrets that must never appear in any
//! produced event) and, for `PermissionRequest`, the expected approval draft.

mod common;

use std::collections::BTreeSet;

use agentnest_adapter_api::RawObservation;
use agentnest_core::adapters::claude_code::{
    hook_event_name, normalize, permission_request_draft, pre_tool_use_ask_reply,
    pre_tool_use_risk, NormalizeCtx,
};
use agentnest_core::state::reducer::SessionReducer;
use agentnest_protocol::{AgentEvent, AgentKind, AgentState, RiskLevel};
use common::*;
use serde_json::{json, Value};

fn fixtures() -> Vec<(String, Value)> {
    json_files(&fixtures_dir().join("claude_code"))
        .into_iter()
        .map(|p| {
            (
                p.file_stem().unwrap().to_string_lossy().into_owned(),
                read_json(&p),
            )
        })
        .collect()
}

fn events_of(obs: &[RawObservation]) -> Vec<&AgentEvent> {
    obs.iter()
        .filter_map(|o| match o {
            RawObservation::Event(e) => Some(e),
            _ => None,
        })
        .collect()
}

#[test]
fn every_fixture_normalises_to_the_expected_events() {
    let schemas = Schemas::load();
    let validator = schemas.validator("model/agent_event.schema.json");
    let all = fixtures();
    assert!(
        all.len() >= 40,
        "expected the full fixture set, got {}",
        all.len()
    );
    let mut failures = Vec::new();
    for (name, fx) in &all {
        assert_eq!(
            fx["_source"], "doc-derived",
            "{name}: fixtures must be marked doc-derived"
        );
        let env = golden_env(golden_fs());
        let ctx = NormalizeCtx::http(&env);
        let obs = normalize(&fx["hook"], &ctx);
        let events = events_of(&obs);
        let expect = fx["expect"].as_array().unwrap();
        if events.len() != expect.len() {
            failures.push(format!(
                "{name}: expected {} events, got {:?}",
                expect.len(),
                events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>()
            ));
            continue;
        }
        let mut serialized = String::new();
        for (i, (ev, want)) in events.iter().zip(expect).enumerate() {
            let (problems, text) = check_event(name, i, ev, want, &validator);
            failures.extend(problems);
            serialized.push_str(&text);
        }
        for needle in fx
            .get("forbid")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if serialized.contains(needle) {
                failures.push(format!(
                    "{name}: forbidden text {needle:?} appears in the normalised events"
                ));
            }
        }
        // metadata patches
        if let Some(metas) = fx.get("expect_meta").and_then(Value::as_array) {
            let patches: Vec<Value> = obs
                .iter()
                .filter_map(|o| match o {
                    RawObservation::SessionMeta { patch, .. } => {
                        Some(serde_json::to_value(patch).unwrap())
                    }
                    _ => None,
                })
                .collect();
            if patches.len() != metas.len() {
                failures.push(format!(
                    "{name}: expected {} meta patches, got {}",
                    metas.len(),
                    patches.len()
                ));
            } else {
                for (p, m) in patches.iter().zip(metas) {
                    if let Err(e) = subset(m, p) {
                        failures.push(format!("{name}: meta {e}"));
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} fixture problems:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn permission_request_fixtures_build_drafts_and_no_events() {
    let mut seen = 0;
    for (name, fx) in fixtures() {
        let Some(want) = fx.get("expect_draft") else {
            continue;
        };
        seen += 1;
        let env = golden_env(golden_fs());
        let ctx = NormalizeCtx::http(&env);
        assert!(
            normalize(&fx["hook"], &ctx).is_empty(),
            "{name}: a PermissionRequest is not an observation"
        );
        let d =
            permission_request_draft(&fx["hook"], &ctx).unwrap_or_else(|e| panic!("{name}: {e}"));
        let got = json!({
            "session_key": d.session_key,
            "tool_name": d.tool_name,
            "permission_mode": d.permission_mode,
            "permission_suggestions_count": d.permission_suggestions_count,
            "agent_description": d.agent_description,
            "agent_id": d.agent_id,
            "available_decisions": d.available_decisions.iter().map(|x| x.as_str()).collect::<Vec<_>>(),
            "origin": d.origin.as_str(),
            "cwd": d.cwd,
            "project_name": d.project.as_ref().map(|p| p.name.clone()),
        });
        subset(want, &got).unwrap_or_else(|m| panic!("{name}: {m}"));
        assert_eq!(
            d.binding.ids["tool_input_sha256"],
            agentnest_protocol::canonical::tool_input_sha256(&fx["hook"]["tool_input"]),
            "{name}: the binding carries the canonical input hash"
        );
        assert!(
            !format!("{d:?}").contains("rm -rf"),
            "{name}: Debug must not print the raw tool input"
        );
    }
    assert!(seen >= 2);
}

#[test]
fn every_documented_hook_event_has_a_fixture() {
    let names: BTreeSet<String> = fixtures()
        .iter()
        .filter_map(|(_, fx)| hook_event_name(&fx["hook"]).map(str::to_owned))
        .collect();
    for want in [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PermissionRequest",
        "PermissionDenied",
        "PostToolUse",
        "PostToolUseFailure",
        "Notification",
        "SubagentStart",
        "SubagentStop",
        "Stop",
        "StopFailure",
        "TaskCreated",
        "TaskCompleted",
        "PostCompact",
        "SessionEnd",
    ] {
        assert!(names.contains(want), "no fixture for {want}");
    }
}

#[test]
fn pre_tool_use_hooks_have_a_risk_and_only_ever_ask() {
    let mut checked = 0;
    for (name, fx) in fixtures() {
        if hook_event_name(&fx["hook"]) != Some("PreToolUse") {
            continue;
        }
        checked += 1;
        let risk = pre_tool_use_risk(&fx["hook"]).unwrap_or_else(|| panic!("{name}: no risk"));
        assert_eq!(risk.reasons.len(), risk.reasons_ko.len(), "{name}");
        if let Some(reply) = pre_tool_use_ask_reply(&risk, true) {
            assert_eq!(risk.level, RiskLevel::Critical, "{name}");
            assert_eq!(reply["hookSpecificOutput"]["permissionDecision"], "ask");
        }
    }
    assert!(checked >= 10);
    // a few concrete classifications through the fixture path
    let by_name: std::collections::BTreeMap<String, Value> = fixtures().into_iter().collect();
    let level = |n: &str| pre_tool_use_risk(&by_name[n]["hook"]).unwrap().level;
    assert_eq!(level("pre_tool_use_bash_npm_test"), RiskLevel::Low);
    assert_eq!(level("pre_tool_use_edit"), RiskLevel::Low);
    assert_eq!(level("pre_tool_use_webfetch"), RiskLevel::Low);
    assert_eq!(level("pre_tool_use_mcp_tool"), RiskLevel::Medium);
    assert_eq!(
        level("pre_tool_use_bash_secret_in_command"),
        RiskLevel::Medium
    );
}

#[test]
fn a_session_replays_into_the_expected_states() {
    // SessionStart -> prompt -> test run -> edit -> failed test -> Stop, through normaliser and reducer
    let by_name: std::collections::BTreeMap<String, Value> = fixtures().into_iter().collect();
    let env = golden_env(golden_fs());
    let ctx = NormalizeCtx::http(&env);
    let mut reducer = SessionReducer::new(
        "claude_code:7f1e2d3c-4b5a-4c6d-8e7f-0a1b2c3d4e5f",
        AgentKind::ClaudeCode,
        0,
    );
    let mut t = 0i64;
    fn state_after(
        name: &str,
        by_name: &std::collections::BTreeMap<String, Value>,
        ctx: &NormalizeCtx<'_>,
        reducer: &mut SessionReducer,
        t: &mut i64,
    ) -> AgentState {
        for o in normalize(&by_name[name]["hook"], ctx) {
            if let RawObservation::Event(e) = o {
                *t += 1_000;
                reducer.apply(&e, *t);
            }
        }
        reducer.state_at(*t)
    }
    assert_eq!(
        state_after(
            "session_start_startup",
            &by_name,
            &ctx,
            &mut reducer,
            &mut t
        ),
        AgentState::Idle
    );
    assert_eq!(
        state_after("user_prompt_submit", &by_name, &ctx, &mut reducer, &mut t),
        AgentState::Working
    );
    assert_eq!(
        state_after(
            "pre_tool_use_bash_npm_test",
            &by_name,
            &ctx,
            &mut reducer,
            &mut t
        ),
        AgentState::Testing
    );
    assert_eq!(
        state_after("pre_tool_use_edit", &by_name, &ctx, &mut reducer, &mut t),
        AgentState::WritingCode
    );
    assert_eq!(
        state_after(
            "post_tool_use_failure_bash_test",
            &by_name,
            &ctx,
            &mut reducer,
            &mut t
        ),
        AgentState::Error
    );
    let view = reducer.session_state(t);
    assert_eq!(
        view.last_test.as_ref().unwrap().status,
        agentnest_protocol::TestStatus::Failed
    );
    assert_eq!(view.counters.errors, 1);
    assert_eq!(view.recent_commands[0].command_preview, "npm test");
    assert_eq!(view.recent_commands[0].exit_code, Some(1));
    // Stop releases the 30 s test_failed latch (protocol.md 5.4); the 5 s transient latch of the command failure has
    // expired by then (the agent needs more than 5 s to react to a failed test)
    t += 5_000;
    assert_eq!(
        state_after("stop_done", &by_name, &ctx, &mut reducer, &mut t),
        AgentState::Completed
    );
    reducer.tick(t + 60_000);
    assert_eq!(reducer.state_at(t + 60_000), AgentState::Idle);
}

#[test]
fn normalisation_is_deterministic() {
    for (name, fx) in fixtures() {
        let a = {
            let env = golden_env(golden_fs());
            serde_json::to_value(
                events_of(&normalize(&fx["hook"], &NormalizeCtx::http(&env)))
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>(),
            )
            .unwrap()
        };
        let b = {
            let env = golden_env(golden_fs());
            serde_json::to_value(
                events_of(&normalize(&fx["hook"], &NormalizeCtx::http(&env)))
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>(),
            )
            .unwrap()
        };
        assert_eq!(a, b, "{name}");
    }
}

#[test]
fn hostile_hook_inputs_never_panic() {
    let env = golden_env(golden_fs());
    let ctx = NormalizeCtx::http(&env);
    let events = [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PermissionRequest",
        "PermissionDenied",
        "PostToolUse",
        "PostToolUseFailure",
        "Notification",
        "SubagentStart",
        "SubagentStop",
        "Stop",
        "StopFailure",
        "TaskCreated",
        "TaskCompleted",
        "PostCompact",
        "SessionEnd",
        "Nope",
    ];
    let weird_values = [
        json!(null),
        json!(7),
        json!("str"),
        json!([1, "a", null]),
        json!({"nested": {"a": [1]}}),
        json!("\u{0}\u{202e}"),
        json!(1.5e300),
    ];
    for ev in events {
        for tool in [
            "Bash",
            "PowerShell",
            "Write",
            "Edit",
            "Read",
            "Grep",
            "Agent",
            "mcp__a__b",
            "",
            "WebFetch",
        ] {
            for v in &weird_values {
                let hook = json!({
                    "hook_event_name": ev, "session_id": "s", "cwd": v, "tool_name": tool, "tool_input": v, "tool_response": v,
                    "prompt": v, "error": v, "message": v, "notification_type": v, "source": v, "reason": v,
                    "background_tasks": v, "session_crons": v, "last_assistant_message": v, "task_id": v, "agent_id": v,
                });
                let _ = normalize(&hook, &ctx);
                let _ = permission_request_draft(&hook, &ctx);
                let _ = pre_tool_use_risk(&hook);
            }
        }
    }
}

#[test]
fn huge_inputs_stay_bounded() {
    let env = golden_env(golden_fs());
    let ctx = NormalizeCtx::http(&env);
    let huge = "x ".repeat(400_000);
    let hook = json!({"hook_event_name": "PostToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": huge.clone()},
        "tool_response": {"stdout": huge.clone(), "stderr": huge.clone(), "interrupted": false}});
    for o in normalize(&hook, &ctx) {
        if let RawObservation::Event(e) = o {
            assert!(serde_json::to_vec(&e).unwrap().len() < 20_000, "{}", e.kind);
        }
    }
    let prompt = json!({"hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": huge});
    for o in normalize(&prompt, &ctx) {
        if let RawObservation::Event(e) = o {
            assert!(e.detail["prompt_preview"].as_str().unwrap().chars().count() <= 200);
        }
    }
}
