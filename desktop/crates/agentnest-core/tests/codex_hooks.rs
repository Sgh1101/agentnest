//! Golden tests of the Codex hooks normaliser (docs/integrations/codex.md 5.3).
//!
//! The payload shapes beyond the common fields are UNVERIFIED (Phase 0 C10), so the fixtures under
//! `tests/fixtures/codex_hooks/` are **synthetic** (`"synthetic": true`) and say so. They pin the mapping table of
//! codex.md 5.3: known candidate tool names are specialised, unknown ones stay `working`.

mod common;

use agentnest_adapter_api::RawObservation;
use agentnest_core::adapters::codex::hooks::{normalize, permission_request_draft};
use agentnest_core::state::reducer::SessionReducer;
use agentnest_protocol::{AgentEvent, AgentKind, AgentState, ReviewState};
use common::*;
use serde_json::{json, Value};

fn fixtures() -> Vec<(String, Value)> {
    json_files(&fixtures_dir().join("codex_hooks"))
        .into_iter()
        .map(|p| {
            (
                p.file_stem().unwrap().to_string_lossy().into_owned(),
                read_json(&p),
            )
        })
        .collect()
}

fn events_of(obs: Vec<RawObservation>) -> Vec<AgentEvent> {
    obs.into_iter()
        .filter_map(|o| match o {
            RawObservation::Event(e) => Some(e),
            _ => None,
        })
        .collect()
}

#[test]
fn every_synthetic_fixture_normalises_to_the_expected_events() {
    let schemas = Schemas::load();
    let validator = schemas.validator("model/agent_event.schema.json");
    let all = fixtures();
    assert!(all.len() >= 14, "got {}", all.len());
    let mut failures = Vec::new();
    for (name, fx) in &all {
        assert_eq!(
            fx["synthetic"], true,
            "{name}: fixtures must be marked synthetic until C10 captures exist"
        );
        let env = golden_env(golden_fs());
        let events = events_of(normalize(&fx["hook"], &env));
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
            assert_eq!(ev.agent_kind, AgentKind::Codex, "{name}");
            assert!(ev.session_key.starts_with("codex:"), "{name}");
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
                failures.push(format!("{name}: forbidden text {needle:?} in the events"));
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
fn permission_request_is_observation_only_and_never_offers_deny_and_stop() {
    let mut seen = 0;
    for (name, fx) in fixtures() {
        let Some(want) = fx.get("expect_draft") else {
            continue;
        };
        seen += 1;
        let env = golden_env(golden_fs());
        assert!(normalize(&fx["hook"], &env).is_empty(), "{name}");
        let d = permission_request_draft(&fx["hook"], &env).unwrap();
        let got = json!({
            "session_key": d.session_key, "tool_name": d.tool_name, "origin": d.origin.as_str(), "agent_id": d.agent_id,
            "available_decisions": d.available_decisions.iter().map(|x| x.as_str()).collect::<Vec<_>>(),
        });
        subset(want, &got).unwrap_or_else(|m| panic!("{name}: {m}"));
    }
    assert_eq!(seen, 1);
}

#[test]
fn state_path_for_codex_hooks_matches_the_state_table() {
    let by_name: std::collections::BTreeMap<String, Value> = fixtures().into_iter().collect();
    let env = golden_env(golden_fs());
    let mut reducer = SessionReducer::new(
        "codex:0199e0a4-7c1d-7b3c-9e4d-2a7b1c3d4e5f",
        AgentKind::Codex,
        0,
    );
    let mut t = 0i64;
    let mut step = |name: &str, reducer: &mut SessionReducer| -> AgentState {
        for e in events_of(normalize(&by_name[name]["hook"], &env)) {
            t += 1_000;
            reducer.apply(&e, t);
        }
        reducer.state_at(t)
    };
    assert_eq!(step("session_start", &mut reducer), AgentState::Idle);
    assert_eq!(
        step("user_prompt_submit", &mut reducer),
        AgentState::Working
    );
    assert_eq!(
        step("pre_tool_use_shell_test", &mut reducer),
        AgentState::Testing
    );
    // codex.md 5.3: a patch tool is writing_code, an unknown tool name does NOT match that row and stays working
    assert_eq!(
        step("pre_tool_use_apply_patch", &mut reducer),
        AgentState::WritingCode
    );
    assert_eq!(
        step("pre_tool_use_unknown_tool", &mut reducer),
        AgentState::Working
    );
    assert_eq!(step("stop", &mut reducer), AgentState::Completed);
    // hooks mode has no review source: the phone shows "unavailable"
    let view = reducer.session_state(t);
    assert_eq!(
        view.meta.review.as_ref().unwrap().state,
        ReviewState::Unavailable
    );
    assert_eq!(
        view.remote_approval,
        agentnest_protocol::RemoteApproval::PolicyUnknown
    );
}

#[test]
fn hooks_adapter_never_emits_a_decision_shape() {
    // The hooks normaliser has no reply type at all; the draft offers allow/deny only.
    let env = golden_env(golden_fs());
    let hook = json!({"hook_event_name": "PermissionRequest", "session_id": "s", "tool_name": "shell", "tool_input": {"command": "ls"}});
    let d = permission_request_draft(&hook, &env).unwrap();
    assert_eq!(d.available_decisions.len(), 2);
}
