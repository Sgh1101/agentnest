//! Structural checks of `protocol/fixtures/*.json` so that the shared golden files stay well-formed and
//! self-consistent. The behavioural tests that run the fixtures through the real reducers/classifiers/summarisers live
//! in `agentnest-core` (Rust) and `android/core` (Kotlin).

mod common;

use std::collections::{BTreeMap, BTreeSet};

use agentnest_protocol::{AgentState, EventKind};
use common::{protocol_dir, read_json};
use regex::Regex;
use serde_json::Value;

fn fixture(name: &str) -> Value {
    read_json(&protocol_dir().join("fixtures").join(name))
}

fn cases(v: &Value) -> &Vec<Value> {
    v["cases"].as_array().expect("cases array")
}

fn unique_names(v: &Value) {
    let mut seen = BTreeSet::new();
    for c in cases(v) {
        let n = c["name"].as_str().unwrap();
        assert!(seen.insert(n.to_owned()), "duplicate case name {n}");
    }
}

// ------------------------------------------------------------------ risk_cases.json

#[test]
fn risk_cases_cover_every_rule_with_two_positive_and_two_negative_cases() {
    let v = fixture("risk_cases.json");
    unique_names(&v);
    let levels = v["reason_levels"].as_object().unwrap();
    let rank = |l: &str| {
        ["low", "medium", "high", "critical"]
            .iter()
            .position(|x| *x == l)
            .unwrap()
    };
    assert_eq!(
        levels.len(),
        31,
        "reason code list of integrations/claude-code.md 7 (9 critical, 9 high, 8 medium, 5 low)"
    );
    for want in [("critical", 9), ("high", 9), ("medium", 8), ("low", 5)] {
        assert_eq!(
            levels
                .values()
                .filter(|l| l.as_str() == Some(want.0))
                .count(),
            want.1,
            "{}",
            want.0
        );
    }

    let mut counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    assert!(cases(&v).len() >= 80, "at least 80 cases");
    for c in cases(&v) {
        let name = c["name"].as_str().unwrap();
        let rule = c["rule"].as_str().unwrap();
        let pol = c["polarity"].as_str().unwrap();
        assert!(levels.contains_key(rule), "{name}: unknown rule {rule}");
        let reasons: Vec<&str> = c["expect"]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap())
            .collect();
        assert!(!reasons.is_empty(), "{name}");
        for r in &reasons {
            assert!(levels.contains_key(*r), "{name}: unknown reason {r}");
        }
        match pol {
            "positive" => assert!(
                reasons.contains(&rule),
                "{name}: positive case must list {rule}"
            ),
            "negative" => assert!(
                !reasons.contains(&rule),
                "{name}: negative case must not list {rule}"
            ),
            other => panic!("{name}: polarity {other}"),
        }
        let level = c["expect"]["level"].as_str().unwrap();
        let plan_write = c["permission_mode"] == "plan"
            && matches!(
                c["tool_name"].as_str().unwrap(),
                "Edit" | "Write" | "MultiEdit" | "NotebookEdit"
            );
        for r in &reasons {
            let base = rank(levels[*r].as_str().unwrap());
            let expected = if plan_write { (base + 1).min(3) } else { base };
            assert_eq!(rank(level), expected, "{name}: level of reason {r}");
        }
        let extra = match level {
            "low" | "medium" => "none",
            "high" => "hold",
            _ => "hold_and_reconfirm",
        };
        assert_eq!(c["expect"]["extra_confirmation"], extra, "{name}");
        if let Some(exp) = c.get("expand") {
            for (ptr, spec) in exp.as_object().unwrap() {
                assert!(
                    c["tool_input"].pointer(ptr).is_some_and(Value::is_string),
                    "{name}: expand pointer {ptr}"
                );
                assert!(
                    spec["repeat"].is_string() && spec["count"].is_u64(),
                    "{name}"
                );
            }
        }
        if let Some(inj) = c.get("inject") {
            assert_eq!(inj, "classifier_panic");
            assert_eq!(reasons, ["classifier_error"], "{name}");
        }
        *counts.entry((rule.to_owned(), pol.to_owned())).or_default() += 1;
    }
    for rule in levels.keys() {
        for pol in ["positive", "negative"] {
            let n = counts
                .get(&(rule.clone(), pol.to_owned()))
                .copied()
                .unwrap_or(0);
            assert!(n >= 2, "rule {rule} needs >= 2 {pol} cases, has {n}");
        }
    }
}

// ------------------------------------------------------------------ redact_cases.json

fn apply_patterns(v: &Value, input: &str, replacement: &str) -> String {
    let mut s = input.to_owned();
    for p in v["patterns"].as_array().unwrap() {
        let re = Regex::new(p["regex"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", p["name"]));
        // fixture semantics (see `_format.known_limitations`): the named groups `pre` / `post` are kept, the rest of
        // the match is replaced; a pattern without them is replaced as a whole
        let keeps = re
            .capture_names()
            .flatten()
            .any(|n| n == "pre" || n == "post");
        s = if keeps {
            re.replace_all(&s, |c: &regex::Captures<'_>| {
                let g = |n: &str| c.name(n).map_or("", |m| m.as_str());
                format!("{}{replacement}{}", g("pre"), g("post"))
            })
            .into_owned()
        } else {
            re.replace_all(&s, replacement).into_owned()
        };
    }
    s
}

#[test]
fn redact_cases_agree_with_the_rust_regex_engine() {
    let v = fixture("redact_cases.json");
    unique_names(&v);
    assert_eq!(v["patterns"].as_array().unwrap().len(), 18);
    let repl = v["_format"]["replacement"].as_str().unwrap();
    let mut by_rule: BTreeMap<(String, String), usize> = BTreeMap::new();
    for c in cases(&v) {
        let name = c["name"].as_str().unwrap();
        let input = c["input"].as_str().unwrap();
        let out = apply_patterns(&v, input, repl);
        assert_eq!(out, c["expect"]["output"].as_str().unwrap(), "{name}");
        assert_eq!(
            out != input,
            c["expect"]["redacted"].as_bool().unwrap(),
            "{name}"
        );
        *by_rule
            .entry((
                c["rule"].as_str().unwrap().to_owned(),
                c["polarity"].as_str().unwrap().to_owned(),
            ))
            .or_default() += 1;
    }
    for p in v["patterns"].as_array().unwrap() {
        let n = p["name"].as_str().unwrap().to_owned();
        for pol in ["positive", "negative"] {
            assert!(
                by_rule
                    .get(&(n.clone(), pol.to_owned()))
                    .copied()
                    .unwrap_or(0)
                    >= 1,
                "pattern {n} needs a {pol} case"
            );
        }
    }
    let prepl = v["_format"]["cmd_preview_replacement"].as_str().unwrap();
    for c in v["cmd_preview_cases"].as_array().unwrap() {
        assert_eq!(
            apply_patterns(&v, c["input"].as_str().unwrap(), prepl),
            c["expect"]["output"].as_str().unwrap(),
            "{}",
            c["name"]
        );
    }
}

// ------------------------------------------------------------------ summaries_ko.json

#[test]
fn summaries_respect_the_length_limits() {
    let v = fixture("summaries_ko.json");
    unique_names(&v);
    assert!(cases(&v).len() >= 25);
    let check = |name: &str, e: &Value| {
        assert!(
            e["headline"].as_str().unwrap().chars().count() <= 40,
            "{name}: headline > 40"
        );
        if let Some(d) = e.get("detail") {
            assert!(
                d.as_str().unwrap().chars().count() <= 200,
                "{name}: detail > 200"
            );
        }
    };
    for c in cases(&v) {
        check(c["name"].as_str().unwrap(), &c["expect"]);
        assert!(c["expect"]["title"].as_str().unwrap().chars().count() <= 40);
        // URLs never appear beyond their host
        let text = c["expect"].to_string();
        assert!(
            !text.contains("token=") && !text.contains("http"),
            "{}",
            c["name"]
        );
    }
    for c in v["event_cases"].as_array().unwrap() {
        check(c["name"].as_str().unwrap(), &c["expect"]);
    }
}

// ------------------------------------------------------------------ state_transitions.json

#[test]
fn state_transition_cases_are_well_formed() {
    let v = fixture("state_transitions.json");
    unique_names(&v);
    let names: BTreeSet<&str> = cases(&v)
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    for required in [
        "codex_file_change",
        "codex_review_window",
        "codex_waiting_on_approval_flag",
        "codex_active_idle",
        "codex_web_mcp",
        "codex_socket_eof",
        "codex_system_error",
        "codex_hooks_unknown_tool",
    ] {
        assert!(
            names.contains(required),
            "protocol.md 5.4 requires the case {required}"
        );
    }
    let mut kinds_used = BTreeSet::new();
    for c in cases(&v) {
        let name = c["name"].as_str().unwrap();
        let mut last = 0u64;
        let steps = c["steps"].as_array().unwrap();
        assert!(!steps.is_empty(), "{name}");
        for s in steps {
            let t = s["t_ms"].as_u64().unwrap();
            assert!(t >= last, "{name}: t_ms must not decrease");
            last = t;
            let st = s["expect"]["state"].as_str().unwrap();
            assert!(
                !AgentState::from_wire(st).is_unknown(),
                "{name}: unknown state {st}"
            );
            if !s["input"].is_null() {
                let kind = s["input"]["kind"].as_str().unwrap();
                assert!(
                    !EventKind::from_wire(kind).is_unknown(),
                    "{name}: unknown kind {kind}"
                );
                kinds_used.insert(kind.to_owned());
            }
        }
    }
    for k in [
        "prompt_submitted",
        "command_started",
        "file_modified",
        "file_read",
        "approval_requested",
        "approval_resolved",
        "tool_failed",
        "command_failed",
        "test_failed",
        "turn_failed",
        "turn_completed",
        "turn_interrupted",
        "idle",
        "session_started",
        "session_ended",
        "review_started",
        "review_completed",
        "agent_error",
        "adapter_status",
        "notification",
    ] {
        assert!(kinds_used.contains(k), "no state case uses kind {k}");
    }
}

// ------------------------------------------------------------------ mood_priority.json

#[test]
fn mood_cases_are_consistent_with_the_focus_rank() {
    let v = fixture("mood_priority.json");
    unique_names(&v);
    let moods: BTreeSet<&str> = [
        "blink_slow",
        "typing",
        "magnifier",
        "tools",
        "raise_hand",
        "flustered",
        "celebrate",
        "sleepy",
        "worried",
    ]
    .into_iter()
    .collect();
    for c in cases(&v) {
        let name = c["name"].as_str().unwrap();
        let exp = &c["expect"];
        assert!(moods.contains(exp["mood"].as_str().unwrap()), "{name}");
        if c["link"] != "connected" {
            assert_eq!(
                exp["mood"],
                if c["link"] == "offline" {
                    "sleepy"
                } else {
                    "worried"
                },
                "{name}"
            );
            continue;
        }
        let live: Vec<&Value> = c["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| s["ended"] != Value::Bool(true))
            .collect();
        if live.is_empty() {
            assert!(exp["focus_session_key"].is_null(), "{name}");
            assert_eq!(exp["mood"], "blink_slow", "{name}");
            continue;
        }
        // focus = lowest rank, newest last_event_at wins ties (RFC 3339 strings of equal format sort chronologically)
        let best = live
            .iter()
            .min_by(|a, b| {
                let ra = AgentState::from_wire(a["state"].as_str().unwrap()).focus_rank();
                let rb = AgentState::from_wire(b["state"].as_str().unwrap()).focus_rank();
                ra.cmp(&rb).then_with(|| {
                    b["last_event_at"]
                        .as_str()
                        .unwrap()
                        .cmp(a["last_event_at"].as_str().unwrap())
                })
            })
            .unwrap();
        assert_eq!(exp["focus_session_key"], best["session_key"], "{name}");
        assert_eq!(exp["focus_state"], best["state"], "{name}");
    }
}
