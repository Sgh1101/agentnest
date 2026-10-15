//! Text-level contract tests against the TypeScript front end and the Tauri glue crate.
//!
//! They read `desktop/apps/desktop/src/api/*.ts` and `desktop/apps/desktop/src-tauri/src/*.rs` as plain text, so they
//! run on any platform and fail the moment one side drifts: a command without a handler, an argument renamed on one
//! side, an error code the UI cannot translate, a payload field the guards do not read.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use regex::Regex;
use serde_json::{json, Value};

use crate::commands::{COMMAND_ARGS, COMMAND_NAMES, EVENT_KINDS};

fn app_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../apps/desktop")
}

fn read(rel: &str) -> String {
    let path = app_dir().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn set<I: IntoIterator<Item = S>, S: Into<String>>(it: I) -> BTreeSet<String> {
    it.into_iter().map(Into::into).collect()
}

/// `COMMANDS = { camelName: "snake_name", ... }` of backend.ts.
fn ts_commands() -> Vec<(String, String)> {
    let src = read("src/api/backend.ts");
    let start = src.find("export const COMMANDS = {").expect("COMMANDS constant");
    let body = &src[start..];
    let end = body.find("} as const").expect("end of COMMANDS");
    let re = Regex::new(r#"(?m)^\s*(\w+):\s*"([a-z_]+)","#).unwrap();
    re.captures_iter(&body[..end])
        .map(|c| (c[1].to_owned(), c[2].to_owned()))
        .collect()
}

/// The body of `{ ... }` starting at `open` (index of the `{`), without the braces.
fn brace_body(src: &str, open: usize) -> &str {
    let bytes = src.as_bytes();
    let mut depth = 0usize;
    for (i, b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'{' | b'(' | b'[' => depth += 1,
            b'}' | b')' | b']' => {
                depth -= 1;
                if depth == 0 {
                    return &src[open + 1..i];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces");
}

/// Keys of a TS object literal body (`a: x, b, c: y`) at depth 0.
fn literal_keys(body: &str) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    let mut entries = Vec::new();
    for ch in body.chars() {
        match ch {
            '{' | '(' | '[' => {
                depth += 1;
                cur.push(ch);
            }
            '}' | ')' | ']' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => entries.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    entries.push(cur);
    for e in entries {
        let e = e.trim();
        if e.is_empty() {
            continue;
        }
        let key = e.split(':').next().unwrap().trim().trim_matches('"');
        keys.insert(key.to_owned());
    }
    keys
}

#[test]
fn every_ts_command_has_a_rust_handler_name_and_vice_versa() {
    let ts = ts_commands();
    assert!(ts.len() >= 20, "parsed {} commands", ts.len());
    let ts_names = set(ts.iter().map(|(_, n)| n.clone()));
    let rust_names = set(COMMAND_NAMES);
    assert_eq!(ts_names, rust_names, "COMMANDS (backend.ts) and COMMAND_NAMES differ");
    // same order too, so a diff of the two tables reads naturally
    let ordered: Vec<&str> = ts.iter().map(|(_, n)| n.as_str()).collect();
    assert_eq!(ordered, COMMAND_NAMES.to_vec());
}

/// The argument names tauri.ts sends for each command.
fn ts_call_args() -> std::collections::BTreeMap<String, BTreeSet<String>> {
    let src = read("src/api/tauri.ts");
    let names = ts_commands();
    let mut out = std::collections::BTreeMap::new();
    let call = Regex::new(r"this\.call\(COMMANDS\.(\w+)").unwrap();
    for m in call.captures_iter(&src) {
        let camel = &m[1];
        let command = names
            .iter()
            .find(|(c, _)| c == camel)
            .map(|(_, n)| n.clone())
            .unwrap_or_else(|| panic!("unknown COMMANDS.{camel}"));
        let after = &src[m.get(0).unwrap().end()..];
        let mut args = BTreeSet::new();
        let rest = after.trim_start();
        if let Some(r) = rest.strip_prefix(',') {
            let r = r.trim_start();
            if r.starts_with('{') {
                let open = src.len() - r.len();
                args = literal_keys(brace_body(&src, open));
            } else {
                // a variable: find its literal and its later `name["key"] =` assignments within the method
                let ident: String = r.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                let method_start = src[..m.get(0).unwrap().start()].rfind("async ").unwrap();
                let method_end = after.find("\n  }\n").map_or(src.len(), |e| m.get(0).unwrap().end() + e);
                let method = &src[method_start..method_end];
                let decl = Regex::new(&format!(r"const {ident}[^=]*=\s*\{{")).unwrap();
                if let Some(d) = decl.find(method) {
                    let open = method_start + d.end() - 1;
                    args = literal_keys(brace_body(&src, open));
                }
                let assign = Regex::new(&format!(r#"{ident}\["(\w+)"\]\s*="#)).unwrap();
                for a in assign.captures_iter(method) {
                    args.insert(a[1].to_owned());
                }
            }
        }
        out.insert(command, args);
    }
    out
}

#[test]
fn argument_names_match_what_tauri_ts_sends() {
    let sent = ts_call_args();
    for (name, rust_args) in COMMAND_ARGS {
        let ts_args = sent
            .get(name)
            .unwrap_or_else(|| panic!("tauri.ts never calls {name}"));
        assert_eq!(
            ts_args,
            &set(rust_args.iter().copied()),
            "argument names of {name}: tauri.ts vs COMMAND_ARGS"
        );
    }
}

fn glue_source() -> String {
    let path = app_dir().join("src-tauri/src/commands.rs");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the glue crate's commands.rs must exist ({}): {e}", path.display()))
}

/// Parameter names of `fn name(...)` excluding injected Tauri state.
fn glue_params(src: &str, name: &str) -> Option<BTreeSet<String>> {
    let re = Regex::new(&format!(r"fn {name}\s*\(")).unwrap();
    let m = re.find(src)?;
    let open = m.end() - 1;
    let body = brace_body(src, open);
    let mut params = BTreeSet::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    let mut parts = Vec::new();
    for ch in body.chars() {
        match ch {
            '<' | '(' | '[' | '{' => {
                depth += 1;
                cur.push(ch);
            }
            '>' | ')' | ']' | '}' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    parts.push(cur);
    for p in parts {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        let (pname, ty) = p.split_once(':').expect("typed parameter");
        let ty = ty.trim();
        // injected by Tauri, not sent by the front end
        if ty.starts_with("State<")
            || ty.starts_with("tauri::State<")
            || ty.starts_with("AppHandle")
            || ty.starts_with("tauri::AppHandle")
            || ty.starts_with("WebviewWindow")
            || ty.starts_with("tauri::WebviewWindow")
        {
            continue;
        }
        params.insert(pname.trim().to_owned());
    }
    Some(params)
}

#[test]
fn the_glue_crate_declares_every_command_with_the_contract_arguments() {
    let src = glue_source();
    for (name, args) in COMMAND_ARGS {
        let params = glue_params(&src, name)
            .unwrap_or_else(|| panic!("src-tauri/src/commands.rs has no `fn {name}(`"));
        assert_eq!(params, set(args.iter().copied()), "parameters of glue command {name}");
        // a #[tauri::command] attribute with snake_case argument names right above the function
        let idx = src.find(&format!("fn {name}")).unwrap();
        let before = &src[..idx];
        let attr = before.rfind("#[tauri::command").expect("command attribute");
        let between = &before[attr..];
        assert!(
            between.contains("rename_all = \"snake_case\""),
            "{name} needs #[tauri::command(rename_all = \"snake_case\")]"
        );
        assert!(
            !between[1..].contains("\n}\n"),
            "{name}'s attribute must belong to it"
        );
    }
}

#[test]
fn the_glue_registers_every_command_in_the_invoke_handler() {
    let main = std::fs::read_to_string(app_dir().join("src-tauri/src/lib.rs"))
        .expect("src-tauri/src/lib.rs");
    let start = main.find("generate_handler!").expect("generate_handler!");
    let open = main[start..].find('[').unwrap() + start;
    let body = brace_body(&main, open);
    for name in COMMAND_NAMES {
        assert!(
            body.contains(&format!("commands::{name}")),
            "generate_handler! misses commands::{name}"
        );
    }
    assert_eq!(
        body.matches("commands::").count(),
        COMMAND_NAMES.len(),
        "generate_handler! registers something that is not in the contract"
    );
}

#[test]
fn error_codes_are_exactly_the_ones_the_ui_can_translate() {
    let src = read("src/api/errors.ts");
    let start = src.find("MESSAGES_KO").unwrap();
    let body_start = src[start..].find("= {").unwrap() + start + 2;
    let keys = literal_keys(brace_body(&src, body_start));
    // `CONTRACT` is raised by the TS guards themselves
    let ui: BTreeSet<String> = keys.into_iter().filter(|k| k != "CONTRACT").collect();
    let rust: BTreeSet<String> = set(crate::error::code::ALL.iter().copied());
    assert_eq!(ui, rust, "error codes: errors.ts vs error::code::ALL");
}

fn guard_keys(function: &str) -> BTreeSet<String> {
    let src = read("src/api/guards.ts");
    let start = src
        .find(&format!("export function {function}("))
        .unwrap_or_else(|| panic!("guards.ts has no {function}"));
    let open = src[start..].find(" {\n").unwrap() + start + 1;
    let body = brace_body(&src, open);
    let helper = Regex::new(
        r#"(?:reqStr|optStr|reqNum|optNum|reqBool|boolOr)\(\s*r\s*,\s*"([^"]+)""#,
    )
    .unwrap();
    let index = Regex::new(r#"\b(?:r|v)\["([^"]+)"\]"#).unwrap();
    let mut keys = BTreeSet::new();
    for c in helper.captures_iter(body) {
        keys.insert(c[1].to_owned());
    }
    for c in index.captures_iter(body) {
        keys.insert(c[1].to_owned());
    }
    keys
}

fn top_keys(v: &Value) -> BTreeSet<String> {
    v.as_object().unwrap().keys().cloned().collect()
}

#[test]
fn daemon_status_fields_are_exactly_what_the_guard_reads() {
    use crate::dto::{DaemonStatusDto, LastEventAt};
    let dto = DaemonStatusDto {
        running: true,
        hook_port: 1,
        wss_addr: String::new(),
        hosts: vec![],
        link_enabled: true,
        cert_expires_at: None,
        spki_pin: String::new(),
        hooks_installed: false,
        effective_ttl_s: 120,
        hook_timeout_s: 0,
        codex_mode: "hooks",
        sessions: 0,
        devices_online: 0,
        remote_approval_paused: false,
        last_event_at: LastEventAt::default(),
    };
    assert_eq!(top_keys(&serde_json::to_value(dto).unwrap()), guard_keys("parseDaemonStatus"));
}

#[test]
fn small_result_payloads_match_their_guards() {
    use crate::dto::*;
    let device = DeviceDto {
        device_id: "d".into(),
        name: "n".into(),
        platform: "android".into(),
        model: None,
        paired_at: "t".into(),
        last_seen_at: None,
        online: false,
        revoked_at: None,
    };
    assert_eq!(top_keys(&serde_json::to_value(device).unwrap()), guard_keys("parseDevice"));
    let hooks = HooksStatusDto { installed: true, path: None, warnings: vec![] };
    assert_eq!(top_keys(&serde_json::to_value(hooks).unwrap()), guard_keys("parseHooksStatus"));
    let probe = CodexProbeDto { socket_path: None, reachable: false, user_agent: None, threads: 0 };
    assert_eq!(top_keys(&serde_json::to_value(probe).unwrap()), guard_keys("parseCodexProbe"));
    let fw = FirewallResultDto { ok: true, elevated: false, error: None };
    assert_eq!(top_keys(&serde_json::to_value(fw).unwrap()), guard_keys("parseFirewallResult"));
    let pairing = PairingStartDto { pairing_id: "p".into(), qr_svg: "<svg/>".into(), expires_at: "t".into() };
    assert_eq!(top_keys(&serde_json::to_value(pairing).unwrap()), guard_keys("parsePairingStart"));
    let hist = HistoryEntry {
        request_id: "r".into(),
        title: "t".into(),
        tool_name: "Bash".into(),
        risk_level: "low".into(),
        outcome: "allowed".into(),
        resolved_by: "phone".into(),
        resolved_device_name: None,
        resolved_at: "t".into(),
    };
    assert_eq!(top_keys(&serde_json::to_value(hist).unwrap()), guard_keys("parseHistoryEntry"));
}

#[test]
fn diagnostics_payload_matches_the_guard() {
    use crate::diagnostics::{build_report, DiagnosticsInput};
    use crate::net::{FirewallState, NetworkProfile};
    let report = build_report(&DiagnosticsInput {
        link_enabled: true,
        listener: Some("127.0.0.1:47832".parse().unwrap()),
        profile: NetworkProfile::Private,
        firewall: FirewallState::default(),
        platform_checks: true,
        last_preauth: Some(("t".into(), "1.2.3.x".into())),
        self_connect_ok: true,
        hosts: vec![],
    });
    let v = serde_json::to_value(report).unwrap();
    assert_eq!(top_keys(&v), guard_keys("parseDiagnostics"));
    // nested objects: the guard reads exactly these keys
    let src = read("src/api/guards.ts");
    for k in ["bound", "addr", "port", "rule_present", "scoped_ok", "block_rule_present", "at", "ip_masked"] {
        assert!(src.contains(&format!("\"{k}\"")), "guards.ts does not read {k}");
    }
    assert_eq!(top_keys(&v["listener"]), set(["bound", "addr", "port"]));
    assert_eq!(top_keys(&v["firewall"]), set(["rule_present", "scoped_ok", "block_rule_present"]));
    assert_eq!(top_keys(&v["last_preauth_attempt"]), set(["at", "ip_masked"]));
}

#[test]
fn settings_keys_are_exactly_the_ones_the_guard_reads_minus_autostart() {
    use crate::settings::{settings_value, UiSettings};
    let v = settings_value(&agentnest_core::config::AppConfig::default(), &UiSettings::default(), false);
    let mut guard = guard_keys("parseSettings");
    // the TS side owns `app.autostart` (autostart plugin)
    guard.remove("app.autostart");
    assert_eq!(top_keys(&v), guard);
    // the TS whitelist (SETTING_KEYS) is the writable set plus risk.accepted plus app.autostart
    let types = read("src/api/types.ts");
    let start = types.find("export const SETTING_KEYS").unwrap();
    let open = types[start..].find("= [").unwrap() + start + 2;
    let ts_keys: BTreeSet<String> = Regex::new(r#""([a-z_.]+)""#)
        .unwrap()
        .captures_iter(brace_body(&types, open))
        .map(|c| c[1].to_owned())
        .collect();
    let mut rust: BTreeSet<String> = set(crate::settings::WRITABLE_KEYS.iter().copied());
    rust.extend(set(crate::settings::READ_ONLY_KEYS.iter().copied()));
    rust.insert("app.autostart".to_owned());
    assert_eq!(ts_keys, rust, "SETTING_KEYS (types.ts) vs the Rust whitelist");
    // the TTL range is the same on both sides
    assert!(types.contains("TTL_MIN_S = 60") && types.contains("TTL_MAX_S = 180"));
}

#[test]
fn the_approval_card_and_event_carry_every_field_the_guards_read() {
    use crate::dto::{agent_event_value, approval_pending_value};
    let card: agentnest_protocol::ApprovalRequest = serde_json::from_value(json!({
        "request_id": "ar_1", "nonce_b64": "SECRET", "session_key": "claude_code:s",
        "agent_kind": "claude_code", "agent_label": "Claude Code",
        "project": {"project_key": "p", "name": "n"}, "origin": "claude_code.hook.http",
        "created_at": "t", "expires_at": "t", "ttl_seconds": 120, "tool_name": "Bash", "title": "t",
        "purpose": "p", "details": {"kind": "command", "command": "ls", "truncated": false},
        "tool_input_sha256": "a".repeat(64),
        "risk": {"level": "low", "reasons": [], "reasons_ko": [], "extra_confirmation": "none"},
        "allowed_decisions": ["allow"], "auth_required_for": [], "permission_mode": "default",
        "local_prompt": "unknown"
    }))
    .unwrap();
    let v = approval_pending_value(&card, &["dev_1".into()], true, false);
    let mut guard = guard_keys("parseApprovalRequest");
    guard.remove("origin"); // read through enumStrict(.., r["origin"], ..) below
    let sent = top_keys(&v);
    for k in &guard {
        assert!(sent.contains(k), "the card lacks `{k}`, which the guard reads");
    }
    assert!(sent.contains("origin") && sent.contains("delivery"));
    assert!(!sent.contains("nonce_b64"));
    // and nothing is sent that the guard would silently drop, except the delivery wrapper the pending guard reads
    let known: BTreeSet<String> = guard.into_iter().chain(["origin".to_owned(), "delivery".to_owned()]).collect();
    assert_eq!(sent, known);
    assert_eq!(top_keys(&v["delivery"]), guard_keys("parseDelivery"));

    let event: agentnest_protocol::AgentEvent = serde_json::from_value(json!({
        "event_id": "e", "seq": 4, "ts": "t", "agent_kind": "claude_code", "session_key": "s",
        "kind": "tool_started", "category": "tool", "severity": "info",
        "summary": {"headline": "h"}, "detail": {"command": "SECRET"},
        "source": {"channel": "claude_code.hook.http", "native_event": "PreToolUse"}
    }))
    .unwrap();
    let e = agent_event_value(&event);
    let sent = top_keys(&e);
    for k in guard_keys("parseAgentEvent") {
        if k == "detail" {
            continue;
        }
        // optional keys the event legitimately omits (null on the TS side)
        if ["project", "state_hint"].contains(&k.as_str()) {
            continue;
        }
        assert!(sent.contains(&k), "the event lacks `{k}`");
    }
    assert!(!sent.contains("detail"), "the bounded detail object stays in the daemon");
    assert!(!e.to_string().contains("SECRET"));
}

#[test]
fn event_kinds_match_the_guard_switch() {
    let src = read("src/api/guards.ts");
    let start = src.find("export function parseDaemonEvent").unwrap();
    let open = src[start..].find(" {\n").unwrap() + start + 1;
    let body = brace_body(&src, open);
    let kinds: BTreeSet<String> = Regex::new(r#"case "(\w+)":"#)
        .unwrap()
        .captures_iter(body)
        .map(|c| c[1].to_owned())
        .collect();
    assert_eq!(kinds, set(EVENT_KINDS));
    let types = read("src/api/types.ts");
    assert!(types.contains(&format!("DAEMON_EVENT_NAME = \"{}\"", crate::commands::DAEMON_EVENT_NAME)));
}

#[test]
fn pairing_and_approval_ops_match_the_guards() {
    let src = read("src/api/guards.ts");
    for op in ["pending_sas", "completed", "ended", "requested", "delivery", "resolved"] {
        assert!(src.contains(&format!("op === \"{op}\"")), "guards.ts has no op {op}");
    }
    for reason in ["expired", "cancelled", "rejected", "failed", "timeout", "link_disabled"] {
        assert!(src.contains(&format!("\"{reason}\"")), "guards.ts lacks the pairing reason {reason}");
    }
}
