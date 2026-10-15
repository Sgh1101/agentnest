//! Codex hooks adapter: `POST /v1/hooks/codex` normalisation (docs/integrations/codex.md 5.3).
//!
//! **Observation only.** Everything about the Codex hook payloads beyond the common fields is `UNVERIFIED (Phase 0 C10)`:
//! the values of `tool_name`, which events carry a `tool_use_id`, the shape of `tool_response` and the `apply_patch`
//! input are not verified against a real Codex run. The mapping therefore follows the Codex-specific table of codex.md
//! 5.3 and never guesses: a tool name this module does not recognise becomes `tool_started{tool_name}` and the reducer
//! keeps it at `working` (it never gets promoted to `writing_code` by accident). The Claude Code normaliser is **not**
//! reused for tool names, only the common post-processing (project resolution, masking, bounds) is shared.
//!
//! Approvals: [`permission_request_draft`] describes a hooks `PermissionRequest` (origin `codex.hook.cli`, no
//! `deny_and_stop`, because a hooks reply with `interrupt` would void the decision, codex.md 5.2). Whether it is used at
//! all is decided by the adapter registry: until Phase 0 C6 passes, `PermissionRequest` is answered observation-only
//! (empty reply). This module makes **no decision** and builds no reply.
//!
//! Fixtures under `tests/fixtures/codex_hooks/` are synthetic (`"synthetic": true`) until C10 captures replace them.

use agentnest_adapter_api::{ApprovalDraft, NativeBinding, RawObservation};
use agentnest_protocol::canonical::{canonical_json, tool_input_sha256};
use agentnest_protocol::{
    AgentEvent, AgentKind, AgentState, CommandClass, Decision, EventKind, Severity, SourceChannel,
};
use serde_json::{json, Map, Value};

use crate::normalize::hook::{
    first_line, int_field, raw_text, str_field, tool_input_with_truncation_marker, Hook,
    RAW_TEXT_MAX_BYTES,
};
use crate::normalize::path;
use crate::normalize::post::{build_event, EventDraft};
use crate::normalize::NormalizeEnv;
use crate::redact::{clip, head_bytes, tail_bytes};
use crate::risk::classify::command_text;
use crate::risk::command_class::{command_class_for, runner};
use crate::risk::rules::apply_patch_changes;
use crate::risk::tokenizer::Shell;
use crate::state::timers::format_ms;
use crate::summarize::ko::{self, ToolObservation};

const RAW_TAIL_BYTES: usize = 4 * 1024;
const MAX_PATCH_FILES: usize = 5;

/// Why a draft could not be built.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CodexHookError {
    /// The input is not a hook (no object, no `hook_event_name` or no `session_id`).
    #[error("not a hook input")]
    NotAHook,
    /// The hook is not a `PermissionRequest`.
    #[error("not a PermissionRequest")]
    NotPermissionRequest,
    /// A `PermissionRequest` without `tool_name`.
    #[error("PermissionRequest without tool_name")]
    MissingToolName,
}

/// UNVERIFIED (Phase 0 C10): candidate names of the shell tool.
fn is_shell_tool(lower: &str) -> bool {
    matches!(
        lower,
        "bash" | "shell" | "local_shell" | "exec_command" | "shell_command" | "powershell"
    )
}

/// UNVERIFIED (Phase 0 C10): candidate name of the patch tool (aliases are possible).
fn is_patch_tool(lower: &str) -> bool {
    matches!(lower, "apply_patch" | "applypatch")
}

fn map(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

fn draft(h: &Hook<'_>, kind: EventKind) -> EventDraft {
    h.draft(AgentKind::Codex, SourceChannel::CodexHookCli, kind)
}

fn push(out: &mut Vec<RawObservation>, d: EventDraft, env: &NormalizeEnv) {
    let ev: AgentEvent = build_event(d, env);
    out.push(RawObservation::Event(ev));
}

fn with_input_hash(d: &mut EventDraft, h: &Hook<'_>) {
    if !h.tool_input.is_null() {
        d.native_ids.insert(
            "tool_input_sha256".to_owned(),
            tool_input_sha256(h.tool_input),
        );
    }
}

/// Normalises one Codex hook input. `PermissionRequest` yields no observations here (see the module docs).
pub fn normalize(hook: &Value, env: &NormalizeEnv) -> Vec<RawObservation> {
    let Some(h) = Hook::parse(hook) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    match h.event_name {
        "SessionStart" => {
            let source = str_field(hook, "source")
                .filter(|s| matches!(*s, "startup" | "resume" | "clear" | "compact" | "fork"))
                .unwrap_or("startup");
            let mut d = draft(&h, EventKind::SessionStarted);
            d.headline = ko::session_started_headline(source);
            d.state_hint = matches!(source, "startup" | "clear").then_some(AgentState::Idle);
            let mut detail = json!({ "source_reason": source });
            if let Some(m) = str_field(hook, "model") {
                detail["model"] = json!(m);
            }
            if let Some(p) = h.permission_mode {
                detail["permission_mode"] = json!(p);
            }
            d.detail = map(detail);
            push(&mut out, d, env);
        }
        "SessionEnd" => {
            let mut d = draft(&h, EventKind::SessionEnded);
            d.headline = ko::session_ended_headline();
            d.detail = map(json!({ "reason": str_field(hook, "reason").unwrap_or("other") }));
            push(&mut out, d, env);
        }
        "UserPromptSubmit" => {
            let prompt = raw_text(hook, "prompt").unwrap_or_default();
            let len = hook
                .get("prompt")
                .and_then(Value::as_str)
                .map(|s| s.chars().count())
                .unwrap_or(0);
            let preview =
                crate::redact::mask_and_clip(&prompt, crate::redact::PROMPT_PREVIEW_MAX_CHARS).text;
            let (headline, summary_detail) = ko::prompt_submitted_summary(&preview);
            let mut d = draft(&h, EventKind::PromptSubmitted);
            d.headline = headline;
            d.summary_detail = summary_detail;
            d.state_hint = Some(AgentState::Working);
            d.detail = map(
                json!({ "prompt_preview": prompt, "prompt_len": len, "auto_turn_suspect": false }),
            );
            push(&mut out, d, env);
        }
        "PreToolUse" => pre_tool_use(&h, env, &mut out),
        "PostToolUse" => post_tool_use(&h, env, &mut out),
        // observation-only until Phase 0 C6; the draft is built by `permission_request_draft`
        "PermissionRequest" | "PreCompact" => {}
        "Stop" => {
            let last = raw_text(hook, "last_assistant_message");
            let (headline, summary_detail) = ko::stop_summary(0, last.as_deref());
            let mut detail = json!({ "background_tasks": 0, "session_crons": 0 });
            if let Some(m) = last {
                detail["final_message_preview"] = json!(m);
            }
            let mut d = draft(&h, EventKind::TurnCompleted);
            d.headline = headline;
            d.summary_detail = summary_detail;
            d.state_hint = Some(AgentState::Completed);
            d.detail = map(detail);
            push(&mut out, d, env);
        }
        "Interrupt" => {
            let mut d = draft(&h, EventKind::TurnInterrupted);
            d.headline = ko::turn_interrupted_headline();
            d.state_hint = Some(AgentState::Idle);
            push(&mut out, d, env);
        }
        "SubagentStart" | "SubagentStop" => {
            let started = h.event_name == "SubagentStart";
            let kind = if started {
                EventKind::SubagentStarted
            } else {
                EventKind::SubagentStopped
            };
            let agent_type = h.agent_type.unwrap_or("");
            let mut detail =
                json!({ "agent_id": h.agent_id.unwrap_or(""), "agent_type": agent_type });
            if !started {
                if let Some(m) = raw_text(hook, "last_assistant_message") {
                    detail["final_message_preview"] = json!(m);
                }
            }
            let mut d = draft(&h, kind);
            d.headline = ko::subagent_headline(started, agent_type);
            d.detail = map(detail);
            push(&mut out, d, env);
        }
        "PostCompact" => {
            let mut detail = json!({ "trigger": str_field(hook, "trigger").unwrap_or("auto") });
            if let Some(s) = raw_text(hook, "compact_summary") {
                detail["summary_preview"] = json!(s);
            }
            let mut d = draft(&h, EventKind::ContextCompacted);
            d.headline = ko::context_compacted_headline();
            d.detail = map(detail);
            push(&mut out, d, env);
        }
        other => {
            let safe: String = other
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .take(48)
                .collect();
            let nt = format!("unknown_hook:{safe}");
            let mut d = draft(&h, EventKind::Notification);
            d.headline = ko::notification_headline(&nt);
            d.detail = map(json!({ "notification_type": nt, "message": "" }));
            push(&mut out, d, env);
        }
    }
    out
}

fn pre_tool_use(h: &Hook<'_>, env: &NormalizeEnv, out: &mut Vec<RawObservation>) {
    let tool = h.tool_name.unwrap_or("");
    let lower = tool.to_ascii_lowercase();
    let ti = h.tool_input;
    let summary = |class: Option<CommandClass>| {
        ko::summarize_tool(&ToolObservation {
            agent_kind: AgentKind::Codex,
            tool_name: tool,
            tool_input: ti,
            cwd: h.cwd,
            command_class: class,
            file_exists: None,
            permission_request: false,
        })
    };
    if is_shell_tool(&lower) {
        let command = command_text(ti);
        let shell = if lower == "powershell" {
            Shell::PowerShell
        } else {
            Shell::Posix
        };
        let class = command_class_for(&command, shell);
        let s = summary(Some(class.clone()));
        let testing = matches!(class, CommandClass::Test | CommandClass::Build);
        let mut detail = json!({
            "tool_name": tool,
            "command": head_bytes(&command, RAW_TEXT_MAX_BYTES).0,
            "command_class": class.as_str(),
            "cwd_hint": h.cwd.unwrap_or(""),
            "run_in_background": false,
        });
        let mut d = draft(h, EventKind::CommandStarted);
        d.headline = s.headline.clone();
        d.summary_detail = s.detail.clone();
        d.state_hint = Some(if testing {
            AgentState::Testing
        } else {
            AgentState::Working
        });
        d.detail = map(detail.clone());
        with_input_hash(&mut d, h);
        push(out, d, env);
        if class == CommandClass::Test {
            detail["runner"] =
                json!(runner(&command, shell).unwrap_or_else(|| "unknown".to_owned()));
            let mut t = draft(h, EventKind::TestRun);
            t.headline = s.headline;
            t.summary_detail = s.detail;
            t.state_hint = Some(AgentState::Testing);
            t.detail = map(detail);
            with_input_hash(&mut t, h);
            push(out, t, env);
        }
        return;
    }
    if is_patch_tool(&lower) {
        let changes = apply_patch_changes(ti);
        let s = summary(None);
        let first = changes.first().map(|(p, _)| p.clone()).unwrap_or_default();
        let mut d = draft(h, EventKind::ToolStarted);
        d.headline = s.headline;
        d.summary_detail = s.detail;
        // Only a recognised patch tool gets the writing_code hint; the reducer matches `apply_patch` itself.
        d.state_hint = Some(AgentState::WritingCode);
        d.detail = map(json!({
            "tool_name": tool,
            "tool_input_summary": path::basename(&first),
            "file_path": first,
            "op": "edit",
        }));
        with_input_hash(&mut d, h);
        push(out, d, env);
        return;
    }
    // MCP, web search and everything unknown: `working`
    let s = summary(None);
    let summary_text = if lower == "web_search" {
        str_field(ti, "query")
            .map(|q| clip(q, 60))
            .unwrap_or_default()
    } else if tool.starts_with("mcp__") {
        tool.to_owned()
    } else {
        String::new()
    };
    let mut detail = json!({ "tool_name": tool, "tool_input_summary": summary_text });
    if let Some(srv) = tool
        .strip_prefix("mcp__")
        .and_then(|r| r.split("__").next())
        .filter(|s| !s.is_empty())
    {
        detail["mcp_server"] = json!(srv);
    }
    let mut d = draft(h, EventKind::ToolStarted);
    d.headline = s.headline;
    d.summary_detail = s.detail;
    d.state_hint = Some(AgentState::Working);
    d.detail = map(detail);
    with_input_hash(&mut d, h);
    push(out, d, env);
}

/// UNVERIFIED (Phase 0 C10): the `tool_response` shape. Tolerates a string or an object with `exit_code` / `exitCode` /
/// `metadata.exit_code` and `stdout` / `stderr` / `output`.
fn shell_response(resp: &Value) -> (Option<i64>, Option<String>, Option<String>) {
    let exit = int_field(resp, "exit_code")
        .or_else(|| int_field(resp, "exitCode"))
        .or_else(|| resp.get("metadata").and_then(|m| int_field(m, "exit_code")));
    let text = |k: &str| {
        resp.get(k)
            .and_then(Value::as_str)
            .map(|s| tail_bytes(s, RAW_TAIL_BYTES).0)
    };
    match resp {
        Value::String(s) => (None, Some(tail_bytes(s, RAW_TAIL_BYTES).0), None),
        _ => (
            exit,
            text("stdout").or_else(|| text("output")),
            text("stderr"),
        ),
    }
}

fn post_tool_use(h: &Hook<'_>, env: &NormalizeEnv, out: &mut Vec<RawObservation>) {
    let tool = h.tool_name.unwrap_or("");
    let lower = tool.to_ascii_lowercase();
    let ti = h.tool_input;
    let resp = h.raw.get("tool_response").unwrap_or(&Value::Null);
    let duration = int_field(h.raw, "duration_ms");
    if is_shell_tool(&lower) {
        let command = command_text(ti);
        let shell = if lower == "powershell" {
            Shell::PowerShell
        } else {
            Shell::Posix
        };
        let class = command_class_for(&command, shell);
        let (exit, stdout, stderr) = shell_response(resp);
        let failed = exit.is_some_and(|c| c != 0);
        let mut detail = json!({
            "tool_name": tool,
            "command": head_bytes(&command, RAW_TEXT_MAX_BYTES).0,
            "command_class": class.as_str(),
        });
        if let Some(c) = exit {
            detail["exit_code"] = json!(c);
        }
        if let Some(ms) = duration {
            detail["duration_ms"] = json!(ms);
        }
        if failed {
            // Codex has no PostToolUseFailure event: a non-zero exit code arrives as PostToolUse.
            let err_src = stderr
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or(stdout.clone())
                .unwrap_or_default();
            let line = first_line(&err_src);
            detail["error"] = json!(if line.is_empty() {
                format!("exit code {}", exit.unwrap_or(1))
            } else {
                line.to_owned()
            });
            let mut d = draft(h, EventKind::CommandFailed);
            d.severity = Severity::Warning;
            d.headline = format!("명령이 실패했어요 (exit {})", exit.unwrap_or(1));
            d.state_hint = Some(AgentState::Error);
            d.detail = map(detail.clone());
            with_input_hash(&mut d, h);
            push(out, d, env);
            if class == CommandClass::Test {
                detail["runner"] =
                    json!(runner(&command, shell).unwrap_or_else(|| "unknown".to_owned()));
                let mut t = draft(h, EventKind::TestFailed);
                t.headline = ko::command_completed_headline(&class, exit);
                t.state_hint = Some(AgentState::Error);
                t.detail = map(detail);
                with_input_hash(&mut t, h);
                push(out, t, env);
            }
            return;
        }
        if let Some(s) = stdout.filter(|s| !s.is_empty()) {
            detail["stdout_tail"] = json!(s);
        }
        if let Some(s) = stderr.filter(|s| !s.is_empty()) {
            detail["stderr_tail"] = json!(s);
        }
        let mut d = draft(h, EventKind::CommandCompleted);
        d.headline = ko::command_completed_headline(&class, exit);
        d.detail = map(detail.clone());
        with_input_hash(&mut d, h);
        push(out, d, env);
        if class == CommandClass::Test && exit == Some(0) {
            detail["runner"] =
                json!(runner(&command, shell).unwrap_or_else(|| "unknown".to_owned()));
            let mut t = draft(h, EventKind::TestPassed);
            t.headline = ko::command_completed_headline(&class, Some(0));
            t.detail = map(detail);
            with_input_hash(&mut t, h);
            push(out, t, env);
        }
        return;
    }
    if is_patch_tool(&lower) {
        let changes = apply_patch_changes(ti);
        if !changes.is_empty() {
            for (p, kind) in changes.iter().take(MAX_PATCH_FILES) {
                let op = match *kind {
                    "add" => "create",
                    "delete" => "delete",
                    _ => "edit",
                };
                let mut d = draft(h, EventKind::FileModified);
                d.headline = ko::file_modified_headline(p, op);
                d.state_hint = Some(AgentState::WritingCode);
                d.detail = map(json!({ "file_path": p, "op": op }));
                with_input_hash(&mut d, h);
                push(out, d, env);
            }
            return;
        }
        // The patch format was not understood: report a plain completion rather than guessing file names.
    }
    let mut detail = json!({ "tool_name": tool });
    if let Some(ms) = duration {
        detail["duration_ms"] = json!(ms);
    }
    let mut d = draft(h, EventKind::ToolCompleted);
    d.headline = ko::tool_completed_headline(tool);
    d.detail = map(detail);
    with_input_hash(&mut d, h);
    push(out, d, env);
}

/// Describes a hooks `PermissionRequest` for the approval broker (origin `codex.hook.cli`). `available_decisions` has no
/// `deny_and_stop`: a hooks reply with `interrupt` voids the decision (codex.md 5.2), so it is never offered.
///
/// `// UNVERIFIED (Phase 0 C6)`: whether a hooks `PermissionRequest` can be answered at all (and what "no output" does)
/// is unverified; the registry must not use this before C6 passes. No decision is made here.
pub fn permission_request_draft(
    hook: &Value,
    env: &NormalizeEnv,
) -> Result<ApprovalDraft, CodexHookError> {
    let h = Hook::parse(hook).ok_or(CodexHookError::NotAHook)?;
    if h.event_name != "PermissionRequest" {
        return Err(CodexHookError::NotPermissionRequest);
    }
    let tool = h.tool_name.ok_or(CodexHookError::MissingToolName)?;
    let mut ids = std::collections::BTreeMap::new();
    ids.insert("tool_name".to_owned(), tool.to_owned());
    ids.insert(
        "tool_input_sha256".to_owned(),
        tool_input_sha256(h.tool_input),
    );
    if let Some(t) = h.turn_id {
        ids.insert("turn_id".to_owned(), t.to_owned());
    }
    Ok(ApprovalDraft {
        binding: NativeBinding {
            agent_kind: AgentKind::Codex,
            native_session_id: h.session_id.to_owned(),
            ids,
        },
        session_key: format!("codex:{}", h.session_id),
        agent_kind: AgentKind::Codex,
        agent_id: h.agent_id.map(str::to_owned),
        project: h.cwd.map(|c| env.projects.resolve(c)),
        cwd: h.cwd.map(str::to_owned),
        tool_name: tool.to_owned(),
        tool_input: tool_input_with_truncation_marker(h.tool_input, hook),
        origin: SourceChannel::CodexHookCli,
        permission_mode: h.permission_mode.map(str::to_owned),
        available_decisions: vec![Decision::Allow, Decision::Deny],
        permission_suggestions_count: None,
        agent_description: str_field(h.tool_input, "description").map(str::to_owned),
        reason: None,
        created_at: format_ms(env.clock.now_ms()),
    })
}

/// The bytes to hash as the `body` of [`crate::normalize::dedupe::dedupe_key`] for a Codex `PermissionRequest`: the
/// canonical `tool_input`. Codex `PermissionRequest` has no `tool_use_id`, so the key falls back to the input hash
/// (codex.md 5.3: no rule may assume a `tool_use_id`).
pub fn permission_dedupe_body(hook: &Value) -> Vec<u8> {
    canonical_json(hook.get("tool_input").unwrap_or(&Value::Null)).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::project::testing::FakeFs;
    use crate::normalize::{ProjectResolver, SequentialIdGen};
    use crate::state::timers::ManualClock;
    use std::sync::Arc;

    fn env() -> NormalizeEnv {
        let clock = Arc::new(ManualClock::new(1_792_055_553_120));
        NormalizeEnv::new(
            clock.clone(),
            Arc::new(SequentialIdGen::default()),
            Arc::new(ProjectResolver::with_probe(
                Box::new(FakeFs::default()),
                clock,
            )),
        )
    }

    fn events(hook: Value) -> Vec<AgentEvent> {
        normalize(&hook, &env())
            .into_iter()
            .filter_map(|o| match o {
                RawObservation::Event(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    fn pre(tool: &str, input: Value) -> Vec<AgentEvent> {
        events(
            json!({"hook_event_name": "PreToolUse", "session_id": "th1", "turn_id": "tu1", "cwd": "/w", "model": "gpt-x",
            "permission_mode": "on-request", "tool_name": tool, "tool_input": input, "tool_use_id": "call_1"}),
        )
    }

    #[test]
    fn session_key_channel_and_turn_id() {
        let evs = pre("shell", json!({"command": ["bash", "-lc", "cargo test"]}));
        let e = &evs[0];
        assert_eq!(e.session_key, "codex:th1");
        assert_eq!(e.agent_kind, AgentKind::Codex);
        assert_eq!(e.source.channel, SourceChannel::CodexHookCli);
        assert_eq!(e.source.native_ids["turn_id"], "tu1");
        assert_eq!(e.kind, EventKind::CommandStarted);
        assert_eq!(
            e.detail["command"], "cargo test",
            "argv form: the script of `bash -lc`"
        );
        assert_eq!(evs[1].kind, EventKind::TestRun);
        assert_eq!(e.state_hint, Some(AgentState::Testing));
    }

    #[test]
    fn apply_patch_is_writing_code_and_unknown_tools_are_not() {
        let patch = "*** Begin Patch\n*** Update File: src/a.rs\n@@\n*** Add File: docs/n.md\n*** End Patch";
        let evs = pre("apply_patch", json!(patch));
        assert_eq!(evs[0].kind, EventKind::ToolStarted);
        assert_eq!(evs[0].state_hint, Some(AgentState::WritingCode));
        assert_eq!(evs[0].detail["tool_name"], "apply_patch");
        // an unknown tool name must not be promoted
        let evs = pre("some_future_tool", json!({}));
        assert_eq!(evs[0].state_hint, Some(AgentState::Working));
        assert_eq!(
            evs[0].headline_for_test(),
            "some_future_tool 도구를 쓰고 있어요"
        );
        let evs = pre("mcp__github__create_issue", json!({"title": "x"}));
        assert_eq!(evs[0].detail["mcp_server"], "github");
        assert_eq!(
            pre("web_search", json!({"query": "rust"}))[0].state_hint,
            Some(AgentState::Working)
        );
    }

    #[test]
    fn patch_post_tool_use_yields_file_modified_per_file_or_a_plain_completion() {
        let patch = "*** Begin Patch\n*** Update File: src/a.rs\n*** Add File: docs/n.md\n*** Delete File: old.txt\n*** End Patch";
        let evs = events(
            json!({"hook_event_name": "PostToolUse", "session_id": "th1", "tool_name": "apply_patch", "tool_input": patch, "tool_response": "ok", "tool_use_id": "c2"}),
        );
        let ops: Vec<String> = evs
            .iter()
            .map(|e| e.detail["op"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(ops, vec!["edit", "create", "delete"]);
        // an unrecognised patch format: no guessed file names
        let evs = events(
            json!({"hook_event_name": "PostToolUse", "session_id": "th1", "tool_name": "apply_patch", "tool_input": "weird", "tool_response": "ok"}),
        );
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, EventKind::ToolCompleted);
    }

    #[test]
    fn failing_commands_arrive_as_post_tool_use_with_an_exit_code() {
        let evs = events(
            json!({"hook_event_name": "PostToolUse", "session_id": "th1", "tool_name": "shell", "tool_input": {"command": "cargo test"},
            "tool_response": {"exit_code": 101, "stdout": "", "stderr": "error[E0432]: unresolved import\nmore"}}),
        );
        let kinds: Vec<&str> = evs.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(kinds, vec!["command_failed", "test_failed"]);
        assert_eq!(evs[0].detail["error"], "error[E0432]: unresolved import");
        assert_eq!(evs[0].detail["exit_code"], 101);
        // success with an unknown response shape: command_completed without an exit code, no test_passed guess
        let evs = events(
            json!({"hook_event_name": "PostToolUse", "session_id": "th1", "tool_name": "shell", "tool_input": {"command": "cargo test"}, "tool_response": "all good"}),
        );
        assert_eq!(
            evs.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(),
            vec!["command_completed"]
        );
        // exit 0 is a pass
        let evs = events(
            json!({"hook_event_name": "PostToolUse", "session_id": "th1", "tool_name": "shell", "tool_input": {"command": "cargo test"}, "tool_response": {"metadata": {"exit_code": 0}, "output": "ok"}}),
        );
        assert_eq!(
            evs.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(),
            vec!["command_completed", "test_passed"]
        );
    }

    #[test]
    fn lifecycle_hooks() {
        let kinds = |h: Value| {
            events(h)
                .iter()
                .map(|e| e.kind.as_str().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            kinds(
                json!({"hook_event_name": "SessionStart", "session_id": "t", "source": "startup"})
            ),
            vec!["session_started"]
        );
        assert_eq!(
            kinds(
                json!({"hook_event_name": "Stop", "session_id": "t", "last_assistant_message": "done."})
            ),
            vec!["turn_completed"]
        );
        assert_eq!(
            kinds(json!({"hook_event_name": "Interrupt", "session_id": "t"})),
            vec!["turn_interrupted"]
        );
        assert_eq!(
            kinds(json!({"hook_event_name": "SessionEnd", "session_id": "t", "reason": "exit"})),
            vec!["session_ended"]
        );
        assert_eq!(
            kinds(
                json!({"hook_event_name": "UserPromptSubmit", "session_id": "t", "prompt": "hi"})
            ),
            vec!["prompt_submitted"]
        );
        assert!(kinds(json!({"hook_event_name": "PermissionRequest", "session_id": "t", "tool_name": "shell", "tool_input": {}})).is_empty());
        assert!(kinds(json!({"hook_event_name": "PreCompact", "session_id": "t"})).is_empty());
        assert_eq!(
            kinds(json!({"hook_event_name": "Whatever", "session_id": "t"})),
            vec!["notification"]
        );
        let stop = &events(json!({"hook_event_name": "Stop", "session_id": "t"}))[0];
        assert_eq!(stop.detail["background_tasks"], 0);
        assert_eq!(stop.detail["session_crons"], 0);
    }

    #[test]
    fn permission_draft_never_offers_deny_and_stop_and_has_no_tool_use_id_dependency() {
        let env = env();
        let hook = json!({"hook_event_name": "PermissionRequest", "session_id": "th1", "turn_id": "tu1", "cwd": "/w", "permission_mode": "on-request",
            "tool_name": "shell", "tool_input": {"command": "rm -rf build"}});
        let d = permission_request_draft(&hook, &env).unwrap();
        assert_eq!(d.origin, SourceChannel::CodexHookCli);
        assert_eq!(d.available_decisions, vec![Decision::Allow, Decision::Deny]);
        assert!(!d.available_decisions.contains(&Decision::DenyAndStop));
        assert_eq!(d.session_key, "codex:th1");
        assert_eq!(d.binding.ids["turn_id"], "tu1");
        assert!(!d.binding.ids.contains_key("tool_use_id"));
        assert!(permission_request_draft(
            &json!({"hook_event_name": "Stop", "session_id": "t"}),
            &env
        )
        .is_err());
        assert_eq!(
            permission_dedupe_body(&hook),
            br#"{"command":"rm -rf build"}"#.to_vec()
        );
        assert_eq!(permission_dedupe_body(&json!({})), b"null".to_vec());
    }

    #[test]
    fn hostile_inputs_never_panic() {
        let env = env();
        let weird = [
            json!(null),
            json!(5),
            json!("x"),
            json!([1]),
            json!({"a": {"b": 1}}),
        ];
        for ev in [
            "SessionStart",
            "UserPromptSubmit",
            "PreToolUse",
            "PostToolUse",
            "PermissionRequest",
            "Stop",
            "Interrupt",
            "SessionEnd",
            "SubagentStart",
            "SubagentStop",
            "PostCompact",
            "PreCompact",
            "Zzz",
        ] {
            for tool in [
                "shell",
                "apply_patch",
                "mcp__a__b",
                "web_search",
                "",
                "weird",
            ] {
                for v in &weird {
                    let hook = json!({"hook_event_name": ev, "session_id": "s", "cwd": v, "tool_name": tool, "tool_input": v, "tool_response": v, "prompt": v, "source": v, "reason": v});
                    let _ = normalize(&hook, &env);
                    let _ = permission_request_draft(&hook, &env);
                    let _ = permission_dedupe_body(&hook);
                }
            }
        }
    }

    trait HeadlineForTest {
        fn headline_for_test(&self) -> &str;
    }
    impl HeadlineForTest for AgentEvent {
        fn headline_for_test(&self) -> &str {
            &self.summary.headline
        }
    }
}
