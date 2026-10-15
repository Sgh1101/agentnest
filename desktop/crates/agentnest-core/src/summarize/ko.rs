//! Korean summary templates (docs/protocol.md 7), golden file `protocol/fixtures/summaries_ko.json`.
//!
//! Everything here is a deterministic template: no model call, no I/O. The phone renders the strings as is.
//!
//! Rules (protocol.md 7, fixtures `_format.rules`):
//!
//! * tone: 해요체, progressive "~하고 있어요", results "~했어요";
//! * `headline <= 40`, `detail <= 200` characters: the template is filled first and the result is **clipped last**
//!   (`s[:n-1] + '…'`), so a long `{cmd60}` is cut a second time inside the headline;
//! * `{cmd60}`: strip leading `cd X &&` segments, then a leading `env` and `VAR=value` assignments, mask secrets with
//!   `***`, clip to 60;
//! * paths: basename (`{basename}`), path relative to the working directory (`{rel_path}`) or, outside it, the last two
//!   segments; URLs: host only, never path, query, fragment or credentials.
//!
//! Agent supplied strings (`description`, patterns, tool names) are sanitised (control and bidirectional characters
//! removed) and masked before they enter a template.

use agentnest_protocol::{AgentKind, CommandClass};
use serde_json::Value;

use crate::normalize::path;
use crate::redact::{
    clip, mask, mask_cmd_preview, mask_keep_long_tokens, mask_path, sanitize_display_text,
};
use crate::risk::classify::command_text;
use crate::risk::command_class::command_class_for;
use crate::risk::rules::apply_patch_changes;
use crate::risk::tokenizer::{is_assignment, Shell};

/// Maximum headline length in characters (protocol.md 5.1).
pub const HEADLINE_MAX: usize = 40;
/// Maximum detail length in characters (protocol.md 5.1).
pub const DETAIL_MAX: usize = 200;
/// Maximum length of the approval card title (not specified by the docs; keeps agent supplied tool names bounded).
pub const TITLE_MAX: usize = 60;

/// Title (approval card), headline and detail of a tool call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolSummary {
    /// Approval card title ("명령을 실행하려고 해요").
    pub title: String,
    /// Event / session headline, at most [`HEADLINE_MAX`] characters.
    pub headline: String,
    /// Optional detail, at most [`DETAIL_MAX`] characters.
    pub detail: Option<String>,
}

/// A tool observation to summarise.
#[derive(Clone, Debug)]
pub struct ToolObservation<'a> {
    /// Agent family (only used to pick tool-name dialects).
    pub agent_kind: AgentKind,
    /// Tool name (`Bash`, `Edit`, `mcp__github__create_issue`, Codex `commandExecution` / `fileChange`).
    pub tool_name: &'a str,
    /// Raw tool input (read only).
    pub tool_input: &'a Value,
    /// Session working directory; without it `{cwd_short}` and relative paths are unavailable.
    pub cwd: Option<&'a str>,
    /// Command class if the caller already computed it; derived from the command otherwise.
    pub command_class: Option<CommandClass>,
    /// Whether the target of a `Write` already exists (`None` = unknown, treated as "overwrite").
    pub file_exists: Option<bool>,
    /// `true` for a `PermissionRequest`: the headline gets the "허락을 기다리고 있어요: " prefix.
    pub permission_request: bool,
}

/// Summarises a tool call for approval cards (`title`, `purpose` is separate) and events (`headline`, `detail`).
pub fn summarize_tool(obs: &ToolObservation<'_>) -> ToolSummary {
    let (title, headline, detail) = raw_tool_summary(obs);
    let headline = if obs.permission_request {
        format!("허락을 기다리고 있어요: {headline}")
    } else {
        headline
    };
    ToolSummary {
        title: clip(&sanitize_display_text(&title), TITLE_MAX),
        headline: clip(&headline, HEADLINE_MAX),
        detail: detail
            .map(|d| clip(&d, DETAIL_MAX))
            .filter(|d| !d.trim().is_empty()),
    }
}

fn raw_tool_summary(obs: &ToolObservation<'_>) -> (String, String, Option<String>) {
    let ti = obs.tool_input;
    let name = obs.tool_name;
    let lower = name.to_lowercase();
    if let Some(rest) = lower.strip_prefix("mcp__") {
        // keep the original case of server and tool
        let original_rest = &name[name.len() - rest.len()..];
        let (srv, tool) = match original_rest.split_once("__") {
            Some((s, t)) => (s, t),
            None => (original_rest, ""),
        };
        let srv = safe_name(srv);
        let tool = safe_name(tool);
        let headline = if tool.is_empty() {
            format!("{srv} 도구를 쓰고 있어요")
        } else {
            format!("{srv}의 {tool}을(를) 쓰고 있어요")
        };
        return (format!("{srv} 도구를 쓰려고 해요"), headline, None);
    }
    match lower.as_str() {
        "bash" | "powershell" | "commandexecution" | "shell" | "local_shell" | "exec_command" => {
            let shell = if lower == "powershell" {
                Shell::PowerShell
            } else {
                Shell::Posix
            };
            command_summary(obs, shell)
        }
        "edit" | "multiedit" | "notebookedit" => {
            let p = tool_path(ti).unwrap_or_default();
            let desc = description(ti);
            let mut detail = format!("{} 의 일부를 바꿉니다.", rel_path(&p, obs.cwd));
            if let Some(d) = desc {
                detail.push(' ');
                detail.push_str(&d);
            }
            (
                "파일을 고치려고 해요".to_owned(),
                format!("{} 파일을 고치고 있어요", basename_of(&p)),
                Some(detail),
            )
        }
        "write" => {
            let p = tool_path(ti).unwrap_or_default();
            let base = basename_of(&p);
            if obs.file_exists == Some(false) {
                let detail = match ti.get("content").and_then(Value::as_str) {
                    Some(c) => format!("{} ({}줄)", rel_path(&p, obs.cwd), c.lines().count()),
                    None => rel_path(&p, obs.cwd),
                };
                (
                    "새 파일을 만들려고 해요".to_owned(),
                    format!("{base} 파일을 새로 만들고 있어요"),
                    Some(detail),
                )
            } else {
                (
                    "파일을 다시 쓰려고 해요".to_owned(),
                    format!("{base} 파일을 다시 쓰고 있어요"),
                    None,
                )
            }
        }
        "read" | "ls" | "notebookread" => {
            let p = tool_path(ti).unwrap_or_default();
            (
                "파일을 읽으려고 해요".to_owned(),
                format!("{} 파일을 읽고 있어요", basename_of(&p)),
                None,
            )
        }
        "grep" | "glob" => {
            let pattern = ti
                .get("pattern")
                .and_then(Value::as_str)
                .map(|s| sanitize_display_text(&mask(s).text));
            let headline = match pattern {
                Some(p) if !p.is_empty() => format!("'{p}'을(를) 찾고 있어요"),
                _ => "파일을 찾고 있어요".to_owned(),
            };
            ("파일을 읽으려고 해요".to_owned(), headline, None)
        }
        "webfetch" => {
            let host = ti
                .get("url")
                .and_then(Value::as_str)
                .and_then(url_host)
                .unwrap_or_else(|| "알 수 없는 주소".to_owned());
            (
                "웹에 접속하려고 해요".to_owned(),
                format!("{host} 에서 자료를 가져오고 있어요"),
                None,
            )
        }
        "websearch" | "web_search" => {
            // Not in the template table: reading "'{query}'을(를) 웹에서 찾고 있어요".
            let query = ti
                .get("query")
                .and_then(Value::as_str)
                .map(|s| sanitize_display_text(&mask(s).text))
                .unwrap_or_default();
            let headline = if query.is_empty() {
                "웹에서 자료를 찾고 있어요".to_owned()
            } else {
                format!("웹에서 '{query}'을(를) 찾고 있어요")
            };
            ("웹에 접속하려고 해요".to_owned(), headline, None)
        }
        "agent" | "task" => {
            let d = ti
                .get("description")
                .and_then(Value::as_str)
                .map(|s| clip(&sanitize_display_text(&mask(s).text), 60))
                .filter(|s| !s.is_empty());
            let headline = match d {
                Some(d) => format!("보조 에이전트에게 맡겼어요: {d}"),
                None => "보조 에이전트에게 맡겼어요".to_owned(),
            };
            ("보조 에이전트를 실행하려고 해요".to_owned(), headline, None)
        }
        "filechange" => {
            let changes: Vec<(String, String)> = ti
                .get("changes")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|c| {
                            let p = c.get("path").and_then(Value::as_str)?.to_owned();
                            let kind = c
                                .get("kind")
                                .and_then(|k| {
                                    k.as_str().or_else(|| k.get("type").and_then(Value::as_str))
                                })
                                .unwrap_or("update")
                                .to_owned();
                            Some((p, kind))
                        })
                        .collect()
                })
                .unwrap_or_default();
            file_change_summary(&changes)
        }
        // UNVERIFIED (Phase 0 C10): the Codex hooks patch tool name.
        "apply_patch" => {
            let changes: Vec<(String, String)> = apply_patch_changes(ti)
                .into_iter()
                .map(|(p, k)| (p, k.to_owned()))
                .collect();
            file_change_summary(&changes)
        }
        _ => {
            let t = safe_name(name);
            (
                format!("{t} 도구를 쓰려고 해요"),
                format!("{t} 도구를 쓰고 있어요"),
                None,
            )
        }
    }
}

fn file_change_summary(changes: &[(String, String)]) -> (String, String, Option<String>) {
    let n = changes.len();
    let title = format!("파일 {n}개를 바꾸려고 해요");
    let first = changes
        .first()
        .map(|(p, _)| basename_of(p))
        .unwrap_or_default();
    // n == 1 is not covered by the doc table: the single-file headline is reused.
    let headline = if n > 1 {
        format!("{first} 외 {}개 파일을 고치고 있어요", n - 1)
    } else {
        format!("{first} 파일을 고치고 있어요")
    };
    let count = |kinds: &[&str]| {
        changes
            .iter()
            .filter(|(_, k)| kinds.contains(&k.as_str()))
            .count()
    };
    let add = count(&["add", "create"]);
    let del = count(&["delete", "remove"]);
    let upd = n - add - del;
    let mut parts = Vec::new();
    if upd > 0 {
        parts.push(format!("수정 {upd}개"));
    }
    if add > 0 {
        parts.push(format!("새 파일 {add}개"));
    }
    if del > 0 {
        parts.push(format!("삭제 {del}개"));
    }
    let detail = if parts.is_empty() {
        None
    } else {
        Some(parts.join(" · "))
    };
    (title, headline, detail)
}

fn command_summary(obs: &ToolObservation<'_>, shell: Shell) -> (String, String, Option<String>) {
    let command = command_text(obs.tool_input);
    let class = obs
        .command_class
        .clone()
        .unwrap_or_else(|| command_class_for(&command, shell));
    let cmd_full = collapse_ws(&mask_cmd_preview(&strip_leading_noise(&command)).text);
    let cmd60 = clip(&cmd_full, 60);
    let desc = description(obs.tool_input);
    match class {
        CommandClass::Test => {
            let detail = match desc {
                Some(d) => Some(if d.ends_with('.') { d } else { format!("{d}.") }),
                None => obs
                    .cwd
                    .map(|c| format!("{} 에서 {cmd_full}", basename_of(c))),
            };
            (
                "테스트를 실행하려고 해요".to_owned(),
                format!("테스트를 돌리고 있어요 ({cmd60})"),
                detail,
            )
        }
        CommandClass::Build => (
            "빌드를 실행하려고 해요".to_owned(),
            format!("빌드하고 있어요 ({cmd60})"),
            desc,
        ),
        _ => (
            "명령을 실행하려고 해요".to_owned(),
            format!("명령을 실행하고 있어요: {cmd60}"),
            desc,
        ),
    }
}

fn description(ti: &Value) -> Option<String> {
    let d = ti.get("description").and_then(Value::as_str)?;
    let d = sanitize_display_text(&mask(d).text);
    (!d.is_empty()).then_some(d)
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn safe_name(s: &str) -> String {
    clip(&sanitize_display_text(&mask(s).text), 30)
}

fn tool_path(ti: &Value) -> Option<String> {
    ["file_path", "notebook_path", "path"]
        .iter()
        .find_map(|k| ti.get(*k).and_then(Value::as_str))
        .map(|s| mask_path(s).text)
}

fn basename_of(p: &str) -> String {
    sanitize_display_text(path::basename(p))
}

/// `{rel_path}`: relative to `cwd` (case-insensitive prefix, `/` separators), outside it the last two segments.
fn rel_path(p: &str, cwd: Option<&str>) -> String {
    if let Some(cwd) = cwd {
        let root = path::resolve(cwd, None);
        let full = path::resolve(p, Some(cwd));
        if let Some(rel) = path::relative_to(&full, &root) {
            return sanitize_display_text(&rel);
        }
    }
    sanitize_display_text(&path::last_segments(p, 2).join("/"))
}

/// The host of a URL: no scheme, credentials, port, path, query or fragment.
pub fn url_host(url: &str) -> Option<String> {
    let rest = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => url,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or("");
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        // IPv6 literal
        stripped.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    let host = sanitize_display_text(host);
    (!host.is_empty() && host.len() <= 253).then_some(host)
}

/// Removes leading `cd X &&` segments, then a leading `env` keyword and `VAR=value` assignments (`{cmd60}` step 1).
/// If nothing is left the original command is returned.
pub fn strip_leading_noise(command: &str) -> String {
    let mut rest = command.trim_start();
    // cd segments
    loop {
        let (word, end) = read_word(rest);
        if !matches!(
            word.to_lowercase().as_str(),
            "cd" | "pushd" | "set-location"
        ) {
            break;
        }
        match find_separator(&rest[end..]) {
            Some(after) => rest = rest[end..][after..].trim_start(),
            None => break,
        }
    }
    // env and assignments
    loop {
        let (word, end) = read_word(rest);
        if word.is_empty() {
            break;
        }
        if word.eq_ignore_ascii_case("env") || is_assignment(&word) {
            rest = rest[end..].trim_start();
        } else {
            break;
        }
    }
    let out = rest.trim();
    if out.is_empty() {
        command.trim().to_owned()
    } else {
        out.to_owned()
    }
}

/// Reads one shell word (quotes respected, removed from the returned text) and returns it with the byte index just
/// after it.
fn read_word(s: &str) -> (String, usize) {
    let mut word = String::new();
    let mut quote: Option<char> = None;
    let mut end = s.len();
    for (i, c) in s.char_indices() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    word.push(c);
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                } else if c.is_whitespace() {
                    end = i;
                    break;
                } else {
                    word.push(c);
                }
            }
        }
    }
    (word, end)
}

/// The byte index just after the first unquoted `&&` or `;`, if any.
fn find_separator(s: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    let bytes: Vec<(usize, char)> = s.char_indices().collect();
    let mut idx = 0;
    while idx < bytes.len() {
        let (i, c) = bytes[idx];
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                } else if c == ';' {
                    return Some(i + 1);
                } else if c == '&' && bytes.get(idx + 1).map(|(_, n)| *n) == Some('&') {
                    return Some(i + 2);
                }
            }
        }
        idx += 1;
    }
    None
}

// ---------------------------------------------------------------------------------------------------------------------
// Non-tool rows of the template table
// ---------------------------------------------------------------------------------------------------------------------

/// The first sentence of `text` (up to and including the first `.`, `!`, `?` or `。` that is followed by whitespace or
/// the end, on the first line only), clipped to `max` characters.
pub fn first_sentence(text: &str, max: usize) -> String {
    let line = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    let chars: Vec<char> = line.chars().collect();
    let mut end = chars.len();
    for (i, c) in chars.iter().enumerate() {
        if matches!(c, '.' | '!' | '?' | '。') && chars.get(i + 1).is_none_or(|n| n.is_whitespace())
        {
            end = i + 1;
            break;
        }
    }
    let sentence: String = chars[..end].iter().collect();
    clip(
        &sanitize_display_text(&mask_keep_long_tokens(&sentence).text),
        max,
    )
}

/// `Stop` summary: `(headline, detail)` (protocol.md 7: "이번 작업을 마쳤어요" / "백그라운드 작업 N개를 기다리고 있어요").
pub fn stop_summary(
    background_tasks: usize,
    last_assistant_message: Option<&str>,
) -> (String, Option<String>) {
    if background_tasks > 0 {
        return (
            clip(
                &format!("백그라운드 작업 {background_tasks}개를 기다리고 있어요"),
                HEADLINE_MAX,
            ),
            None,
        );
    }
    let detail = last_assistant_message
        .map(|m| first_sentence(m, 120))
        .filter(|d| !d.is_empty())
        .map(|d| clip(&d, DETAIL_MAX));
    ("이번 작업을 마쳤어요".to_owned(), detail)
}

/// The exit code of a Claude Code Bash error text (`Exit code 101\n...`).
pub fn parse_exit_code(error: &str) -> Option<i64> {
    let first = error.lines().next()?.trim();
    let rest = first.strip_prefix("Exit code ")?;
    rest.split_whitespace().next()?.parse().ok()
}

/// `PostToolUseFailure` summary: `(headline, detail)`. Shell tools say "명령이 실패했어요 (exit N)".
pub fn post_tool_failure_summary(
    tool_name: &str,
    error: &str,
    is_interrupt: bool,
) -> (String, Option<String>) {
    let first_line = error
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    let detail =
        Some(clip(&sanitize_display_text(&mask(first_line).text), 160)).filter(|d| !d.is_empty());
    let is_shell = matches!(tool_name.to_lowercase().as_str(), "bash" | "powershell");
    let headline = if is_interrupt {
        if is_shell {
            "명령이 중단됐어요".to_owned()
        } else {
            clip(
                &format!("{} 도구가 중단됐어요", safe_name(tool_name)),
                HEADLINE_MAX,
            )
        }
    } else if is_shell {
        match parse_exit_code(error) {
            Some(code) => format!("명령이 실패했어요 (exit {code})"),
            None => "명령이 실패했어요".to_owned(),
        }
    } else {
        clip(
            &format!("{} 도구가 실패했어요", safe_name(tool_name)),
            HEADLINE_MAX,
        )
    };
    (headline, detail)
}

/// `StopFailure` headline by error type (12 types; protocol.md 7 gives only `rate_limit`, the others are written in the
/// same tone).
pub fn stop_failure_headline(error: &str) -> String {
    match error {
        "rate_limit" => "사용량 한도에 걸려 멈췄어요",
        "overloaded" => "서버가 혼잡해서 멈췄어요",
        "authentication_failed" => "로그인 인증에 실패해서 멈췄어요",
        "oauth_org_not_allowed" => "이 조직은 사용할 수 없어서 멈췄어요",
        "account_on_hold" => "계정이 보류 상태라 멈췄어요",
        "billing_error" => "결제 문제로 멈췄어요",
        "invalid_request" => "잘못된 요청 때문에 멈췄어요",
        "model_not_found" => "모델을 찾을 수 없어서 멈췄어요",
        "server_error" => "서버 오류로 멈췄어요",
        "max_output_tokens" => "답변 길이 한도에 걸려 멈췄어요",
        "cloud_credential_error" => "클라우드 인증 문제로 멈췄어요",
        _ => "오류로 멈췄어요", // `unknown` and anything newer
    }
    .to_owned()
}

/// Codex `enteredReviewMode`.
pub fn review_started_headline() -> String {
    "코드 리뷰를 시작했어요".to_owned()
}

/// Codex `exitedReviewMode`: `(headline, detail)` with the first sentence of the overall text.
pub fn review_completed_summary(
    p0: u32,
    p1: u32,
    overall: Option<&str>,
) -> (String, Option<String>) {
    let headline = clip(
        &format!("리뷰를 마쳤어요 · P0 {p0} · P1 {p1}"),
        HEADLINE_MAX,
    );
    let detail = overall
        .map(|o| first_sentence(o, 120))
        .filter(|d| !d.is_empty());
    (headline, detail)
}

// -- headlines for the remaining event kinds (not part of the golden file) ---------------------------------------------

/// `session_started`.
pub fn session_started_headline(source_reason: &str) -> String {
    match source_reason {
        "resume" => "세션을 이어서 시작했어요",
        "clear" => "대화를 비우고 새로 시작했어요",
        "compact" => "대화를 정리하고 이어가요",
        "fork" => "세션을 갈라서 시작했어요",
        _ => "세션을 시작했어요",
    }
    .to_owned()
}

/// `session_ended`.
pub fn session_ended_headline() -> String {
    "세션을 마쳤어요".to_owned()
}

/// `prompt_submitted`: `(headline, detail)` where the detail is the (already masked) prompt preview.
pub fn prompt_submitted_summary(prompt_preview: &str) -> (String, Option<String>) {
    let detail = clip(&sanitize_display_text(prompt_preview), DETAIL_MAX);
    (
        "새 지시를 받았어요".to_owned(),
        Some(detail).filter(|d| !d.is_empty()),
    )
}

/// `tool_completed`.
pub fn tool_completed_headline(tool_name: &str) -> String {
    clip(
        &format!("{} 도구를 마쳤어요", safe_name(tool_name)),
        HEADLINE_MAX,
    )
}

/// `command_completed` / `test_passed` / `test_failed`.
pub fn command_completed_headline(class: &CommandClass, exit_code: Option<i64>) -> String {
    match (class, exit_code) {
        (CommandClass::Test, Some(0) | None) => "테스트를 모두 통과했어요".to_owned(),
        (CommandClass::Test, Some(c)) => format!("테스트가 실패했어요 (exit {c})"),
        (_, Some(0) | None) => "명령을 마쳤어요".to_owned(),
        (_, Some(c)) => format!("명령이 끝났어요 (exit {c})"),
    }
}

/// `file_modified` (`op` = create / update / delete / edit).
pub fn file_modified_headline(path_text: &str, op: &str) -> String {
    let base = basename_of(path_text);
    let text = match op {
        "create" => format!("{base} 파일을 새로 만들었어요"),
        "delete" => format!("{base} 파일을 지웠어요"),
        _ => format!("{base} 파일을 고쳤어요"),
    };
    clip(&text, HEADLINE_MAX)
}

/// `subagent_started` / `subagent_stopped`.
pub fn subagent_headline(started: bool, agent_type: &str) -> String {
    let t = safe_name(agent_type);
    let text = match (started, t.is_empty()) {
        (true, true) => "보조 에이전트가 일을 시작했어요".to_owned(),
        (false, true) => "보조 에이전트가 일을 마쳤어요".to_owned(),
        (true, false) => format!("보조 에이전트({t})가 일을 시작했어요"),
        (false, false) => format!("보조 에이전트({t})가 일을 마쳤어요"),
    };
    clip(&text, HEADLINE_MAX)
}

/// `task_created` / `task_completed`.
pub fn task_headline(created: bool, subject: &str) -> String {
    let s = clip(&sanitize_display_text(&mask(subject).text), 24);
    let text = match (created, s.is_empty()) {
        (true, true) => "할 일이 추가됐어요".to_owned(),
        (false, true) => "할 일을 마쳤어요".to_owned(),
        (true, false) => format!("할 일이 추가됐어요: {s}"),
        (false, false) => format!("할 일을 마쳤어요: {s}"),
    };
    clip(&text, HEADLINE_MAX)
}

/// `turn_interrupted` (Codex `Interrupt` hook).
pub fn turn_interrupted_headline() -> String {
    "작업이 중단됐어요".to_owned()
}

/// `context_compacted`.
pub fn context_compacted_headline() -> String {
    "대화를 요약해서 정리했어요".to_owned()
}

/// `permission_denied_auto`.
pub fn permission_denied_headline(tool_name: &str) -> String {
    clip(
        &format!("{} 사용이 자동으로 거부됐어요", safe_name(tool_name)),
        HEADLINE_MAX,
    )
}

/// `notification` by `notification_type`.
pub fn notification_headline(notification_type: &str) -> String {
    match notification_type {
        "permission_prompt" => "권한 확인을 기다리고 있어요",
        "idle_prompt" => "입력을 기다리고 있어요",
        "agent_needs_input" => "입력이 필요해요",
        "agent_completed" => "백그라운드 작업이 끝났어요",
        t if t.starts_with("unknown_hook:") => "알 수 없는 훅 이벤트가 왔어요",
        _ => "알림이 왔어요",
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DEFAULT_CWD: &str = "C:\\dev\\agentnest";

    fn fixture() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../protocol/fixtures/summaries_ko.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn class_of_name(name: &str) -> CommandClass {
        CommandClass::from_wire(name)
    }

    #[test]
    fn tool_cases_golden() {
        let f = fixture();
        let cases = f["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 32);
        let mut failures = Vec::new();
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let input = &c["input"];
            let agent = if input["agent"] == "codex" {
                AgentKind::Codex
            } else {
                AgentKind::ClaudeCode
            };
            // The fixture file does not say it, but cases without `cwd` expect "agentnest" (basename of the default
            // working directory C:\dev\agentnest).
            let cwd = input
                .get("cwd")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_CWD);
            let obs = ToolObservation {
                agent_kind: agent,
                tool_name: input["tool_name"].as_str().unwrap(),
                tool_input: &input["tool_input"],
                cwd: Some(cwd),
                command_class: input
                    .get("command_class")
                    .and_then(Value::as_str)
                    .map(class_of_name),
                file_exists: input.get("file_exists").and_then(Value::as_bool),
                permission_request: input.get("hook").and_then(Value::as_str)
                    == Some("PermissionRequest"),
            };
            let got = summarize_tool(&obs);
            let expect = &c["expect"];
            let mut ok = got.title == expect["title"].as_str().unwrap()
                && got.headline == expect["headline"].as_str().unwrap();
            ok &= match expect.get("detail").and_then(Value::as_str) {
                Some(d) => got.detail.as_deref() == Some(d),
                None => got.detail.is_none(),
            };
            ok &= got.headline.chars().count() <= HEADLINE_MAX;
            ok &= got
                .detail
                .as_ref()
                .is_none_or(|d| d.chars().count() <= DETAIL_MAX);
            if !ok {
                failures.push(format!("{name}: got {got:?}\n   want {expect}"));
            }
        }
        assert!(
            failures.is_empty(),
            "{} failing summary cases:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    #[test]
    fn event_cases_golden() {
        let f = fixture();
        let cases = f["event_cases"].as_array().unwrap();
        assert_eq!(cases.len(), 7);
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let input = &c["input"];
            let (headline, detail) = match (
                input.get("hook").and_then(Value::as_str),
                input.get("item").and_then(Value::as_str),
            ) {
                (Some("Stop"), _) => stop_summary(
                    input["background_tasks"].as_u64().unwrap() as usize,
                    input.get("last_assistant_message").and_then(Value::as_str),
                ),
                (Some("PostToolUseFailure"), _) => post_tool_failure_summary(
                    input["tool_name"].as_str().unwrap(),
                    input["error"].as_str().unwrap(),
                    false,
                ),
                (Some("StopFailure"), _) => (
                    stop_failure_headline(input["error"].as_str().unwrap()),
                    None,
                ),
                (_, Some("enteredReviewMode")) => (review_started_headline(), None),
                (_, Some("exitedReviewMode")) => review_completed_summary(
                    input["p0"].as_u64().unwrap() as u32,
                    input["p1"].as_u64().unwrap() as u32,
                    input.get("overall").and_then(Value::as_str),
                ),
                other => panic!("unhandled event case {name}: {other:?}"),
            };
            let expect = &c["expect"];
            assert_eq!(headline, expect["headline"].as_str().unwrap(), "{name}");
            match expect.get("detail").and_then(Value::as_str) {
                Some(d) => assert_eq!(detail.as_deref(), Some(d), "{name}"),
                None => assert!(detail.is_none(), "{name}: unexpected detail {detail:?}"),
            }
            assert!(headline.chars().count() <= HEADLINE_MAX);
        }
    }

    #[test]
    fn every_stop_failure_type_fits_the_headline() {
        for t in [
            "rate_limit",
            "overloaded",
            "authentication_failed",
            "oauth_org_not_allowed",
            "account_on_hold",
            "billing_error",
            "invalid_request",
            "model_not_found",
            "server_error",
            "max_output_tokens",
            "cloud_credential_error",
            "unknown",
            "something_new",
        ] {
            let h = stop_failure_headline(t);
            assert!(!h.is_empty() && h.chars().count() <= HEADLINE_MAX, "{t}");
            assert!(h.ends_with("요"), "{t}");
        }
    }

    #[test]
    fn strip_noise_cases() {
        assert_eq!(
            strip_leading_noise("cd a && cd \"b c\" && env CI=1 NODE_ENV=test cargo build"),
            "cargo build"
        );
        assert_eq!(
            strip_leading_noise("CI=1 RUST_LOG=debug cargo test"),
            "cargo test"
        );
        assert_eq!(strip_leading_noise("cd x"), "cd x");
        assert_eq!(strip_leading_noise("cd x; ls -la"), "ls -la");
        assert_eq!(strip_leading_noise("echo \"a && b\""), "echo \"a && b\"");
        assert_eq!(strip_leading_noise("env"), "env");
        assert_eq!(strip_leading_noise(""), "");
        assert_eq!(strip_leading_noise("FOO=\"a b\" run"), "run");
    }

    #[test]
    fn host_extraction_drops_everything_but_the_host() {
        assert_eq!(
            url_host("https://docs.rs/serde/latest/serde/?token=abc123#derive").as_deref(),
            Some("docs.rs")
        );
        assert_eq!(
            url_host("https://user:pass@example.com:8443/x").as_deref(),
            Some("example.com")
        );
        assert_eq!(url_host("http://[::1]:3000/x").as_deref(), Some("::1"));
        assert_eq!(url_host("example.org/path").as_deref(), Some("example.org"));
        assert_eq!(url_host(""), None);
        assert_eq!(url_host("https:///x"), None);
    }

    #[test]
    fn sentences() {
        assert_eq!(first_sentence("Done. Next.", 120), "Done.");
        assert_eq!(first_sentence("v1.2 released! more", 120), "v1.2 released!");
        assert_eq!(first_sentence("no terminator", 120), "no terminator");
        assert_eq!(
            first_sentence("\n\nfirst line only. second\nthird.", 120),
            "first line only."
        );
        assert_eq!(first_sentence("", 120), "");
        assert_eq!(first_sentence("끝났어요。 다음", 120), "끝났어요。");
    }

    #[test]
    fn agent_text_is_sanitised_and_masked() {
        let ti = json!({"command": "ls", "description": "do it\u{202e}\nnow password=hunter2"});
        let s = summarize_tool(&ToolObservation {
            agent_kind: AgentKind::ClaudeCode,
            tool_name: "Bash",
            tool_input: &ti,
            cwd: None,
            command_class: None,
            file_exists: None,
            permission_request: false,
        });
        assert_eq!(s.detail.as_deref(), Some("do it now <redacted>"));
        // a tool name with control characters cannot break the title
        let s = summarize_tool(&ToolObservation {
            agent_kind: AgentKind::ClaudeCode,
            tool_name: "Evil\n\u{202e}Tool",
            tool_input: &json!({}),
            cwd: None,
            command_class: None,
            file_exists: None,
            permission_request: false,
        });
        assert_eq!(s.title, "Evil Tool 도구를 쓰려고 해요");
    }

    #[test]
    fn missing_inputs_do_not_panic() {
        for tool in [
            "Bash",
            "Edit",
            "Write",
            "Read",
            "Grep",
            "WebFetch",
            "WebSearch",
            "Agent",
            "fileChange",
            "apply_patch",
            "mcp__x",
            "",
            "Unknown",
        ] {
            for ti in [
                json!(null),
                json!({}),
                json!({"command": 5}),
                json!({"changes": 3}),
                json!([1, 2]),
            ] {
                let s = summarize_tool(&ToolObservation {
                    agent_kind: AgentKind::Codex,
                    tool_name: tool,
                    tool_input: &ti,
                    cwd: None,
                    command_class: None,
                    file_exists: None,
                    permission_request: true,
                });
                assert!(s.headline.chars().count() <= HEADLINE_MAX);
                assert!(!s.title.is_empty());
            }
        }
    }

    #[test]
    fn other_headlines_respect_the_limits() {
        let long = "x".repeat(300);
        for h in [
            session_started_headline("resume"),
            session_ended_headline(),
            tool_completed_headline(&long),
            command_completed_headline(&CommandClass::Test, Some(1)),
            file_modified_headline(&format!("C:\\a\\{long}.rs"), "create"),
            subagent_headline(true, &long),
            task_headline(false, &long),
            context_compacted_headline(),
            permission_denied_headline(&long),
            notification_headline("idle_prompt"),
            post_tool_failure_summary(&long, "boom", true).0,
        ] {
            assert!(h.chars().count() <= HEADLINE_MAX, "{h}");
        }
        assert_eq!(
            post_tool_failure_summary("Bash", "no exit code here", false).0,
            "명령이 실패했어요"
        );
        assert_eq!(parse_exit_code("Exit code 2\nboom"), Some(2));
        assert_eq!(parse_exit_code("nope"), None);
    }
}
