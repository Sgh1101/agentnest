//! The shared post-processing every adapter runs before an event leaves its normaliser (architecture.md 5.1 step 4):
//! project resolution, path shortening, secret masking and bounds, summary clipping, ids and timestamps.
//!
//! Adapters describe an event as an [`EventDraft`] with *raw* detail values (a full prompt, a long command, the tail of
//! stdout). [`build_event`] is the only way (by convention and by code review) from a draft to an [`AgentEvent`]; it
//! masks first and cuts afterwards, so nothing unmasked and nothing oversized can reach the store or the phone.

use std::collections::BTreeMap;

use agentnest_protocol::{
    Actor, AgentEvent, AgentKind, AgentState, EventCategory, EventKind, EventSource, EventSummary,
    Severity, SourceChannel,
};
use serde_json::{Map, Value};

use super::path;
use super::NormalizeEnv;
use crate::redact::{bound_detail, clip, mask, sanitize_display_text};
use crate::state::timers::format_ms;
use crate::summarize::ko::{DETAIL_MAX, HEADLINE_MAX};

/// Maximum number of `native_ids` entries and their value length (schema: <= 16 entries, <= 256 chars).
const NATIVE_IDS_MAX: usize = 16;
const NATIVE_ID_VALUE_MAX: usize = 256;

/// An event as an adapter sees it: raw values, nothing masked or bounded yet.
#[derive(Clone, Debug)]
pub struct EventDraft {
    /// Agent family.
    pub agent_kind: AgentKind,
    /// Native session id (`session_id`, Codex `thread.id`); the session key is `<agent_kind>:<id>`.
    pub native_session_id: String,
    /// Event kind.
    pub kind: EventKind,
    /// Severity; use [`default_severity`] unless the adapter knows better.
    pub severity: Severity,
    /// Suggested state (reducer input).
    pub state_hint: Option<AgentState>,
    /// Korean headline (clipped to 40 characters).
    pub headline: String,
    /// Korean detail text (clipped to 200 characters).
    pub summary_detail: Option<String>,
    /// Kind specific detail object with **raw** values. Keys `file_path`, `notebook_path` and `cwd_hint` are shortened
    /// to path hints; every string is masked and bounded.
    pub detail: Map<String, Value>,
    /// Sub-agent context.
    pub actor: Option<Actor>,
    /// Raw working directory, used for project resolution. Never stored in the event.
    pub cwd: Option<String>,
    /// Collection channel.
    pub channel: SourceChannel,
    /// Native event name (`PreToolUse`, ...).
    pub native_event: Option<String>,
    /// Native identifiers (`tool_use_id`, `prompt_id`, `session_id`, ...).
    pub native_ids: BTreeMap<String, String>,
}

impl EventDraft {
    /// A draft with empty detail and the default severity of `kind`.
    pub fn new(
        agent_kind: AgentKind,
        native_session_id: impl Into<String>,
        kind: EventKind,
        channel: SourceChannel,
        native_event: &str,
    ) -> Self {
        let severity = default_severity(&kind);
        Self {
            agent_kind,
            native_session_id: native_session_id.into(),
            kind,
            severity,
            state_hint: None,
            headline: String::new(),
            summary_detail: None,
            detail: Map::new(),
            actor: None,
            cwd: None,
            channel,
            native_event: Some(native_event.to_owned()),
            native_ids: BTreeMap::new(),
        }
    }
}

/// The default severity of an event kind.
pub fn default_severity(kind: &EventKind) -> Severity {
    match kind {
        EventKind::TurnFailed | EventKind::AgentError => Severity::Error,
        EventKind::ToolFailed | EventKind::CommandFailed | EventKind::TestFailed => {
            Severity::Warning
        }
        EventKind::PermissionDeniedAuto | EventKind::ApprovalRequested => Severity::Notice,
        EventKind::TokenUsageUpdated => Severity::Debug,
        _ => Severity::Info,
    }
}

/// Turns a draft into a finished event: `seq` stays `None` (the stream assigns it).
pub fn build_event(draft: EventDraft, env: &NormalizeEnv) -> AgentEvent {
    let mut redacted = false;

    let project = draft
        .cwd
        .as_deref()
        .filter(|c| !c.is_empty())
        .map(|c| env.projects.resolve(c));

    // detail: path hints first (they are substrings of the raw path), then masking and bounds
    let mut detail = Value::Object(draft.detail);
    if let Value::Object(map) = &mut detail {
        for key in ["file_path", "notebook_path", "cwd_hint"] {
            if let Some(Value::String(s)) = map.get_mut(key) {
                *s = path::path_hint(s);
            }
        }
    }
    let (detail_redacted, _truncated) = bound_detail(&mut detail);
    redacted |= detail_redacted;

    // summary
    let headline = {
        let m = mask(&sanitize_display_text(&draft.headline));
        redacted |= m.redacted;
        let h = clip(&m.text, HEADLINE_MAX);
        if h.is_empty() {
            "이벤트가 있어요".to_owned()
        } else {
            h
        }
    };
    let summary_detail = draft.summary_detail.and_then(|d| {
        let m = mask(&sanitize_display_text(&d));
        redacted |= m.redacted;
        let t = clip(&m.text, DETAIL_MAX);
        (!t.is_empty()).then_some(t)
    });

    // native ids
    let mut native_ids = BTreeMap::new();
    for (k, v) in draft.native_ids {
        if native_ids.len() >= NATIVE_IDS_MAX {
            break;
        }
        if v.is_empty() {
            continue;
        }
        native_ids.insert(clip(&k, 64), clip(&v, NATIVE_ID_VALUE_MAX));
    }

    let actor = draft.actor.map(|a| Actor {
        agent_id: a.agent_id.map(|s| clip(&s, 128)).filter(|s| !s.is_empty()),
        agent_type: a.agent_type.map(|s| clip(&s, 64)).filter(|s| !s.is_empty()),
        is_subagent: a.is_subagent,
    });

    let category = draft.kind.category().unwrap_or(EventCategory::Notification);
    AgentEvent {
        event_id: env.ids.next_event_id(),
        seq: None,
        ts: format_ms(env.clock.now_ms()),
        agent_kind: draft.agent_kind,
        session_key: format!(
            "{}:{}",
            draft.agent_kind.as_str(),
            clip(&draft.native_session_id, 128)
        ),
        actor,
        project,
        kind: draft.kind,
        category,
        severity: draft.severity,
        summary: EventSummary {
            headline,
            detail: summary_detail,
        },
        state_hint: draft.state_hint,
        detail,
        source: EventSource {
            channel: draft.channel,
            native_event: draft.native_event,
            native_ids,
        },
        redacted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::path::basename;
    use serde_json::json;

    fn draft(kind: EventKind) -> EventDraft {
        EventDraft::new(
            AgentKind::ClaudeCode,
            "sess-1",
            kind,
            SourceChannel::ClaudeCodeHookHttp,
            "PreToolUse",
        )
    }

    #[test]
    fn masks_bounds_and_shortens() {
        let env = NormalizeEnv::for_test();
        let mut d = draft(EventKind::CommandStarted);
        d.headline = "명령을 실행하고 있어요: echo token=abc123".to_owned();
        d.detail = json!({
            "command": format!("echo password=hunter2 {}", "x ".repeat(2000)),
            "cwd_hint": "C:\\dev\\agentnest\\apps\\desktop",
            "file_path": "C:\\dev\\agentnest\\src\\pairing.rs",
            "command_class": "shell",
        })
        .as_object()
        .cloned()
        .unwrap();
        d.cwd = Some("C:\\dev\\agentnest".to_owned());
        d.native_ids
            .insert("tool_use_id".to_owned(), "toolu_1".to_owned());
        d.native_ids.insert("empty".to_owned(), String::new());
        let e = build_event(d, &env);
        assert!(e.redacted);
        assert!(e.seq.is_none());
        let cmd = e.detail["command"].as_str().unwrap();
        assert!(cmd.chars().count() <= 2000);
        assert!(cmd.starts_with("echo <redacted> "));
        assert_eq!(e.detail["cwd_hint"], "…\\apps\\desktop");
        assert_eq!(e.detail["file_path"], "…\\src\\pairing.rs");
        assert!(e.summary.headline.chars().count() <= 40);
        assert!(!e.summary.headline.contains("abc123"));
        assert_eq!(e.session_key, "claude_code:sess-1");
        assert_eq!(e.category, EventCategory::Command);
        assert_eq!(e.source.native_ids.len(), 1);
        assert_eq!(
            e.project.as_ref().map(|p| basename(&p.project_key)),
            Some("agentnest")
        );
        assert!(serde_json::to_vec(&e.detail).unwrap().len() <= 8192);
    }

    #[test]
    fn clean_events_are_not_marked_redacted() {
        let env = NormalizeEnv::for_test();
        let mut d = draft(EventKind::ToolStarted);
        d.headline = "WebFetch 도구를 쓰고 있어요".to_owned();
        d.detail = json!({"tool_name": "WebFetch", "tool_input_summary": "docs.rs"})
            .as_object()
            .cloned()
            .unwrap();
        let e = build_event(d, &env);
        assert!(!e.redacted);
        assert_eq!(e.severity, Severity::Info);
        assert!(e.project.is_none());
    }

    #[test]
    fn ids_and_time_come_from_the_environment() {
        let env = NormalizeEnv::for_test();
        let a = build_event(draft(EventKind::Idle), &env);
        let b = build_event(draft(EventKind::Idle), &env);
        assert_ne!(a.event_id, b.event_id);
        assert_eq!(a.ts, "2026-10-15T09:12:33.120Z");
        assert!(agentnest_protocol::is_uuid7(&a.event_id));
    }

    #[test]
    fn empty_headline_gets_a_fallback_and_hostile_text_is_neutralised() {
        let env = NormalizeEnv::for_test();
        let mut d = draft(EventKind::Notification);
        d.headline = String::new();
        d.summary_detail = Some("line1\nline2\u{202e}".to_owned());
        let e = build_event(d, &env);
        assert!(!e.summary.headline.is_empty());
        assert_eq!(e.summary.detail.as_deref(), Some("line1 line2"));
    }

    #[test]
    fn severity_defaults() {
        assert_eq!(default_severity(&EventKind::TurnFailed), Severity::Error);
        assert_eq!(default_severity(&EventKind::ToolFailed), Severity::Warning);
        assert_eq!(
            default_severity(&EventKind::PermissionDeniedAuto),
            Severity::Notice
        );
        assert_eq!(default_severity(&EventKind::SessionStarted), Severity::Info);
    }
}
