//! Duplicate suppression for observation hooks (docs/integrations/claude-code.md 4, architecture.md 5.1).
//!
//! `dedupe_key = sha256(session_id | hook_event_name | tool_use_id ?? sha256(body))`; the same key within a 2 second
//! window is ignored. The same hook can arrive twice when it is defined in both the user and the project settings.
//! `PermissionRequest` is *not* deduplicated here: the broker merges approval cards with its own rule (same
//! `agent_id`, 2 second window, claude-code.md 6).

use std::collections::{HashMap, VecDeque};

use agentnest_protocol::canonical::sha256_hex;

/// The de-duplication window.
pub const DEDUPE_WINDOW_MS: i64 = 2_000;
const MAX_ENTRIES: usize = 4_096;

/// A computed key and where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DedupeKey {
    /// Lower-case hex SHA-256.
    pub key: String,
    /// `true` if the key was derived from a `tool_use_id` (unique per tool call, safe to persist in the unique
    /// `events.dedupe_key` index). Keys derived from the body hash are only valid inside the 2 second window: two
    /// legitimate identical bodies minutes apart must both be stored.
    pub from_tool_use_id: bool,
}

/// Computes the key. `body` is the raw request body (or, for a Codex permission request without `tool_use_id`, the
/// canonical `tool_input`).
pub fn dedupe_key(
    session_id: &str,
    hook_event_name: &str,
    tool_use_id: Option<&str>,
    body: &[u8],
) -> DedupeKey {
    let tool_use_id = tool_use_id.filter(|t| !t.is_empty());
    let third = match tool_use_id {
        Some(t) => t.to_owned(),
        None => sha256_hex(body),
    };
    let key = sha256_hex(format!("{session_id}|{hook_event_name}|{third}").as_bytes());
    DedupeKey {
        key,
        from_tool_use_id: tool_use_id.is_some(),
    }
}

/// A sliding window of recently seen keys. Not thread safe; the hook handler owns it behind a mutex.
#[derive(Debug)]
pub struct DedupeWindow {
    window_ms: i64,
    seen: HashMap<String, i64>,
    order: VecDeque<(String, i64)>,
}

impl Default for DedupeWindow {
    fn default() -> Self {
        Self::new(DEDUPE_WINDOW_MS)
    }
}

impl DedupeWindow {
    /// A window of `window_ms` milliseconds.
    pub fn new(window_ms: i64) -> Self {
        Self {
            window_ms,
            seen: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Returns `true` if `key` was already seen less than the window ago (the event is a duplicate and must be
    /// ignored); otherwise records it and returns `false`. A duplicate does **not** extend the window.
    pub fn is_duplicate(&mut self, key: &str, now_ms: i64) -> bool {
        self.prune(now_ms);
        if let Some(&first) = self.seen.get(key) {
            if now_ms - first < self.window_ms {
                return true;
            }
        }
        self.seen.insert(key.to_owned(), now_ms);
        self.order.push_back((key.to_owned(), now_ms));
        while self.order.len() > MAX_ENTRIES {
            if let Some((k, t)) = self.order.pop_front() {
                if self.seen.get(&k) == Some(&t) {
                    self.seen.remove(&k);
                }
            }
        }
        false
    }

    fn prune(&mut self, now_ms: i64) {
        while let Some((k, t)) = self.order.front() {
            if now_ms - *t < self.window_ms {
                break;
            }
            let (k, t) = (k.clone(), *t);
            self.order.pop_front();
            if self.seen.get(&k) == Some(&t) {
                self.seen.remove(&k);
            }
        }
    }

    /// Number of keys currently remembered.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// `true` if nothing is remembered.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_follows_the_documented_formula() {
        let body = br#"{"a":1}"#;
        let with_id = dedupe_key("s1", "PreToolUse", Some("toolu_1"), body);
        assert_eq!(with_id.key, sha256_hex(b"s1|PreToolUse|toolu_1"));
        assert!(with_id.from_tool_use_id);
        let without = dedupe_key("s1", "Stop", None, body);
        assert_eq!(
            without.key,
            sha256_hex(format!("s1|Stop|{}", sha256_hex(body)).as_bytes())
        );
        assert!(!without.from_tool_use_id);
        assert_eq!(
            dedupe_key("s1", "Stop", Some(""), body),
            without,
            "an empty tool_use_id counts as missing"
        );
        assert_ne!(dedupe_key("s2", "Stop", None, body).key, without.key);
        assert_ne!(dedupe_key("s1", "Stop", None, b"other").key, without.key);
        assert_ne!(
            dedupe_key("s1", "SubagentStop", None, body).key,
            without.key
        );
        assert_eq!(without.key.len(), 64);
    }

    #[test]
    fn two_second_window() {
        let mut w = DedupeWindow::default();
        assert!(!w.is_duplicate("k", 1_000));
        assert!(w.is_duplicate("k", 1_500));
        assert!(
            w.is_duplicate("k", 2_999),
            "a duplicate does not extend the window"
        );
        assert!(
            !w.is_duplicate("k", 3_000),
            "after exactly 2 s the key is new again"
        );
        assert!(w.is_duplicate("k", 3_500));
        assert!(!w.is_duplicate("other", 3_500));
    }

    #[test]
    fn window_is_bounded() {
        let mut w = DedupeWindow::new(60_000);
        for i in 0..10_000 {
            w.is_duplicate(&format!("k{i}"), i);
        }
        assert!(w.len() <= MAX_ENTRIES);
        assert!(!w.is_empty());
        let mut w2 = DedupeWindow::default();
        w2.is_duplicate("a", 0);
        w2.is_duplicate("b", 10_000);
        assert_eq!(w2.len(), 1, "expired keys are pruned");
    }
}
