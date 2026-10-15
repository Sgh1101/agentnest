//! The outcome correlator: what happened to a tool call after its approval was resolved (`observed_result`;
//! docs/integrations/claude-code.md 6 "관찰 결과", docs/protocol.md 4.12).
//!
//! A hook reply alone does not say whether the tool really ran (a `PermissionRequest` has no `tool_use_id`). So the
//! correlator remembers every resolved request for 60 s and matches the later observation hooks of the **same session,
//! tool name and `sha256(tool_input)`**:
//!
//! | resolution | `PostToolUse` | `PostToolUseFailure` |
//! | --- | --- | --- |
//! | allowed | `executed` | `executed` (it ran and failed) |
//! | denied / denied and stopped | `executed` (it ran anyway: worth showing) | `declined` (UNVERIFIED Phase 0 A7: a denied call surfaces as a failed tool call) |
//!
//! `PreToolUse` is accepted as an observation but never decides anything (it comes *before* the permission request).
//! Each tracked request resolves at most once; a request that gets no evidence within the window stays `unknown`.
//! The correlator is pure data: the broker feeds it and applies the result.

use agentnest_protocol::ObservedResult;

/// How long a resolved request can still be correlated.
pub const CORRELATION_WINDOW_MS: i64 = 60_000;
/// Upper bound of remembered requests.
const MAX_TRACKED: usize = 256;

/// Which hook produced the observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookPhase {
    /// `PreToolUse`.
    Pre,
    /// `PostToolUse`.
    Post,
    /// `PostToolUseFailure`.
    PostFailure,
}

/// How the request was resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackedOutcome {
    /// Allowed by a decision.
    Allowed,
    /// Denied (with or without stopping).
    Denied,
}

#[derive(Clone, Debug)]
struct Tracked {
    request_id: String,
    session_key: String,
    tool_name: String,
    input_sha256: String,
    resolved_ms: i64,
    outcome: TrackedOutcome,
}

/// One observation hook.
#[derive(Clone, Debug)]
pub struct Observation<'a> {
    /// Session key.
    pub session_key: &'a str,
    /// Tool name.
    pub tool_name: &'a str,
    /// Lower-case hex SHA-256 of the canonical tool input.
    pub input_sha256: &'a str,
    /// Which hook.
    pub phase: HookPhase,
    /// Server time, Unix ms.
    pub now_ms: i64,
}

/// A request whose observed result became known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Correlated {
    /// The request.
    pub request_id: String,
    /// What was observed.
    pub observed: ObservedResult,
}

/// Tracks resolved requests and matches observations.
#[derive(Debug, Default)]
pub struct Correlator {
    tracked: Vec<Tracked>,
}

impl Correlator {
    /// An empty correlator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Remembers a resolved request.
    pub fn track(
        &mut self,
        request_id: &str,
        session_key: &str,
        tool_name: &str,
        input_sha256: &str,
        resolved_ms: i64,
        outcome: TrackedOutcome,
    ) {
        self.tracked.push(Tracked {
            request_id: request_id.to_owned(),
            session_key: session_key.to_owned(),
            tool_name: tool_name.to_owned(),
            input_sha256: input_sha256.to_owned(),
            resolved_ms,
            outcome,
        });
        if self.tracked.len() > MAX_TRACKED {
            let excess = self.tracked.len() - MAX_TRACKED;
            self.tracked.drain(..excess);
        }
    }

    /// Forgets requests older than the window.
    pub fn prune(&mut self, now_ms: i64) {
        self.tracked
            .retain(|t| now_ms - t.resolved_ms <= CORRELATION_WINDOW_MS);
    }

    /// Number of requests still waiting for evidence.
    pub fn len(&self) -> usize {
        self.tracked.len()
    }

    /// `true` if nothing is tracked.
    pub fn is_empty(&self) -> bool {
        self.tracked.is_empty()
    }

    /// Matches an observation. Returns the correlated request when the observation is evidence, and stops tracking it.
    pub fn observe(&mut self, obs: &Observation<'_>) -> Option<Correlated> {
        self.prune(obs.now_ms);
        if obs.phase == HookPhase::Pre {
            return None;
        }
        // the oldest matching request first (the same call may have been requested twice in the window)
        let idx = self.tracked.iter().position(|t| {
            t.session_key == obs.session_key
                && t.tool_name == obs.tool_name
                && t.input_sha256 == obs.input_sha256
                && obs.now_ms >= t.resolved_ms
        })?;
        let t = self.tracked.remove(idx);
        let observed = match (t.outcome, obs.phase) {
            (TrackedOutcome::Allowed, _) => ObservedResult::Executed,
            (TrackedOutcome::Denied, HookPhase::Post) => ObservedResult::Executed,
            (TrackedOutcome::Denied, _) => ObservedResult::Declined,
        };
        Some(Correlated {
            request_id: t.request_id,
            observed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(phase: HookPhase, now_ms: i64) -> Observation<'static> {
        Observation {
            session_key: "claude_code:s1",
            tool_name: "Bash",
            input_sha256: "abc",
            phase,
            now_ms,
        }
    }

    fn tracked(c: &mut Correlator, id: &str, outcome: TrackedOutcome) {
        c.track(id, "claude_code:s1", "Bash", "abc", 1_000, outcome);
    }

    #[test]
    fn allowed_requests_become_executed_on_post_or_post_failure() {
        let mut c = Correlator::new();
        tracked(&mut c, "ar_1", TrackedOutcome::Allowed);
        assert_eq!(c.observe(&obs(HookPhase::Pre, 2_000)), None, "PreToolUse is never evidence");
        assert_eq!(c.len(), 1);
        assert_eq!(
            c.observe(&obs(HookPhase::Post, 5_000)),
            Some(Correlated { request_id: "ar_1".into(), observed: ObservedResult::Executed })
        );
        assert!(c.is_empty());
        tracked(&mut c, "ar_2", TrackedOutcome::Allowed);
        assert_eq!(
            c.observe(&obs(HookPhase::PostFailure, 5_000)).unwrap().observed,
            ObservedResult::Executed
        );
    }

    #[test]
    fn denied_requests_are_declined_unless_the_tool_ran_anyway() {
        let mut c = Correlator::new();
        tracked(&mut c, "ar_1", TrackedOutcome::Denied);
        assert_eq!(c.observe(&obs(HookPhase::PostFailure, 5_000)).unwrap().observed, ObservedResult::Declined);
        tracked(&mut c, "ar_2", TrackedOutcome::Denied);
        assert_eq!(c.observe(&obs(HookPhase::Post, 5_000)).unwrap().observed, ObservedResult::Executed);
    }

    #[test]
    fn only_same_session_tool_and_input_hash_match() {
        let mut c = Correlator::new();
        tracked(&mut c, "ar_1", TrackedOutcome::Allowed);
        for (s, t, h) in [
            ("claude_code:other", "Bash", "abc"),
            ("claude_code:s1", "Edit", "abc"),
            ("claude_code:s1", "Bash", "abd"),
        ] {
            let o = Observation { session_key: s, tool_name: t, input_sha256: h, phase: HookPhase::Post, now_ms: 2_000 };
            assert_eq!(c.observe(&o), None);
        }
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn the_window_is_sixty_seconds() {
        let mut c = Correlator::new();
        tracked(&mut c, "ar_1", TrackedOutcome::Allowed);
        assert!(c.observe(&obs(HookPhase::Post, 1_000 + CORRELATION_WINDOW_MS + 1)).is_none());
        assert!(c.is_empty(), "expired entries are pruned");
        tracked(&mut c, "ar_2", TrackedOutcome::Allowed);
        assert!(c.observe(&obs(HookPhase::Post, 1_000 + CORRELATION_WINDOW_MS)).is_some());
    }

    #[test]
    fn two_requests_for_the_same_call_resolve_oldest_first_once_each() {
        let mut c = Correlator::new();
        tracked(&mut c, "ar_1", TrackedOutcome::Allowed);
        tracked(&mut c, "ar_2", TrackedOutcome::Allowed);
        assert_eq!(c.observe(&obs(HookPhase::Post, 3_000)).unwrap().request_id, "ar_1");
        assert_eq!(c.observe(&obs(HookPhase::Post, 3_100)).unwrap().request_id, "ar_2");
        assert!(c.observe(&obs(HookPhase::Post, 3_200)).is_none());
    }

    #[test]
    fn observations_before_the_resolution_are_ignored_and_the_list_is_bounded() {
        let mut c = Correlator::new();
        c.track("ar_1", "claude_code:s1", "Bash", "abc", 5_000, TrackedOutcome::Allowed);
        assert!(c.observe(&obs(HookPhase::Post, 4_000)).is_none());
        for i in 0..400 {
            c.track(&format!("ar_{i}"), "s", "t", "h", 5_000, TrackedOutcome::Allowed);
        }
        assert!(c.len() <= 256);
    }
}
