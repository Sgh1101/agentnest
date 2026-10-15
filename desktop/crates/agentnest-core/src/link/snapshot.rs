//! Building a `snapshot` within the byte budget (docs/protocol.md 4.6).
//!
//! The snapshot is limited by **bytes** (`limits.snapshot_max_bytes`, 192 KiB; the frame limit is 256 KiB), not by item
//! counts. Twenty maximum-size approval cards alone can exceed the budget, so the cut order is fixed. **A pending
//! approval is never silently dropped**:
//!
//! 1. `recent_events[].detail` removed (`truncated.recent_events_detail`);
//! 2. approval `diff_preview` / `content_preview` set to `null` (`details.truncated`, `truncated.approval_previews`);
//! 3. `recent_events` reduced 50 -> 20 -> 0 (`truncated.recent_events`);
//! 4. session summaries shrunk: `recent_files` / `recent_commands` emptied, then sessions without a pending approval or an
//!    `awaiting_*` state dropped, oldest `last_event_at` first (`truncated.sessions`);
//! 5. still too big: approval cards that do not fit move out of `pending_approvals[]` into **follow-up
//!    `approval_request` frames** that the caller sends right after the snapshot (`pending_followup` counts them;
//!    `truncated.pending_approvals`). A single card always fits a frame.
//!
//! `pending_approval_ids_complete` always lists **every** pending request id, so the phone never mistakes a card that is
//! still valid for "handled on the PC".

use agentnest_protocol::{
    AdapterStatus, AgentEvent, AgentState, ApprovalRequest, Focus, SessionState, SnapshotPayload,
    SnapshotTruncated,
};
use serde_json::json;

/// Everything a snapshot is made of before the budget is applied.
#[derive(Clone, Debug)]
pub struct SnapshotInputs {
    /// Sessions, newest activity first (at most 20 are used).
    pub sessions: Vec<SessionState>,
    /// Pending, unexpired approval cards in creation order (at most 20 are inlined).
    pub pending: Vec<ApprovalRequest>,
    /// Recent warnings and errors (at most 5).
    pub recent_errors: Vec<AgentEvent>,
    /// Recent events, ascending (at most 50).
    pub recent_events: Vec<AgentEvent>,
    /// Adapter health.
    pub adapters: Vec<AdapterStatus>,
    /// Focused session.
    pub focus: Option<Focus>,
}

/// Maximum number of sessions in a snapshot.
pub const MAX_SESSIONS: usize = 20;
/// Maximum number of inlined pending approvals.
pub const MAX_PENDING: usize = 20;

fn size_of(p: &SnapshotPayload) -> usize {
    serde_json::to_vec(p).map(|v| v.len()).unwrap_or(usize::MAX)
}

fn wants_attention(s: &SessionState) -> bool {
    !s.pending_approval_ids.is_empty()
        || matches!(
            s.state,
            AgentState::AwaitingApproval | AgentState::AwaitingInput
        )
}

/// Builds the snapshot payload within `max_bytes` and returns the approval cards that must follow as separate frames.
pub fn build(inputs: SnapshotInputs, max_bytes: usize) -> (SnapshotPayload, Vec<ApprovalRequest>) {
    let mut sessions = inputs.sessions;
    sessions.truncate(MAX_SESSIONS);
    let mut pending = inputs.pending;
    let ids: Vec<String> = pending.iter().map(|c| c.request_id.clone()).collect();
    // cards beyond the inline limit go to follow-up frames right away
    let mut followups: Vec<ApprovalRequest> = if pending.len() > MAX_PENDING {
        pending.split_off(MAX_PENDING)
    } else {
        Vec::new()
    };
    let mut recent_events = inputs.recent_events;
    let keep = recent_events.len().saturating_sub(50);
    recent_events.drain(..keep);
    let mut recent_errors = inputs.recent_errors;
    let keep = recent_errors.len().saturating_sub(5);
    recent_errors.drain(..keep);

    let t = SnapshotTruncated {
        pending_approvals: !followups.is_empty(),
        ..SnapshotTruncated::default()
    };
    let mut payload = SnapshotPayload {
        sessions,
        pending_approvals: pending,
        recent_errors,
        recent_events,
        adapters: inputs.adapters,
        focus: inputs.focus,
        pending_approval_ids_complete: ids,
        pending_followup: followups.len() as u32,
        truncated: t,
    };
    let fits = |p: &SnapshotPayload| size_of(p) <= max_bytes;
    if fits(&payload) {
        return (payload, followups);
    }
    // 1. event details
    for e in &mut payload.recent_events {
        e.detail = json!({});
    }
    for e in &mut payload.recent_errors {
        e.detail = json!({});
    }
    payload.truncated.recent_events_detail = true;
    if fits(&payload) {
        return (payload, followups);
    }
    // 2. approval previews
    for c in &mut payload.pending_approvals {
        c.details.diff_preview = None;
        c.details.content_preview = None;
        c.details.truncated = true;
    }
    payload.truncated.approval_previews = true;
    if fits(&payload) {
        return (payload, followups);
    }
    // 3. fewer recent events: 50 -> 20 -> 0
    for limit in [20usize, 0] {
        let cut = payload.recent_events.len().saturating_sub(limit);
        payload.recent_events.drain(..cut);
        payload.truncated.recent_events = true;
        if fits(&payload) {
            return (payload, followups);
        }
    }
    // 4. session summaries, then sessions
    for s in &mut payload.sessions {
        s.recent_files.clear();
        s.recent_commands.clear();
    }
    if fits(&payload) {
        return (payload, followups);
    }
    payload.recent_errors.clear();
    while !fits(&payload) {
        // drop the oldest session that needs no attention
        let victim = payload
            .sessions
            .iter()
            .enumerate()
            .filter(|(_, s)| !wants_attention(s))
            .min_by(|a, b| a.1.last_event_at.cmp(&b.1.last_event_at))
            .map(|(i, _)| i);
        match victim {
            Some(i) => {
                payload.sessions.remove(i);
                payload.truncated.sessions = true;
            }
            None => break,
        }
    }
    if fits(&payload) {
        return (payload, followups);
    }
    // 5. move cards out of the list (last first) until it fits; they follow as their own frames
    while !fits(&payload) {
        match payload.pending_approvals.pop() {
            Some(card) => followups.insert(0, card),
            None => break,
        }
    }
    payload.truncated.pending_approvals = true;
    payload.pending_followup = followups.len() as u32;
    (payload, followups)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentnest_protocol::{
        ApprovalDetails, Counters, DetailsKind, EventCategory, EventKind, EventSource,
        EventSummary, ExtraConfirmation, LocalPrompt, ProjectRef, RecentCommand, RecentFile,
        RemoteApproval, RiskLevel, Secret, Severity, SourceChannel, TurnInfo,
    };
    use std::collections::BTreeMap;

    fn project() -> ProjectRef {
        ProjectRef {
            project_key: "c:/dev/agentnest".into(),
            name: "agentnest".into(),
            path_hint: Some("…\\dev\\agentnest".into()),
            repo: None,
            branch: Some("main".into()),
        }
    }

    /// A maximum-size card: 2,000 character command, 4 KiB diff, 4 KiB content preview, 50 paths.
    fn big_card(i: usize) -> ApprovalRequest {
        ApprovalRequest {
            request_id: format!("ar_{i:08x}-0000-7000-8000-000000000000"),
            nonce_b64: Secret::new("Kq2hYm9zZ3FwdHZ4eXoxMg=="),
            session_key: format!("claude_code:s{i}"),
            agent_kind: agentnest_protocol::AgentKind::ClaudeCode,
            agent_label: "Claude Code".into(),
            project: project(),
            origin: SourceChannel::ClaudeCodeHookHttp,
            created_at: "2026-10-15T12:35:00.000Z".into(),
            expires_at: "2026-10-15T12:37:00.000Z".into(),
            ttl_seconds: 120,
            tool_name: "Bash".into(),
            title: "명령을 실행하려고 해요".into(),
            purpose: Some("x".repeat(200)),
            details: ApprovalDetails {
                kind: DetailsKind::Command,
                command: Some("c".repeat(2000)),
                cwd_hint: Some("…\\apps\\desktop".into()),
                file_paths: (0..50)
                    .map(|n| format!("desktop/apps/desktop/src/some/long/path/f{n}.rs"))
                    .collect(),
                diff_preview: Some("d".repeat(4096)),
                content_preview: Some("p".repeat(4096)),
                mcp_server: None,
                reason: None,
                truncated: false,
                permission_suggestions_count: Some(1),
            },
            tool_input_sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                .into(),
            risk: agentnest_protocol::Risk {
                level: RiskLevel::High,
                reasons: vec!["recursive_delete".into()],
                reasons_ko: vec!["폴더를 통째로 지우는 명령이에요".into()],
                extra_confirmation: ExtraConfirmation::Hold,
            },
            allowed_decisions: vec![
                agentnest_protocol::Decision::Allow,
                agentnest_protocol::Decision::Deny,
            ],
            auth_required_for: vec![agentnest_protocol::Decision::Allow],
            permission_mode: Some("default".into()),
            local_prompt: LocalPrompt::Unverified,
        }
    }

    fn event(i: i64, detail_len: usize) -> AgentEvent {
        AgentEvent {
            event_id: format!("01929f1a-7a00-7b3c-9e4d-{i:012x}"),
            seq: Some(i),
            ts: "2026-10-15T12:35:00.000Z".into(),
            agent_kind: agentnest_protocol::AgentKind::ClaudeCode,
            session_key: "claude_code:s1".into(),
            actor: None,
            project: Some(project()),
            kind: EventKind::CommandStarted,
            category: EventCategory::Command,
            severity: Severity::Info,
            summary: EventSummary {
                headline: "명령을 실행하고 있어요".into(),
                detail: Some("d".into()),
            },
            state_hint: None,
            detail: json!({"command": "c".repeat(detail_len)}),
            source: EventSource {
                channel: SourceChannel::ClaudeCodeHookHttp,
                native_event: Some("PreToolUse".into()),
                native_ids: BTreeMap::new(),
            },
            redacted: false,
        }
    }

    fn session(i: usize, pending: bool) -> SessionState {
        SessionState {
            session_key: format!("claude_code:s{i}"),
            agent_kind: agentnest_protocol::AgentKind::ClaudeCode,
            agent_label: "Claude Code".into(),
            project: project(),
            state: if pending {
                AgentState::AwaitingApproval
            } else {
                AgentState::Working
            },
            state_since: "2026-10-15T12:34:50.000Z".into(),
            headline: "작업하고 있어요".into(),
            detail: None,
            started_at: "2026-10-15T11:02:10.000Z".into(),
            turn: TurnInfo::default(),
            permission_mode: None,
            remote_approval: RemoteApproval::Available,
            pending_approval_ids: if pending {
                vec![format!("ar_{i:08x}-0000-7000-8000-000000000000")]
            } else {
                vec![]
            },
            counters: Counters::default(),
            recent_files: (0..5)
                .map(|n| RecentFile {
                    path_hint: format!("…\\src\\f{n}.rs"),
                    op: agentnest_protocol::FileOp::Update,
                    at: "2026-10-15T12:34:40.000Z".into(),
                })
                .collect(),
            recent_commands: (0..3)
                .map(|n| RecentCommand {
                    command_preview: format!("cargo test {n}"),
                    command_class: agentnest_protocol::CommandClass::Test,
                    exit_code: None,
                    at: "2026-10-15T12:34:50.000Z".into(),
                })
                .collect(),
            last_test: None,
            meta: Default::default(),
            last_event_seq: Some(10),
            last_event_at: format!("2026-10-15T12:34:{:02}.000Z", i % 60),
            ended: false,
            stale: false,
        }
    }

    fn inputs(n_cards: usize, n_events: usize, event_detail: usize) -> SnapshotInputs {
        SnapshotInputs {
            sessions: (0..20).map(|i| session(i, i < n_cards)).collect(),
            pending: (0..n_cards).map(big_card).collect(),
            recent_errors: vec![],
            recent_events: (1..=n_events as i64)
                .map(|i| event(i, event_detail))
                .collect(),
            adapters: vec![],
            focus: None,
        }
    }

    fn all_ids(p: &SnapshotPayload, followups: &[ApprovalRequest]) -> Vec<String> {
        let mut v: Vec<String> = p
            .pending_approvals
            .iter()
            .map(|c| c.request_id.clone())
            .collect();
        v.extend(followups.iter().map(|c| c.request_id.clone()));
        v.sort();
        v
    }

    #[test]
    fn a_small_snapshot_is_untouched() {
        let (p, follow) = build(inputs(2, 10, 50), 196_608);
        assert_eq!(p.pending_approvals.len(), 2);
        assert!(follow.is_empty());
        assert_eq!(p.truncated, SnapshotTruncated::default());
        assert_eq!(p.pending_followup, 0);
        assert_eq!(p.pending_approval_ids_complete.len(), 2);
    }

    #[test]
    fn twenty_maximum_size_cards_fit_the_frame_and_none_disappears() {
        let budget = 196_608;
        let (p, follow) = build(inputs(20, 50, 2000), budget);
        // (a) the payload is within the byte budget, so the frame is within max_frame_bytes
        assert!(serde_json::to_vec(&p).unwrap().len() <= budget);
        assert!(serde_json::to_vec(&p).unwrap().len() + 512 <= 262_144);
        // (b) ids_complete lists all 20
        assert_eq!(p.pending_approval_ids_complete.len(), 20);
        // (c) every card is either inline or follows as its own frame
        let mut want: Vec<String> = (0..20).map(|i| big_card(i).request_id).collect();
        want.sort();
        assert_eq!(all_ids(&p, &follow), want, "no approval may be lost");
        assert_eq!(p.pending_followup as usize, follow.len());
        assert!(p.truncated.pending_approvals == !follow.is_empty());
        // one card is always within a frame by itself
        for c in &follow {
            assert!(serde_json::to_vec(c).unwrap().len() < 262_144 - 512);
        }
        // (d) the cut order was applied: the cheap cuts happened before cards were moved
        assert!(p.truncated.recent_events_detail);
        assert!(p.truncated.approval_previews || follow.is_empty());
    }

    #[test]
    fn the_cut_order_is_event_detail_then_previews_then_events_then_sessions_then_followups() {
        let budget = 196_608;
        // event details alone push it over: cutting them is enough
        let (p, follow) = build(inputs(1, 50, 2000), 100_000);
        assert!(p.truncated.recent_events_detail);
        assert!(!p.truncated.approval_previews, "step 2 is not needed");
        assert!(!p.truncated.recent_events);
        assert!(follow.is_empty());
        // previews are cut next: tight budget with several cards
        let (p, follow) = build(inputs(8, 50, 100), 140_000);
        assert!(p.truncated.recent_events_detail && p.truncated.approval_previews);
        assert!(p
            .pending_approvals
            .iter()
            .all(|c| c.details.diff_preview.is_none() && c.details.truncated));
        assert!(
            follow.is_empty(),
            "previews were enough: {}",
            serde_json::to_vec(&p).unwrap().len()
        );
        // many cards: events reduced, then cards move out
        let (p, follow) = build(inputs(20, 50, 2000), 70_000);
        assert!(p.truncated.recent_events);
        assert!(!follow.is_empty());
        assert_eq!(all_ids(&p, &follow).len(), 20);
        assert!(serde_json::to_vec(&p).unwrap().len() <= 70_000);
        let _ = budget;
    }

    #[test]
    fn cards_beyond_twenty_always_follow_as_frames() {
        let mut i = inputs(0, 0, 0);
        i.pending = (0..25).map(big_card).collect();
        let (p, follow) = build(i, 10_000_000);
        assert_eq!(p.pending_approvals.len(), 20);
        assert_eq!(follow.len(), 5);
        assert_eq!(p.pending_followup, 5);
        assert_eq!(p.pending_approval_ids_complete.len(), 25);
        assert!(p.truncated.pending_approvals);
    }

    #[test]
    fn sessions_needing_attention_survive_the_session_cut() {
        // budget so small that session summaries must go; the sessions with a pending approval stay
        let (p, _follow) = build(inputs(3, 0, 0), 22_000);
        assert!(p.truncated.sessions || serde_json::to_vec(&p).unwrap().len() <= 22_000);
        for s in &p.sessions {
            if s.session_key == "claude_code:s0"
                || s.session_key == "claude_code:s1"
                || s.session_key == "claude_code:s2"
            {
                assert!(!s.pending_approval_ids.is_empty());
            }
        }
        let attention: Vec<_> = p.sessions.iter().filter(|s| wants_attention(s)).collect();
        assert_eq!(
            attention.len(),
            3,
            "sessions with pending approvals are never dropped"
        );
        // summaries were emptied before sessions were dropped
        assert!(p.sessions.iter().all(|s| s.recent_files.is_empty()));
    }

    #[test]
    fn item_limits_hold_even_without_a_byte_problem() {
        let mut i = inputs(0, 0, 0);
        i.sessions = (0..30).map(|n| session(n, false)).collect();
        i.recent_events = (1..=80).map(|n| event(n, 10)).collect();
        i.recent_errors = (1..=9).map(|n| event(n, 10)).collect();
        let (p, _) = build(i, 10_000_000);
        assert_eq!(p.sessions.len(), 20);
        assert_eq!(p.recent_events.len(), 50);
        assert_eq!(
            p.recent_events.first().unwrap().seq,
            Some(31),
            "the newest 50 are kept"
        );
        assert_eq!(p.recent_errors.len(), 5);
    }
}
