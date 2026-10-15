//! SessionReducer: `reduce(prev, event, now)`, golden file `protocol/fixtures/state_transitions.json`.
//!
//! The reducer implements the transition table of docs/protocol.md 5.4 and the conventions documented in the fixture
//! file (`_format.conventions`):
//!
//! * the **base state** follows the table; **error latches** (5 s for tool/command failures, 30 s for `test_failed`,
//!   sticky for `turn_failed` / `agent_error`) and **pending approvals** are overlays on top of it, so releasing a
//!   latch reveals the base state again;
//! * pending approvals are the only thing that can hold `awaiting_approval`; while at least one is pending the base
//!   state is frozen, and the state before the first pending approval comes back when the last one is resolved
//!   (`denied_and_stopped` returns `idle`);
//! * `Notification{permission_prompt}`, `Notification{agent_needs_input}` and the Codex `thread/status` flags are *soft*
//!   awaiting states: they are the base state and the next normal event replaces them;
//! * timers: `completed -> idle` after 60 s, `stale` after 15 min and `disconnected` after 45 min (active turn) / 30 min
//!   without events; any event clears `stale` and revives a `disconnected` session.
//!
//! The reducer is a pure function of `(previous state, event, now_ms)`. `now_ms` is the observation time (Unix ms)
//! chosen by the caller; the timestamps of the derived [`SessionState`] are all derived from it.

use agentnest_adapter_api::SessionMetaPatch;
use agentnest_protocol::{
    Actor, AgentEvent, AgentKind, AgentState, CommandClass, Counters, EventKind, FileOp, LastTest,
    ProjectRef, RecentCommand, RecentFile, RemoteApproval, ReviewMeta, ReviewState, SessionMeta,
    SessionState, SourceChannel, TestStatus, TurnInfo,
};
use serde_json::Value;

use super::timers::{
    format_ms, COMPLETED_TO_IDLE_MS, DEAD_AFTER_ACTIVE_MS, DEAD_AFTER_IDLE_MS,
    ENDED_REMOVE_AFTER_MS, ERROR_TEST_FAILED_MS, ERROR_TRANSIENT_MS, STALE_AFTER_MS,
};
use crate::normalize::path;
use crate::redact::{clip, mask};

const EDIT_TOOLS: [&str; 4] = ["Edit", "Write", "MultiEdit", "NotebookEdit"];

/// The full reducer state of one session. Pure data: `Clone`, no timers, no I/O.
#[derive(Clone, Debug)]
pub struct ReducerState {
    session_key: String,
    agent_kind: AgentKind,
    project: Option<ProjectRef>,
    channel: Option<SourceChannel>,
    /// The underlying state that follows the transition table.
    base: AgentState,
    /// Request ids of pending approvals, in arrival order.
    pending: Vec<String>,
    pre_approval: Option<AgentState>,
    stopped_while_pending: bool,
    /// State before a soft `awaiting_*` (Codex flags, `permission_prompt`).
    soft_saved: Option<AgentState>,
    latch5_until: Option<i64>,
    latch30_until: Option<i64>,
    sticky: bool,
    turn_active: bool,
    turn_started_ms: Option<i64>,
    turn_completed_ms: Option<i64>,
    prompt_preview: Option<String>,
    background_tasks: u32,
    ended: bool,
    ended_at_ms: Option<i64>,
    stale: bool,
    disconnected: bool,
    started_ms: Option<i64>,
    last_event_ms: i64,
    last_event_seq: Option<i64>,
    completed_at_ms: Option<i64>,
    read_streak: u32,
    counters: Counters,
    recent_files: Vec<RecentFile>,
    recent_commands: Vec<RecentCommand>,
    last_test: Option<LastTest>,
    meta: SessionMeta,
    permission_mode: Option<String>,
    remote_approval: RemoteApproval,
    headline: String,
    detail: Option<String>,
    headline_state: AgentState,
    state_since_ms: i64,
    last_effective: AgentState,
}

/// What changed after applying an event or a timer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Update {
    /// The effective [`AgentState`] changed.
    pub state_changed: bool,
    /// Anything visible in the derived [`SessionState`] changed (so a `session_state` message is due).
    pub changed: bool,
}

impl ReducerState {
    /// A fresh session: state `idle`, no pending approvals, no active turn, `last_event_at = now`.
    pub fn new(session_key: impl Into<String>, agent_kind: AgentKind, now_ms: i64) -> Self {
        let remote_approval = if agent_kind == AgentKind::ClaudeCode {
            RemoteApproval::Available
        } else {
            // Codex: `approvalPolicy` exposure is unverified (Phase 0 C8); the phone renders `unknown` as unavailable.
            RemoteApproval::PolicyUnknown
        };
        let mut meta = SessionMeta::default();
        if agent_kind == AgentKind::Codex {
            // Hooks mode has no review source (codex.md 8): the phone shows "리뷰 정보 없음 (hooks 모드)".
            meta.review = Some(ReviewMeta {
                p0: 0,
                p1: 0,
                state: ReviewState::Unavailable,
            });
        }
        Self {
            session_key: session_key.into(),
            agent_kind,
            project: None,
            channel: None,
            base: AgentState::Idle,
            pending: Vec::new(),
            pre_approval: None,
            stopped_while_pending: false,
            soft_saved: None,
            latch5_until: None,
            latch30_until: None,
            sticky: false,
            turn_active: false,
            turn_started_ms: None,
            turn_completed_ms: None,
            prompt_preview: None,
            background_tasks: 0,
            ended: false,
            ended_at_ms: None,
            stale: false,
            disconnected: false,
            started_ms: None,
            last_event_ms: now_ms,
            last_event_seq: None,
            completed_at_ms: None,
            read_streak: 0,
            counters: Counters::default(),
            recent_files: Vec::new(),
            recent_commands: Vec::new(),
            last_test: None,
            meta,
            permission_mode: None,
            remote_approval,
            headline: String::new(),
            detail: None,
            headline_state: AgentState::Idle,
            state_since_ms: now_ms,
            last_effective: AgentState::Idle,
        }
    }

    fn latch_active(&self, now: i64) -> bool {
        self.sticky
            || self.latch5_until.is_some_and(|u| now < u)
            || self.latch30_until.is_some_and(|u| now < u)
    }

    /// The effective state at `now`: `disconnected` > pending approval > active error latch > base state.
    pub fn state_at(&self, now_ms: i64) -> AgentState {
        if self.disconnected {
            AgentState::Disconnected
        } else if !self.pending.is_empty() {
            AgentState::AwaitingApproval
        } else if self.latch_active(now_ms) {
            AgentState::Error
        } else {
            self.base.clone()
        }
    }

    /// Request ids of the pending approvals in arrival order.
    pub fn pending_approval_ids(&self) -> &[String] {
        &self.pending
    }

    /// `true` while a turn is running.
    pub fn turn_active(&self) -> bool {
        self.turn_active
    }

    /// `true` after `session_ended`.
    pub fn ended(&self) -> bool {
        self.ended
    }

    /// `true` if no event arrived for 15 minutes during an active turn.
    pub fn stale(&self) -> bool {
        self.stale
    }

    /// Session key.
    pub fn session_key(&self) -> &str {
        &self.session_key
    }

    /// Time (Unix ms) at which an ended session may leave the active list (10 minutes after the end).
    pub fn removable_at_ms(&self) -> Option<i64> {
        self.ended_at_ms.map(|t| t + ENDED_REMOVE_AFTER_MS)
    }

    /// The next instant (Unix ms, strictly after `now_ms`) at which a timer can change the state, if any. The daemon
    /// sleeps until then and calls [`tick`].
    pub fn next_deadline_ms(&self, now_ms: i64) -> Option<i64> {
        let mut best: Option<i64> = None;
        let mut consider = |t: i64| {
            if t > now_ms && best.is_none_or(|b| t < b) {
                best = Some(t);
            }
        };
        if let Some(t) = self.latch5_until {
            consider(t);
        }
        if let Some(t) = self.latch30_until {
            consider(t);
        }
        if self.base == AgentState::Completed {
            if let Some(t) = self.completed_at_ms {
                consider(t + COMPLETED_TO_IDLE_MS);
            }
        }
        if !self.ended && !self.disconnected {
            if self.turn_active && !self.stale {
                consider(self.last_event_ms + STALE_AFTER_MS);
            }
            let dead = if self.turn_active {
                DEAD_AFTER_ACTIVE_MS
            } else {
                DEAD_AFTER_IDLE_MS
            };
            consider(self.last_event_ms + dead);
        }
        if let Some(t) = self.removable_at_ms() {
            consider(t);
        }
        best
    }
}

/// Fires all timers that are due at `now_ms` (completed -> idle, stale, dead). Latch expiry needs no timer: it is part
/// of [`ReducerState::state_at`].
pub fn tick(prev: &ReducerState, now_ms: i64) -> ReducerState {
    let mut s = prev.clone();
    if s.base == AgentState::Completed {
        if let Some(t) = s.completed_at_ms {
            if now_ms - t >= COMPLETED_TO_IDLE_MS {
                s.base = AgentState::Idle;
                s.completed_at_ms = None;
            }
        }
    }
    if !s.ended && !s.disconnected {
        let idle_for = now_ms - s.last_event_ms;
        if s.turn_active && idle_for >= STALE_AFTER_MS {
            s.stale = true;
        }
        let dead_after = if s.turn_active {
            DEAD_AFTER_ACTIVE_MS
        } else {
            DEAD_AFTER_IDLE_MS
        };
        if idle_for >= dead_after {
            s.disconnected = true;
        }
    }
    track_state_since(&mut s, now_ms);
    s
}

fn track_state_since(s: &mut ReducerState, now_ms: i64) {
    let eff = s.state_at(now_ms);
    if eff != s.last_effective {
        s.last_effective = eff;
        s.state_since_ms = now_ms;
    }
}

/// Applies `event` observed at `now_ms`: timers first, then the transition table, then the derived data (counters,
/// recent files and commands, last test, headline).
pub fn reduce(prev: &ReducerState, event: &AgentEvent, now_ms: i64) -> ReducerState {
    let mut s = tick(prev, now_ms);
    let frozen = !s.pending.is_empty();
    let detail = &event.detail;
    let kind = &event.kind;

    // `adapter_status{disconnected}` of the adapter this session belongs to is not session activity.
    let adapter_down = *kind == EventKind::AdapterStatus
        && str_of(detail, "status") == Some("disconnected")
        && s.channel
            .as_ref()
            .is_none_or(|c| *c == event.source.channel);
    let adapter_status_noise = *kind == EventKind::AdapterStatus && !adapter_down;
    if adapter_status_noise {
        // Another adapter's status or a recovery notice: no activity, no state change.
        track_state_since(&mut s, now_ms);
        return s;
    }

    if adapter_down {
        s.disconnected = true;
        track_state_since(&mut s, now_ms);
        return s;
    }

    // Any other event is activity.
    s.disconnected = false;
    s.stale = false;
    s.last_event_ms = now_ms;
    s.last_event_seq = event.seq.or(s.last_event_seq);
    if s.started_ms.is_none() {
        s.started_ms = Some(now_ms);
    }
    // The session belongs to the adapter whose channel produced its first agent-originated event. Broker-created
    // timeline events (`approval_*`) carry no meaningful channel and do not decide this.
    if s.channel.is_none()
        && !matches!(
            kind,
            EventKind::ApprovalRequested | EventKind::ApprovalResolved
        )
    {
        s.channel = Some(event.source.channel.clone());
    }

    macro_rules! set_base {
        ($state:expr) => {{
            if !frozen {
                s.base = $state;
                s.soft_saved = None;
            }
        }};
    }

    let mut streak_reset = true;
    match kind {
        EventKind::SessionStarted => {
            let reason = str_of(detail, "source_reason").unwrap_or("startup");
            s.ended = false;
            s.ended_at_ms = None;
            match reason {
                "resume" => {
                    s.sticky = false; // `turn_failed` / `agent_error` are released by a resume
                }
                "fork" | "compact" => {}
                _ => reset_session(&mut s),
            }
            if let Some(m) = str_of(detail, "model") {
                s.meta.model = Some(clip(m, 80));
            }
            if let Some(t) = str_of(detail, "title") {
                s.meta.title = Some(clip(&mask(t).text, 80));
            }
            if let Some(pm) = str_of(detail, "permission_mode") {
                set_permission_mode(&mut s, pm);
            }
        }
        EventKind::PromptSubmitted => {
            s.ended = false;
            s.ended_at_ms = None;
            set_base!(AgentState::Working);
            s.turn_active = true;
            s.turn_started_ms = Some(now_ms);
            s.turn_completed_ms = None;
            s.prompt_preview = str_of(detail, "prompt_preview").map(|p| clip(p, 200));
            s.latch5_until = None;
            s.latch30_until = None;
            s.sticky = false;
            s.completed_at_ms = None;
        }
        EventKind::TurnStarted => {
            s.turn_active = true;
            s.latch5_until = None;
            s.completed_at_ms = None;
            if matches!(s.base, AgentState::Idle | AgentState::Completed) {
                set_base!(AgentState::Working);
            }
        }
        EventKind::CommandStarted | EventKind::TestRun => {
            let class = str_of(detail, "command_class").unwrap_or("shell");
            let testing = *kind == EventKind::TestRun || class == "test" || class == "build";
            set_base!(if testing {
                AgentState::Testing
            } else {
                AgentState::Working
            });
            s.latch5_until = None;
            if *kind == EventKind::CommandStarted {
                s.counters.tools = s.counters.tools.saturating_add(1);
                s.counters.commands = s.counters.commands.saturating_add(1);
                if let Some(cmd) = str_of(detail, "command") {
                    push_recent_command(&mut s, cmd, class, now_ms);
                }
            } else {
                s.counters.tests = s.counters.tests.saturating_add(1);
                s.last_test = Some(LastTest {
                    status: TestStatus::Running,
                    command_class: CommandClass::Test,
                    runner: str_of(detail, "runner").map(str::to_owned),
                    at: format_ms(now_ms),
                });
            }
        }
        EventKind::ToolStarted => {
            let tool = str_of(detail, "tool_name").unwrap_or("");
            let writes = EDIT_TOOLS.contains(&tool)
                || str_of(detail, "item_type") == Some("fileChange")
                // UNVERIFIED (Phase 0 C10): the Codex hooks patch tool name; unknown names stay `working`.
                || tool == "apply_patch";
            set_base!(if writes {
                AgentState::WritingCode
            } else {
                AgentState::Working
            });
            s.latch5_until = None;
            s.counters.tools = s.counters.tools.saturating_add(1);
        }
        EventKind::FileModified => {
            set_base!(AgentState::WritingCode);
            s.counters.files_modified = s.counters.files_modified.saturating_add(1);
            if let Some(p) = str_of(detail, "file_path") {
                let op = str_of(detail, "op").unwrap_or("update");
                push_recent_file(&mut s, p, FileOp::from_wire(op), now_ms);
            }
        }
        EventKind::FileRead => {
            streak_reset = false;
            s.read_streak = s.read_streak.saturating_add(1);
            s.counters.tools = s.counters.tools.saturating_add(1);
            let explore = event
                .actor
                .as_ref()
                .and_then(|a: &Actor| a.agent_type.as_deref())
                .is_some_and(|t| t.eq_ignore_ascii_case("Explore"));
            if s.read_streak >= 2 || explore {
                set_base!(AgentState::Reviewing);
            } else if matches!(s.base, AgentState::Idle | AgentState::Completed) {
                set_base!(AgentState::Working);
            }
            if let Some(p) = str_of(detail, "file_path") {
                push_recent_file(&mut s, p, FileOp::Read, now_ms);
            }
        }
        EventKind::CommandCompleted => {
            streak_reset = false;
            if let Some(cmd) = str_of(detail, "command") {
                set_exit_code(&mut s, cmd, int_of(detail, "exit_code"));
            }
        }
        EventKind::ToolCompleted
        | EventKind::TokenUsageUpdated
        | EventKind::TaskCreated
        | EventKind::TaskCompleted
        | EventKind::PermissionDeniedAuto
        | EventKind::ContextCompacted
        | EventKind::ReviewFinding
        | EventKind::SubagentStopped
        | EventKind::Unknown(_) => {
            streak_reset = false;
        }
        EventKind::SubagentStarted => {
            streak_reset = false;
            s.latch5_until = None;
        }
        EventKind::SessionMetaUpdated => {
            streak_reset = false;
            apply_meta_fields(&mut s, detail);
        }
        EventKind::ToolFailed | EventKind::CommandFailed => {
            streak_reset = false;
            // A user interrupt (Esc) is not an error: no counter, no latch.
            if detail.get("is_interrupt").and_then(Value::as_bool) != Some(true) {
                s.counters.errors = s.counters.errors.saturating_add(1);
                s.latch5_until = Some(s.latch5_until.unwrap_or(0).max(now_ms + ERROR_TRANSIENT_MS));
            }
            if *kind == EventKind::CommandFailed {
                if let Some(cmd) = str_of(detail, "command") {
                    set_exit_code(&mut s, cmd, int_of(detail, "exit_code"));
                }
            }
        }
        EventKind::TestFailed => {
            streak_reset = false;
            s.latch30_until = Some(
                s.latch30_until
                    .unwrap_or(0)
                    .max(now_ms + ERROR_TEST_FAILED_MS),
            );
            s.last_test = Some(LastTest {
                status: TestStatus::Failed,
                command_class: CommandClass::Test,
                runner: str_of(detail, "runner").map(str::to_owned),
                at: format_ms(now_ms),
            });
        }
        EventKind::TestPassed => {
            streak_reset = false;
            s.latch30_until = None;
            s.last_test = Some(LastTest {
                status: TestStatus::Passed,
                command_class: CommandClass::Test,
                runner: str_of(detail, "runner").map(str::to_owned),
                at: format_ms(now_ms),
            });
        }
        EventKind::TurnFailed | EventKind::AgentError => {
            s.counters.errors = s.counters.errors.saturating_add(1);
            s.sticky = true;
            if *kind == EventKind::TurnFailed {
                s.turn_active = false;
                s.turn_completed_ms = Some(now_ms);
            }
        }
        EventKind::TurnCompleted => {
            // Releases the 30 s `test_failed` latch (protocol.md 5.4). The 5 s transient latch of a `command_failed`
            // expires on its own.
            s.latch30_until = None;
            let bg = int_of(detail, "background_tasks").unwrap_or(0).max(0) as u32;
            s.background_tasks = bg;
            if bg == 0 {
                s.turn_active = false;
                s.turn_completed_ms = Some(now_ms);
                if !frozen {
                    s.base = AgentState::Completed;
                    s.soft_saved = None;
                    s.completed_at_ms = Some(now_ms);
                }
            } else {
                set_base!(AgentState::Working);
            }
        }
        EventKind::TurnInterrupted => {
            s.turn_active = false;
            s.turn_completed_ms = Some(now_ms);
            set_base!(AgentState::Idle);
            s.completed_at_ms = None;
        }
        EventKind::Idle => {
            s.turn_active = false;
            set_base!(AgentState::Idle);
        }
        EventKind::SessionEnded => {
            streak_reset = false;
            s.ended = true;
            s.ended_at_ms = Some(now_ms);
        }
        EventKind::ApprovalRequested => {
            if let Some(id) = str_of(detail, "request_id") {
                if !s.pending.iter().any(|p| p == id) {
                    if s.pending.is_empty() {
                        s.pre_approval = Some(s.base.clone());
                        s.stopped_while_pending = false;
                    }
                    s.pending.push(id.to_owned());
                }
            }
        }
        EventKind::ApprovalResolved => {
            streak_reset = false;
            if let Some(id) = str_of(detail, "request_id") {
                if let Some(pos) = s.pending.iter().position(|p| p == id) {
                    s.pending.remove(pos);
                    if str_of(detail, "outcome") == Some("denied_and_stopped") {
                        s.stopped_while_pending = true;
                    }
                    if s.pending.is_empty() {
                        if s.stopped_while_pending {
                            s.base = AgentState::Idle;
                            s.turn_active = false;
                        } else {
                            s.base = s.pre_approval.take().unwrap_or(AgentState::Working);
                        }
                        s.pre_approval = None;
                        s.stopped_while_pending = false;
                        s.soft_saved = None;
                    }
                }
            }
        }
        EventKind::Notification => {
            streak_reset = false;
            apply_notification(&mut s, detail, now_ms, frozen);
        }
        EventKind::ReviewStarted => {
            s.latch5_until = None;
            set_base!(AgentState::Reviewing);
            let (p0, p1) = s
                .meta
                .review
                .as_ref()
                .map(|r| (r.p0, r.p1))
                .unwrap_or((0, 0));
            s.meta.review = Some(ReviewMeta {
                p0,
                p1,
                state: ReviewState::Running,
            });
        }
        EventKind::ReviewCompleted => {
            set_base!(AgentState::Working);
            let p0 = int_of(detail, "p0_count").unwrap_or(0).max(0) as u32;
            let p1 = int_of(detail, "p1_count").unwrap_or(0).max(0) as u32;
            s.meta.review = Some(ReviewMeta {
                p0,
                p1,
                state: ReviewState::Completed,
            });
        }
        EventKind::AdapterStatus => {}
    }
    if streak_reset {
        s.read_streak = 0;
    }

    update_headline(&mut s, event, now_ms);
    track_state_since(&mut s, now_ms);
    s
}

fn reset_session(s: &mut ReducerState) {
    s.base = AgentState::Idle;
    s.pending.clear();
    s.pre_approval = None;
    s.stopped_while_pending = false;
    s.soft_saved = None;
    s.latch5_until = None;
    s.latch30_until = None;
    s.sticky = false;
    s.turn_active = false;
    s.completed_at_ms = None;
    s.read_streak = 0;
}

fn apply_notification(s: &mut ReducerState, detail: &Value, _now_ms: i64, frozen: bool) {
    match str_of(detail, "notification_type").unwrap_or("") {
        "agent_needs_input" => {
            if !frozen {
                s.base = AgentState::AwaitingInput;
                s.soft_saved = None;
            }
        }
        "permission_prompt" => {
            // Supplements sandbox network prompts for which no PermissionRequest fires. A pending approval already
            // shows awaiting_approval; the soft state is the base state and the next normal event replaces it.
            if !frozen && s.base != AgentState::AwaitingApproval {
                s.soft_saved = Some(s.base.clone());
                s.base = AgentState::AwaitingApproval;
            }
        }
        "codex_thread_status" => {
            let flags: Vec<&str> = detail
                .get("active_flags")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            match str_of(detail, "status").unwrap_or("") {
                "active" => {
                    if frozen {
                        return;
                    }
                    if flags.contains(&"waitingOnApproval") {
                        if s.base != AgentState::AwaitingApproval {
                            s.soft_saved = Some(s.base.clone());
                            s.base = AgentState::AwaitingApproval;
                        }
                    } else if flags.contains(&"waitingOnUserInput") {
                        if s.base != AgentState::AwaitingInput {
                            s.soft_saved = Some(s.base.clone());
                            s.base = AgentState::AwaitingInput;
                        }
                    } else if matches!(
                        s.base,
                        AgentState::AwaitingApproval | AgentState::AwaitingInput
                    ) && s.soft_saved.is_some()
                    {
                        // flag cleared: back to the state before it
                        s.base = s.soft_saved.take().unwrap_or(AgentState::Working);
                    } else if detail.get("has_recent_items").and_then(Value::as_bool) != Some(true)
                        && matches!(s.base, AgentState::Idle | AgentState::Completed)
                    {
                        s.base = AgentState::Working;
                    }
                }
                "idle" => {
                    if !frozen {
                        s.base = AgentState::Idle;
                        s.soft_saved = None;
                    }
                    s.turn_active = false;
                }
                "systemError" => {
                    s.counters.errors = s.counters.errors.saturating_add(1);
                    s.sticky = true;
                }
                _ => {}
            }
        }
        _ => {}
    }
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn int_of(v: &Value, key: &str) -> Option<i64> {
    v.get(key)
        .and_then(|x| x.as_i64().or_else(|| x.as_f64().map(|f| f as i64)))
}

fn push_recent_file(s: &mut ReducerState, file_path: &str, op: FileOp, now_ms: i64) {
    let hint = path::path_hint(file_path);
    s.recent_files.retain(|f| f.path_hint != hint);
    s.recent_files.insert(
        0,
        RecentFile {
            path_hint: hint,
            op,
            at: format_ms(now_ms),
        },
    );
    s.recent_files.truncate(5);
}

fn push_recent_command(s: &mut ReducerState, command: &str, class: &str, now_ms: i64) {
    s.recent_commands.insert(
        0,
        RecentCommand {
            command_preview: preview(command),
            command_class: CommandClass::from_wire(class),
            exit_code: None,
            at: format_ms(now_ms),
        },
    );
    s.recent_commands.truncate(3);
}

fn preview(command: &str) -> String {
    clip(&mask(command).text, 80)
}

fn set_exit_code(s: &mut ReducerState, command: &str, exit_code: Option<i64>) {
    let p = preview(command);
    if let Some(entry) = s
        .recent_commands
        .iter_mut()
        .find(|c| c.command_preview == p && c.exit_code.is_none())
    {
        entry.exit_code = exit_code.and_then(|c| i32::try_from(c).ok());
    }
}

fn apply_meta_fields(s: &mut ReducerState, detail: &Value) {
    if let Some(t) = str_of(detail, "title") {
        s.meta.title = Some(clip(&mask(t).text, 80));
    }
    if let Some(m) = str_of(detail, "model") {
        s.meta.model = Some(clip(m, 80));
    }
    if let Some(c) = detail.get("cost_usd").and_then(Value::as_f64) {
        s.meta.cost_usd = Some(c);
    }
    if let Some(p) = int_of(detail, "pr_number") {
        s.meta.pr_number = u64::try_from(p).ok();
    }
    if let Some(u) = str_of(detail, "pr_url") {
        s.meta.pr_url = Some(clip(u, 200));
    }
    if let Some(p) = int_of(detail, "context_used_pct") {
        s.meta.context_used_pct = u32::try_from(p.clamp(0, 100)).ok();
    }
}

/// `bypassPermissions`, `dontAsk` and `auto` sessions do not ask for permission, so there is nothing to approve
/// remotely (claude-code.md 5, security.md 7).
pub fn remote_approval_for_mode(permission_mode: &str) -> RemoteApproval {
    match permission_mode {
        "bypassPermissions" | "dontAsk" | "auto" => RemoteApproval::Unavailable,
        _ => RemoteApproval::Available,
    }
}

fn set_permission_mode(s: &mut ReducerState, mode: &str) {
    s.permission_mode = Some(clip(mode, 40));
    if s.agent_kind == AgentKind::ClaudeCode && s.remote_approval != RemoteApproval::Paused {
        s.remote_approval = remote_approval_for_mode(mode);
    }
}

fn update_headline(s: &mut ReducerState, event: &AgentEvent, now_ms: i64) {
    use EventKind as K;
    let meaningful = matches!(
        event.kind,
        K::PromptSubmitted
            | K::CommandStarted
            | K::ToolStarted
            | K::FileModified
            | K::FileRead
            | K::CommandFailed
            | K::ToolFailed
            | K::TestFailed
            | K::TestPassed
            | K::TurnCompleted
            | K::TurnFailed
            | K::AgentError
            | K::TurnInterrupted
            | K::ReviewStarted
            | K::ReviewCompleted
            | K::ApprovalRequested
            | K::SessionEnded
    ) || (event.kind == K::Notification
        && matches!(
            str_of(&event.detail, "notification_type"),
            Some("agent_needs_input" | "permission_prompt")
        ));
    if meaningful && !event.summary.headline.is_empty() {
        s.headline = event.summary.headline.clone();
        s.detail = event.summary.detail.clone();
        s.headline_state = s.state_at(now_ms);
    }
}

fn default_headline(state: &AgentState) -> &'static str {
    match state {
        AgentState::Idle => "대기하고 있어요",
        AgentState::Working => "작업하고 있어요",
        AgentState::WritingCode => "코드를 작성하고 있어요",
        AgentState::Reviewing => "코드를 살펴보고 있어요",
        AgentState::Testing => "테스트를 돌리고 있어요",
        AgentState::AwaitingApproval => "허락을 기다리고 있어요",
        AgentState::AwaitingInput => "입력을 기다리고 있어요",
        AgentState::Error => "문제가 생겼어요",
        AgentState::Completed => "작업을 마쳤어요",
        AgentState::Disconnected => "연결이 끊겼어요",
        AgentState::Unknown(_) => "작업하고 있어요",
    }
}

/// The display label of an agent family.
pub fn agent_label(kind: AgentKind) -> &'static str {
    match kind {
        AgentKind::ClaudeCode => "Claude Code",
        AgentKind::Codex => "Codex",
        AgentKind::GeminiCli => "Gemini CLI",
        AgentKind::OpenCode => "OpenCode",
        AgentKind::Other => "AI",
    }
}

fn view(s: &ReducerState, now_ms: i64) -> SessionState {
    let state = s.state_at(now_ms);
    // The headline belongs to the state it was written in; a timer-driven change (idle, disconnected, error expiry)
    // falls back to the generic text of the new state. Background-task waiting keeps its own headline.
    let (headline, detail) = if !s.headline.is_empty() && state == s.headline_state {
        (s.headline.clone(), s.detail.clone())
    } else if state == AgentState::Working && s.background_tasks > 0 && s.turn_active {
        (
            clip(
                &format!("백그라운드 작업 {}개를 기다리고 있어요", s.background_tasks),
                40,
            ),
            None,
        )
    } else {
        (default_headline(&state).to_owned(), None)
    };
    let project = s.project.clone().unwrap_or_else(|| ProjectRef {
        project_key: "unknown".to_owned(),
        name: "알 수 없는 프로젝트".to_owned(),
        path_hint: None,
        repo: None,
        branch: None,
    });
    SessionState {
        session_key: s.session_key.clone(),
        agent_kind: s.agent_kind,
        agent_label: agent_label(s.agent_kind).to_owned(),
        project,
        state,
        state_since: format_ms(s.state_since_ms),
        headline,
        detail,
        started_at: format_ms(s.started_ms.unwrap_or(s.last_event_ms)),
        turn: TurnInfo {
            active: s.turn_active,
            started_at: s.turn_started_ms.map(format_ms),
            completed_at: s.turn_completed_ms.map(format_ms),
            prompt_preview: s.prompt_preview.clone(),
        },
        permission_mode: s.permission_mode.clone(),
        remote_approval: s.remote_approval.clone(),
        pending_approval_ids: s.pending.clone(),
        counters: s.counters.clone(),
        recent_files: s.recent_files.clone(),
        recent_commands: s.recent_commands.clone(),
        last_test: s.last_test.clone(),
        meta: s.meta.clone(),
        last_event_seq: s.last_event_seq,
        last_event_at: format_ms(s.last_event_ms),
        ended: s.ended,
        stale: s.stale,
    }
}

/// A session's reducer with its derived [`SessionState`]: the object the daemon keeps per session.
#[derive(Clone, Debug)]
pub struct SessionReducer {
    state: ReducerState,
}

impl SessionReducer {
    /// A fresh reducer (state `idle`).
    pub fn new(session_key: impl Into<String>, agent_kind: AgentKind, now_ms: i64) -> Self {
        Self {
            state: ReducerState::new(session_key, agent_kind, now_ms),
        }
    }

    /// Sets the project shown on the session card.
    pub fn set_project(&mut self, project: ProjectRef) {
        self.state.project = Some(project);
    }

    /// Applies an event observed at `now_ms` (timers first). Returns what changed.
    pub fn apply(&mut self, event: &AgentEvent, now_ms: i64) -> Update {
        let before = view(&self.state, now_ms);
        let next = reduce(&self.state, event, now_ms);
        self.finish(before, next, now_ms)
    }

    /// Fires due timers. Returns what changed.
    pub fn tick(&mut self, now_ms: i64) -> Update {
        let before = view(&self.state, now_ms);
        let next = tick(&self.state, now_ms);
        self.finish(before, next, now_ms)
    }

    /// Applies a metadata patch from the adapter (`RawObservation::SessionMeta`): title, model, cost, context usage,
    /// pull request, permission mode and remote-approval availability.
    pub fn apply_meta(&mut self, patch: &SessionMetaPatch, now_ms: i64) -> Update {
        let before = view(&self.state, now_ms);
        let mut next = tick(&self.state, now_ms);
        if let Some(t) = &patch.title {
            next.meta.title = Some(clip(&mask(t).text, 80));
        }
        if let Some(m) = &patch.model {
            next.meta.model = Some(clip(m, 80));
        }
        if let Some(c) = patch.cost_usd {
            next.meta.cost_usd = Some(c);
        }
        if let Some(c) = patch.context_used_pct {
            next.meta.context_used_pct = Some(c.min(100));
        }
        if let Some(n) = patch.pr_number {
            next.meta.pr_number = Some(n);
        }
        if let Some(u) = &patch.pr_url {
            next.meta.pr_url = Some(clip(u, 200));
        }
        if let Some(pm) = &patch.permission_mode {
            set_permission_mode(&mut next, pm);
        }
        if let Some(ra) = &patch.remote_approval {
            next.remote_approval = ra.clone();
        }
        self.finish(before, next, now_ms)
    }

    /// Overrides the remote-approval availability (for example `paused` while the PC user pauses remote approval).
    pub fn set_remote_approval(&mut self, value: RemoteApproval, now_ms: i64) -> Update {
        let before = view(&self.state, now_ms);
        let mut next = self.state.clone();
        next.remote_approval = value;
        self.finish(before, next, now_ms)
    }

    fn finish(&mut self, before: SessionState, next: ReducerState, now_ms: i64) -> Update {
        self.state = next;
        let after = view(&self.state, now_ms);
        Update {
            state_changed: before.state != after.state,
            changed: before != after,
        }
    }

    /// The effective state at `now_ms`.
    pub fn state_at(&self, now_ms: i64) -> AgentState {
        self.state.state_at(now_ms)
    }

    /// The derived session state at `now_ms` (what the phone receives as `session_state`).
    pub fn session_state(&self, now_ms: i64) -> SessionState {
        view(&self.state, now_ms)
    }

    /// The next timer deadline after `now_ms`.
    pub fn next_deadline(&self, now_ms: i64) -> Option<i64> {
        self.state.next_deadline_ms(now_ms)
    }

    /// Read access to the pure state.
    pub fn reducer_state(&self) -> &ReducerState {
        &self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentnest_protocol::{EventSource, EventSummary, Severity};
    use serde_json::json;
    use std::collections::BTreeMap;

    fn fixture() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../protocol/fixtures/state_transitions.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn event(kind: &str, detail: Value, actor: Option<Actor>, channel: &str) -> AgentEvent {
        let kind = EventKind::from_wire(kind);
        let category = kind
            .category()
            .unwrap_or(agentnest_protocol::EventCategory::Notification);
        AgentEvent {
            event_id: "01929f1a-7a00-7b3c-9e4d-000000000001".to_owned(),
            seq: Some(1),
            ts: "2026-10-15T09:00:00.000Z".to_owned(),
            agent_kind: AgentKind::ClaudeCode,
            session_key: "claude_code:t".to_owned(),
            actor,
            project: None,
            kind,
            category,
            severity: Severity::Info,
            summary: EventSummary {
                headline: String::new(),
                detail: None,
            },
            state_hint: None,
            detail,
            source: EventSource {
                channel: SourceChannel::from_wire(channel),
                native_event: None,
                native_ids: BTreeMap::new(),
            },
            redacted: false,
        }
    }

    fn from_fixture(input: &Value) -> AgentEvent {
        let actor = input.get("actor").filter(|a| !a.is_null()).map(|a| Actor {
            agent_id: a.get("agent_id").and_then(Value::as_str).map(str::to_owned),
            agent_type: a
                .get("agent_type")
                .and_then(Value::as_str)
                .map(str::to_owned),
            is_subagent: a
                .get("is_subagent")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        });
        event(
            input["kind"].as_str().unwrap(),
            input.get("detail").cloned().unwrap_or_else(|| json!({})),
            actor,
            input
                .get("channel")
                .and_then(Value::as_str)
                .unwrap_or("claude_code.hook.http"),
        )
    }

    #[test]
    fn state_transitions_golden() {
        let f = fixture();
        let cases = f["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 56);
        let mut failures = Vec::new();
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let mut r = SessionReducer::new("claude_code:t", AgentKind::ClaudeCode, 0);
            for (i, step) in case["steps"].as_array().unwrap().iter().enumerate() {
                let t = step["t_ms"].as_i64().unwrap();
                match step.get("input").filter(|v| !v.is_null()) {
                    Some(input) => {
                        r.apply(&from_fixture(input), t);
                    }
                    None => {
                        r.tick(t);
                    }
                }
                let expect = &step["expect"];
                let view = r.session_state(t);
                let mut bad = Vec::new();
                if let Some(want) = expect.get("state").and_then(Value::as_str) {
                    if view.state.as_str() != want {
                        bad.push(format!("state {} != {want}", view.state));
                    }
                }
                if let Some(want) = expect.get("stale").and_then(Value::as_bool) {
                    if view.stale != want {
                        bad.push(format!("stale {} != {want}", view.stale));
                    }
                }
                if let Some(want) = expect.get("ended").and_then(Value::as_bool) {
                    if view.ended != want {
                        bad.push(format!("ended {} != {want}", view.ended));
                    }
                }
                if let Some(want) = expect.get("turn_active").and_then(Value::as_bool) {
                    if view.turn.active != want {
                        bad.push(format!("turn_active {} != {want}", view.turn.active));
                    }
                }
                if let Some(want) = expect.get("pending_approval_ids").and_then(Value::as_array) {
                    let want: Vec<&str> = want.iter().filter_map(Value::as_str).collect();
                    if view.pending_approval_ids != want {
                        bad.push(format!(
                            "pending {:?} != {want:?}",
                            view.pending_approval_ids
                        ));
                    }
                }
                if !bad.is_empty() {
                    failures.push(format!("{name} step {i} (t={t}): {}", bad.join("; ")));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} failing state steps:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    fn ev(kind: &str, detail: Value) -> AgentEvent {
        event(kind, detail, None, "claude_code.hook.http")
    }

    #[test]
    fn pure_reduce_does_not_mutate_the_previous_state() {
        let prev = ReducerState::new("claude_code:t", AgentKind::ClaudeCode, 0);
        let next = reduce(&prev, &ev("prompt_submitted", json!({})), 1_000);
        assert_eq!(prev.state_at(1_000), AgentState::Idle);
        assert_eq!(next.state_at(1_000), AgentState::Working);
        // reduce is a function of its inputs
        let again = reduce(&prev, &ev("prompt_submitted", json!({})), 1_000);
        assert_eq!(again.state_at(1_000), next.state_at(1_000));
    }

    #[test]
    fn deadlines_follow_the_timer_rules() {
        let mut r = SessionReducer::new("claude_code:t", AgentKind::ClaudeCode, 0);
        assert_eq!(
            r.next_deadline(0),
            Some(30 * 60_000),
            "idle session: dead after 30 min"
        );
        r.apply(&ev("prompt_submitted", json!({})), 1_000);
        assert_eq!(
            r.next_deadline(1_000),
            Some(1_000 + 15 * 60_000),
            "active turn: stale first"
        );
        r.apply(&ev("tool_failed", json!({"tool_name": "WebFetch"})), 2_000);
        assert_eq!(
            r.next_deadline(2_000),
            Some(7_000),
            "the 5 s latch ends first"
        );
        r.apply(
            &ev("turn_completed", json!({"background_tasks": 0})),
            10_000,
        );
        assert_eq!(
            r.next_deadline(10_000),
            Some(70_000),
            "completed -> idle after 60 s"
        );
        r.tick(70_000);
        assert_eq!(r.state_at(70_000), AgentState::Idle);
        r.apply(&ev("session_ended", json!({"reason": "other"})), 80_000);
        assert_eq!(r.reducer_state().removable_at_ms(), Some(80_000 + 600_000));
    }

    #[test]
    fn derived_data_counters_recent_lists_and_last_test() {
        let mut r = SessionReducer::new("claude_code:t", AgentKind::ClaudeCode, 0);
        let mut t = 0i64;
        fn step(r: &mut SessionReducer, t: &mut i64, kind: &str, detail: Value) {
            *t += 1000;
            r.apply(&ev(kind, detail), *t);
        }
        step(
            &mut r,
            &mut t,
            "prompt_submitted",
            json!({"prompt_preview": "do it"}),
        );
        step(
            &mut r,
            &mut t,
            "command_started",
            json!({"command": "cargo test", "command_class": "test"}),
        );
        step(
            &mut r,
            &mut t,
            "test_run",
            json!({"command": "cargo test", "command_class": "test", "runner": "cargo"}),
        );
        assert_eq!(
            r.session_state(t).last_test.unwrap().status,
            TestStatus::Running
        );
        step(
            &mut r,
            &mut t,
            "command_completed",
            json!({"command": "cargo test", "exit_code": 0}),
        );
        step(
            &mut r,
            &mut t,
            "test_passed",
            json!({"command": "cargo test", "runner": "cargo"}),
        );
        for i in 0..7 {
            step(
                &mut r,
                &mut t,
                "file_modified",
                json!({"file_path": format!("C:\\p\\src\\f{}.rs", i % 6), "op": "update"}),
            );
        }
        let v = r.session_state(t);
        assert_eq!(v.counters.commands, 1);
        assert_eq!(v.counters.tests, 1);
        assert_eq!(v.counters.files_modified, 7);
        assert_eq!(v.recent_files.len(), 5, "at most 5 recent files");
        assert_eq!(
            v.recent_files[0].path_hint, "…\\src\\f0.rs",
            "newest first, same path de-duplicated"
        );
        assert_eq!(v.recent_commands.len(), 1);
        assert_eq!(v.recent_commands[0].exit_code, Some(0));
        assert_eq!(v.last_test.unwrap().status, TestStatus::Passed);
        assert_eq!(v.turn.prompt_preview.as_deref(), Some("do it"));
        assert!(v.turn.active);
    }

    #[test]
    fn recent_commands_keep_three_and_never_store_secrets() {
        let mut r = SessionReducer::new("claude_code:t", AgentKind::ClaudeCode, 0);
        for (i, c) in ["a", "b", "c", "login password=hunter2"].iter().enumerate() {
            r.apply(
                &ev(
                    "command_started",
                    json!({"command": c, "command_class": "shell"}),
                ),
                1000 * (i as i64 + 1),
            );
        }
        let v = r.session_state(5000);
        assert_eq!(v.recent_commands.len(), 3);
        assert_eq!(v.recent_commands[0].command_preview, "login <redacted>");
    }

    #[test]
    fn headline_falls_back_when_the_state_changes_by_timer() {
        let mut r = SessionReducer::new("claude_code:t", AgentKind::ClaudeCode, 0);
        let mut e = ev("turn_completed", json!({"background_tasks": 0}));
        e.summary.headline = "이번 작업을 마쳤어요".to_owned();
        r.apply(&e, 1_000);
        assert_eq!(r.session_state(1_000).headline, "이번 작업을 마쳤어요");
        r.tick(61_000);
        assert_eq!(r.session_state(61_000).headline, "대기하고 있어요");
        assert_eq!(r.session_state(61_000).state, AgentState::Idle);
    }

    #[test]
    fn state_since_tracks_the_effective_state() {
        let mut r = SessionReducer::new("claude_code:t", AgentKind::ClaudeCode, 0);
        r.apply(&ev("prompt_submitted", json!({})), 1_000);
        assert_eq!(r.session_state(1_000).state_since, format_ms(1_000));
        r.apply(&ev("tool_started", json!({"tool_name": "WebFetch"})), 2_000);
        assert_eq!(
            r.session_state(2_000).state_since,
            format_ms(1_000),
            "working -> working keeps state_since"
        );
        r.apply(
            &ev("file_modified", json!({"op": "edit", "file_path": "a.rs"})),
            3_000,
        );
        assert_eq!(r.session_state(3_000).state_since, format_ms(3_000));
    }

    #[test]
    fn update_reports_what_changed() {
        let mut r = SessionReducer::new("claude_code:t", AgentKind::ClaudeCode, 0);
        let u = r.apply(&ev("prompt_submitted", json!({})), 1_000);
        assert!(u.state_changed && u.changed);
        let u = r.apply(&ev("tool_completed", json!({"tool_name": "x"})), 2_000);
        assert!(!u.state_changed);
        assert!(u.changed, "last_event_at moved");
    }

    #[test]
    fn meta_patch_and_remote_approval() {
        let mut r = SessionReducer::new("claude_code:t", AgentKind::ClaudeCode, 0);
        assert_eq!(
            r.session_state(0).remote_approval,
            RemoteApproval::Available
        );
        let patch = SessionMetaPatch {
            title: Some("훅 수집기 구현".to_owned()),
            cost_usd: Some(1.23),
            context_used_pct: Some(300),
            permission_mode: Some("bypassPermissions".to_owned()),
            ..Default::default()
        };
        r.apply_meta(&patch, 10);
        let v = r.session_state(10);
        assert_eq!(v.meta.title.as_deref(), Some("훅 수집기 구현"));
        assert_eq!(v.meta.context_used_pct, Some(100));
        assert_eq!(v.remote_approval, RemoteApproval::Unavailable);
        assert_eq!(v.permission_mode.as_deref(), Some("bypassPermissions"));
        r.set_remote_approval(RemoteApproval::Paused, 20);
        assert_eq!(r.session_state(20).remote_approval, RemoteApproval::Paused);
        let codex = SessionReducer::new("codex:x", AgentKind::Codex, 0).session_state(0);
        assert_eq!(codex.remote_approval, RemoteApproval::PolicyUnknown);
        assert_eq!(codex.meta.review.unwrap().state, ReviewState::Unavailable);
        for (mode, want) in [
            ("default", true),
            ("acceptEdits", true),
            ("plan", true),
            ("auto", false),
            ("dontAsk", false),
        ] {
            assert_eq!(
                remote_approval_for_mode(mode) == RemoteApproval::Available,
                want,
                "{mode}"
            );
        }
    }

    #[test]
    fn unknown_kinds_and_garbage_details_are_harmless() {
        let mut r = SessionReducer::new("claude_code:t", AgentKind::ClaudeCode, 0);
        r.apply(&ev("prompt_submitted", json!({})), 1_000);
        for (i, d) in [
            json!(null),
            json!(5),
            json!([]),
            json!({"command_class": 3, "request_id": 7}),
        ]
        .into_iter()
        .enumerate()
        {
            for kind in [
                "command_started",
                "approval_requested",
                "approval_resolved",
                "notification",
                "file_modified",
                "from_the_future",
            ] {
                r.apply(&ev(kind, d.clone()), 2_000 + i as i64);
            }
        }
        assert!(r.session_state(5_000).pending_approval_ids.is_empty());
    }
}
