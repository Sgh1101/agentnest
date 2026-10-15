//! Sessions, projects, adapter state, review findings and settings (docs/storage.md `sessions`, `projects`,
//! `adapter_state`, `review_findings`, `settings`).
//!
//! `sessions.project_key` is a real foreign key to `projects`, so [`Store::upsert_session`] writes the project first,
//! in the same transaction. Nothing references `sessions` (storage.md "FK 원칙"): deleting a session never deletes
//! anything else.

use agentnest_protocol::{
    AgentKind, AgentState, Counters, LastTest, ProjectRef, RecentCommand, RecentFile,
    RemoteApproval, SessionMeta, SessionState, TurnInfo,
};
use rusqlite::{params, OptionalExtension, Row};
use serde_json::{json, Value};

use super::{Store, StoreError};

/// A row of `projects`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct ProjectRecord {
    pub project_key: String,
    pub name: String,
    /// The full path (stays on the PC; the phone only gets `path_hint`).
    pub path: String,
    pub repo: Option<String>,
    pub branch: Option<String>,
    /// First/last seen time (RFC 3339).
    pub seen_at: String,
}

/// A row of `sessions`. Field meanings: docs/storage.md `sessions`.
#[derive(Clone, Debug, PartialEq)]
#[allow(missing_docs)]
pub struct SessionRecord {
    pub session_key: String,
    pub agent_kind: String,
    pub native_session_id: String,
    pub project_key: Option<String>,
    pub title: Option<String>,
    pub model: Option<String>,
    pub permission_mode: Option<String>,
    pub remote_approval: String,
    pub source_channel: String,
    pub transcript_path: Option<String>,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub end_reason: Option<String>,
    pub state: String,
    pub state_since: String,
    pub headline: Option<String>,
    pub detail: Option<String>,
    pub turn_active: bool,
    pub turn_started_at: Option<String>,
    pub turn_completed_at: Option<String>,
    pub prompt_preview: Option<String>,
    pub counters_json: String,
    pub meta_json: String,
    pub recent_json: String,
    pub last_event_at: String,
    pub last_event_seq: Option<i64>,
    pub stale: bool,
}

/// The parts of a [`SessionRecord`] that a [`SessionState`] does not carry.
#[derive(Clone, Debug, Default)]
pub struct SessionExtras {
    /// Native session id (`session_id`, Codex `thread.id`).
    pub native_session_id: String,
    /// `claude_code.hook.http`, `codex.hook.cli`, ...
    pub source_channel: String,
    /// Transcript path (PC only).
    pub transcript_path: Option<String>,
    /// Set when the session ended.
    pub ended_at: Option<String>,
    /// `SessionEnd.reason`.
    pub end_reason: Option<String>,
}

impl SessionRecord {
    /// Builds the row for a derived [`SessionState`].
    pub fn from_state(state: &SessionState, extras: SessionExtras) -> Self {
        Self {
            session_key: state.session_key.clone(),
            agent_kind: state.agent_kind.as_str().to_owned(),
            native_session_id: extras.native_session_id,
            project_key: Some(state.project.project_key.clone()).filter(|k| k != "unknown"),
            title: state.meta.title.clone(),
            model: state.meta.model.clone(),
            permission_mode: state.permission_mode.clone(),
            remote_approval: state.remote_approval.as_str().to_owned(),
            source_channel: extras.source_channel,
            transcript_path: extras.transcript_path,
            started_at: state.started_at.clone(),
            ended_at: extras.ended_at,
            end_reason: extras.end_reason,
            state: state.state.as_str().to_owned(),
            state_since: state.state_since.clone(),
            headline: Some(state.headline.clone()),
            detail: state.detail.clone(),
            turn_active: state.turn.active,
            turn_started_at: state.turn.started_at.clone(),
            turn_completed_at: state.turn.completed_at.clone(),
            prompt_preview: state.turn.prompt_preview.clone(),
            counters_json: serde_json::to_string(&state.counters)
                .unwrap_or_else(|_| "{}".to_owned()),
            meta_json: serde_json::to_string(&state.meta).unwrap_or_else(|_| "{}".to_owned()),
            recent_json: json!({
                "recent_files": state.recent_files,
                "recent_commands": state.recent_commands,
                "last_test": state.last_test,
            })
            .to_string(),
            last_event_at: state.last_event_at.clone(),
            last_event_seq: state.last_event_seq,
            stale: state.stale,
        }
    }

    /// Rebuilds a [`SessionState`] (for a snapshot after a daemon restart, before the reducer has seen new events).
    /// Pending approval ids are not stored in `sessions` and come back empty.
    pub fn to_session_state(&self, project: ProjectRef, agent_label: &str) -> SessionState {
        let recent: Value = serde_json::from_str(&self.recent_json).unwrap_or(Value::Null);
        let counters: Counters = serde_json::from_str(&self.counters_json).unwrap_or_default();
        let meta: SessionMeta = serde_json::from_str(&self.meta_json).unwrap_or_default();
        let recent_files: Vec<RecentFile> =
            serde_json::from_value(recent.get("recent_files").cloned().unwrap_or(Value::Null))
                .unwrap_or_default();
        let recent_commands: Vec<RecentCommand> = serde_json::from_value(
            recent
                .get("recent_commands")
                .cloned()
                .unwrap_or(Value::Null),
        )
        .unwrap_or_default();
        let last_test: Option<LastTest> =
            serde_json::from_value(recent.get("last_test").cloned().unwrap_or(Value::Null))
                .unwrap_or(None);
        SessionState {
            session_key: self.session_key.clone(),
            agent_kind: AgentKind::from_wire(&self.agent_kind),
            agent_label: agent_label.to_owned(),
            project,
            state: AgentState::from_wire(&self.state),
            state_since: self.state_since.clone(),
            headline: self.headline.clone().unwrap_or_default(),
            detail: self.detail.clone(),
            started_at: self.started_at.clone(),
            turn: TurnInfo {
                active: self.turn_active,
                started_at: self.turn_started_at.clone(),
                completed_at: self.turn_completed_at.clone(),
                prompt_preview: self.prompt_preview.clone(),
            },
            permission_mode: self.permission_mode.clone(),
            remote_approval: RemoteApproval::from_wire(&self.remote_approval),
            pending_approval_ids: Vec::new(),
            counters,
            recent_files,
            recent_commands,
            last_test,
            meta,
            last_event_seq: self.last_event_seq,
            last_event_at: self.last_event_at.clone(),
            ended: self.ended_at.is_some(),
            stale: self.stale,
        }
    }
}

const SESSION_COLUMNS: &str = "session_key, agent_kind, native_session_id, project_key, title, model, \
permission_mode, remote_approval, source_channel, transcript_path, started_at, ended_at, end_reason, state, \
state_since, headline, detail, turn_active, turn_started_at, turn_completed_at, prompt_preview, counters_json, \
meta_json, recent_json, last_event_at, last_event_seq, stale";

fn session_from_row(r: &Row<'_>) -> rusqlite::Result<SessionRecord> {
    Ok(SessionRecord {
        session_key: r.get(0)?,
        agent_kind: r.get(1)?,
        native_session_id: r.get(2)?,
        project_key: r.get(3)?,
        title: r.get(4)?,
        model: r.get(5)?,
        permission_mode: r.get(6)?,
        remote_approval: r.get(7)?,
        source_channel: r.get(8)?,
        transcript_path: r.get(9)?,
        started_at: r.get(10)?,
        ended_at: r.get(11)?,
        end_reason: r.get(12)?,
        state: r.get(13)?,
        state_since: r.get(14)?,
        headline: r.get(15)?,
        detail: r.get(16)?,
        turn_active: r.get::<_, i64>(17)? != 0,
        turn_started_at: r.get(18)?,
        turn_completed_at: r.get(19)?,
        prompt_preview: r.get(20)?,
        counters_json: r.get(21)?,
        meta_json: r.get(22)?,
        recent_json: r.get(23)?,
        last_event_at: r.get(24)?,
        last_event_seq: r.get(25)?,
        stale: r.get::<_, i64>(26)? != 0,
    })
}

/// A new `review_findings` row.
#[derive(Clone, Debug, PartialEq)]
#[allow(missing_docs)]
pub struct NewReviewFinding {
    pub session_key: String,
    pub review_id: String,
    pub ts: String,
    pub priority: Option<i64>,
    pub title: String,
    pub body: Option<String>,
    pub file_path: Option<String>,
    pub line_start: Option<i64>,
    pub line_end: Option<i64>,
    pub confidence: Option<f64>,
    /// `app_server_text`, `exec_schema` or `github_pr`.
    pub source: String,
}

/// A row of `adapter_state`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct AdapterStateRow {
    pub agent_kind: String,
    pub status: String,
    pub mode: Option<String>,
    pub detail: Option<String>,
    pub updated_at: String,
}

/// `true` for setting keys that must never exist (security.md 9: no auto-allow, no skipped authentication, no relaxed
/// transport or risk configuration).
pub fn is_forbidden_setting_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    let leaf = k.rsplit('.').next().unwrap_or(&k);
    leaf.starts_with("auto_allow_")
        || leaf.starts_with("skip_auth_for_")
        || matches!(
            leaf,
            "allow_for_session"
                | "trust_all_certs"
                | "bind_hooks_all_interfaces"
                | "hook_bind_addr"
                | "disable_biometric"
                | "risk_overrides"
                | "risk_rules_path"
        )
}

impl Store {
    /// Inserts or updates a project (`last_seen_at`, `repo` and `branch` follow the newest data).
    pub fn upsert_project(&self, p: ProjectRecord) -> Result<(), StoreError> {
        self.run(move |c| {
            upsert_project_conn(c, &p)?;
            Ok(())
        })
    }

    /// Inserts or updates a session (and its project, first, because of the foreign key).
    pub fn upsert_session(
        &self,
        s: SessionRecord,
        project: Option<ProjectRecord>,
    ) -> Result<(), StoreError> {
        self.run(move |c| {
            let tx = c.transaction()?;
            if let Some(p) = &project {
                upsert_project_conn(&tx, p)?;
            }
            tx.execute(
                &format!(
                    "INSERT INTO sessions({SESSION_COLUMNS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,\
                     ?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27) \
                     ON CONFLICT(session_key) DO UPDATE SET project_key=excluded.project_key, title=excluded.title, \
                     model=excluded.model, permission_mode=excluded.permission_mode, \
                     remote_approval=excluded.remote_approval, source_channel=excluded.source_channel, \
                     transcript_path=excluded.transcript_path, ended_at=excluded.ended_at, \
                     end_reason=excluded.end_reason, state=excluded.state, state_since=excluded.state_since, \
                     headline=excluded.headline, detail=excluded.detail, turn_active=excluded.turn_active, \
                     turn_started_at=excluded.turn_started_at, turn_completed_at=excluded.turn_completed_at, \
                     prompt_preview=excluded.prompt_preview, counters_json=excluded.counters_json, \
                     meta_json=excluded.meta_json, recent_json=excluded.recent_json, \
                     last_event_at=excluded.last_event_at, last_event_seq=excluded.last_event_seq, \
                     stale=excluded.stale"
                ),
                params![
                    s.session_key,
                    s.agent_kind,
                    s.native_session_id,
                    s.project_key,
                    s.title,
                    s.model,
                    s.permission_mode,
                    s.remote_approval,
                    s.source_channel,
                    s.transcript_path,
                    s.started_at,
                    s.ended_at,
                    s.end_reason,
                    s.state,
                    s.state_since,
                    s.headline,
                    s.detail,
                    i64::from(s.turn_active),
                    s.turn_started_at,
                    s.turn_completed_at,
                    s.prompt_preview,
                    s.counters_json,
                    s.meta_json,
                    s.recent_json,
                    s.last_event_at,
                    s.last_event_seq,
                    i64::from(s.stale)
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Marks a session as ended.
    pub fn end_session(
        &self,
        session_key: &str,
        ended_at: &str,
        reason: Option<&str>,
    ) -> Result<bool, StoreError> {
        let (k, t, r) = (
            session_key.to_owned(),
            ended_at.to_owned(),
            reason.map(str::to_owned),
        );
        self.run(move |c| {
            Ok(c.execute(
                "UPDATE sessions SET ended_at=?1, end_reason=?2 WHERE session_key=?3",
                params![t, r, k],
            )? == 1)
        })
    }

    /// One session.
    pub fn get_session(&self, session_key: &str) -> Result<Option<SessionRecord>, StoreError> {
        let k = session_key.to_owned();
        self.read(move |c| {
            Ok(c.query_row(
                &format!("SELECT {SESSION_COLUMNS} FROM sessions WHERE session_key=?1"),
                [k],
                session_from_row,
            )
            .optional()?)
        })
    }

    /// Sessions that are still running or ended after `ended_after` (the active list: running sessions plus those that
    /// ended less than 10 minutes ago), newest activity first.
    pub fn list_active_sessions(
        &self,
        ended_after: &str,
    ) -> Result<Vec<SessionRecord>, StoreError> {
        let cutoff = ended_after.to_owned();
        self.read(move |c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {SESSION_COLUMNS} FROM sessions WHERE ended_at IS NULL OR ended_at > ?1 ORDER BY last_event_at DESC"
            ))?;
            let rows = stmt.query_map([cutoff], session_from_row)?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    /// One project.
    pub fn get_project(&self, project_key: &str) -> Result<Option<ProjectRecord>, StoreError> {
        let k = project_key.to_owned();
        self.read(move |c| {
            Ok(c.query_row(
                "SELECT project_key, name, path, repo, branch, last_seen_at FROM projects WHERE project_key=?1",
                [k],
                |r| {
                    Ok(ProjectRecord {
                        project_key: r.get(0)?,
                        name: r.get(1)?,
                        path: r.get(2)?,
                        repo: r.get(3)?,
                        branch: r.get(4)?,
                        seen_at: r.get(5)?,
                    })
                },
            )
            .optional()?)
        })
    }

    /// Inserts or updates the state of an adapter.
    pub fn upsert_adapter_state(&self, a: AdapterStateRow) -> Result<(), StoreError> {
        self.run(move |c| {
            c.execute(
                "INSERT INTO adapter_state(agent_kind, status, mode, detail, updated_at) VALUES (?1,?2,?3,?4,?5) \
                 ON CONFLICT(agent_kind) DO UPDATE SET status=excluded.status, mode=excluded.mode, \
                 detail=excluded.detail, updated_at=excluded.updated_at",
                params![a.agent_kind, a.status, a.mode, a.detail, a.updated_at],
            )?;
            Ok(())
        })
    }

    /// All adapter states.
    pub fn list_adapter_states(&self) -> Result<Vec<AdapterStateRow>, StoreError> {
        self.read(|c| {
            let mut stmt =
                c.prepare("SELECT agent_kind, status, mode, detail, updated_at FROM adapter_state ORDER BY agent_kind")?;
            let rows = stmt.query_map([], |r| {
                Ok(AdapterStateRow {
                    agent_kind: r.get(0)?,
                    status: r.get(1)?,
                    mode: r.get(2)?,
                    detail: r.get(3)?,
                    updated_at: r.get(4)?,
                })
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    /// Stores a review finding (body limited to 2 KiB).
    pub fn insert_review_finding(&self, mut f: NewReviewFinding) -> Result<(), StoreError> {
        if let Some(b) = &mut f.body {
            *b = crate::redact::head_bytes(b, 2048).0;
        }
        self.run(move |c| {
            c.execute(
                "INSERT INTO review_findings(session_key, review_id, ts, priority, title, body, file_path, line_start, \
                 line_end, confidence, source) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    f.session_key,
                    f.review_id,
                    f.ts,
                    f.priority,
                    f.title,
                    f.body,
                    f.file_path,
                    f.line_start,
                    f.line_end,
                    f.confidence,
                    f.source
                ],
            )?;
            Ok(())
        })
    }

    /// Reads a setting.
    pub fn setting_get(&self, key: &str) -> Result<Option<Value>, StoreError> {
        let k = key.to_owned();
        self.read(move |c| {
            let text: Option<String> = c
                .query_row("SELECT value_json FROM settings WHERE key=?1", [k], |r| {
                    r.get(0)
                })
                .optional()?;
            Ok(match text {
                Some(t) => Some(serde_json::from_str(&t)?),
                None => None,
            })
        })
    }

    /// Writes a setting. Forbidden keys (security.md 9) and an `approval.ttl_s` outside 60..=180 are refused; the table
    /// never holds secrets.
    pub fn setting_set(&self, key: &str, value: &Value, now: &str) -> Result<(), StoreError> {
        if is_forbidden_setting_key(key) {
            return Err(StoreError::Invalid(format!(
                "setting key {key} is forbidden"
            )));
        }
        if key == "approval.ttl_s" {
            let ok = value.as_i64().is_some_and(|v| (60..=180).contains(&v));
            if !ok {
                return Err(StoreError::Invalid(
                    "approval.ttl_s must be 60..=180".to_owned(),
                ));
            }
        }
        let (k, v, t) = (key.to_owned(), value.to_string(), now.to_owned());
        self.run(move |c| {
            c.execute(
                "INSERT INTO settings(key, value_json, updated_at) VALUES (?1,?2,?3) \
                 ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
                params![k, v, t],
            )?;
            Ok(())
        })
    }
}

fn upsert_project_conn(c: &rusqlite::Connection, p: &ProjectRecord) -> Result<(), StoreError> {
    c.execute(
        "INSERT INTO projects(project_key, name, path, repo, branch, first_seen_at, last_seen_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?6) \
         ON CONFLICT(project_key) DO UPDATE SET name=excluded.name, path=excluded.path, \
         repo=COALESCE(excluded.repo, projects.repo), branch=COALESCE(excluded.branch, projects.branch), \
         last_seen_at=excluded.last_seen_at",
        params![p.project_key, p.name, p.path, p.repo, p.branch, p.seen_at],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::reducer::SessionReducer;
    use crate::state::timers::format_ms;
    use agentnest_protocol::{
        EventCategory, EventKind, EventSource, EventSummary, Severity, SourceChannel,
    };
    use std::collections::BTreeMap;

    const T0: i64 = 1_760_000_000_000;

    fn project() -> ProjectRecord {
        ProjectRecord {
            project_key: "c:/dev/agentnest".into(),
            name: "agentnest".into(),
            path: "C:\\dev\\agentnest".into(),
            repo: Some("owner/agentnest".into()),
            branch: Some("main".into()),
            seen_at: format_ms(T0),
        }
    }

    fn session(key: &str) -> SessionRecord {
        let mut r = SessionReducer::new(key, AgentKind::ClaudeCode, T0);
        let ev = |kind: &str, detail: Value| agentnest_protocol::AgentEvent {
            event_id: "01929f1a-7a00-7b3c-9e4d-000000000001".into(),
            seq: Some(7),
            ts: format_ms(T0),
            agent_kind: AgentKind::ClaudeCode,
            session_key: key.into(),
            actor: None,
            project: None,
            kind: EventKind::from_wire(kind),
            category: EventCategory::Command,
            severity: Severity::Info,
            summary: EventSummary {
                headline: "테스트를 돌리고 있어요".into(),
                detail: None,
            },
            state_hint: None,
            detail,
            source: EventSource {
                channel: SourceChannel::ClaudeCodeHookHttp,
                native_event: None,
                native_ids: BTreeMap::new(),
            },
            redacted: false,
        };
        r.apply(
            &ev("prompt_submitted", json!({"prompt_preview": "hi"})),
            T0 + 1,
        );
        r.apply(
            &ev(
                "command_started",
                json!({"command": "cargo test", "command_class": "test"}),
            ),
            T0 + 2,
        );
        r.apply(
            &ev(
                "file_modified",
                json!({"file_path": "C:\\a\\b.rs", "op": "update"}),
            ),
            T0 + 3,
        );
        let state = r.session_state(T0 + 3);
        SessionRecord::from_state(
            &state,
            SessionExtras {
                native_session_id: "abc".into(),
                source_channel: "claude_code.hook.http".into(),
                ..Default::default()
            },
        )
    }

    #[test]
    fn session_upsert_round_trips_and_updates() {
        let s = Store::open_in_memory().unwrap();
        let mut rec = session("claude_code:abc");
        rec.project_key = Some("c:/dev/agentnest".into());
        s.upsert_session(rec.clone(), Some(project())).unwrap();
        assert_eq!(s.get_session("claude_code:abc").unwrap().unwrap(), rec);
        assert_eq!(
            s.get_project("c:/dev/agentnest")
                .unwrap()
                .unwrap()
                .repo
                .as_deref(),
            Some("owner/agentnest")
        );
        // update: state changes, the immutable columns stay
        let mut next = rec.clone();
        next.state = "completed".into();
        next.turn_active = false;
        next.native_session_id = "ignored".into();
        next.started_at = "ignored".into();
        s.upsert_session(next, None).unwrap();
        let got = s.get_session("claude_code:abc").unwrap().unwrap();
        assert_eq!(got.state, "completed");
        assert!(!got.turn_active);
        assert_eq!(got.native_session_id, "abc");
        assert_eq!(got.started_at, rec.started_at);
        // a project that disappears from the update keeps its row; repo/branch are not erased by a null
        s.upsert_project(ProjectRecord {
            repo: None,
            branch: None,
            seen_at: format_ms(T0 + 9),
            ..project()
        })
        .unwrap();
        let p = s.get_project("c:/dev/agentnest").unwrap().unwrap();
        assert_eq!(
            (p.repo.as_deref(), p.branch.as_deref()),
            (Some("owner/agentnest"), Some("main"))
        );
        assert_eq!(p.seen_at, format_ms(T0 + 9));
    }

    #[test]
    fn foreign_key_needs_the_project_first() {
        let s = Store::open_in_memory().unwrap();
        let mut rec = session("claude_code:abc");
        rec.project_key = Some("c:/not/there".into());
        assert!(
            s.upsert_session(rec, None).is_err(),
            "foreign_keys=ON: unknown project"
        );
    }

    #[test]
    fn record_to_state_round_trip_keeps_the_phone_facing_fields() {
        let rec = session("claude_code:abc");
        let state = rec.to_session_state(
            ProjectRef {
                project_key: "c:/dev/agentnest".into(),
                name: "agentnest".into(),
                path_hint: None,
                repo: None,
                branch: None,
            },
            "Claude Code",
        );
        assert_eq!(state.state, AgentState::WritingCode);
        assert_eq!(state.counters.commands, 1);
        assert_eq!(state.recent_files.len(), 1);
        assert_eq!(state.recent_commands.len(), 1);
        assert_eq!(state.turn.prompt_preview.as_deref(), Some("hi"));
        assert_eq!(state.last_event_seq, Some(7));
        assert!(!state.ended);
    }

    #[test]
    fn active_list_and_end_session() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_session(session("claude_code:a"), None).unwrap();
        let mut b = session("claude_code:b");
        b.last_event_at = format_ms(T0 + 99_000);
        s.upsert_session(b, None).unwrap();
        assert!(s
            .end_session(
                "claude_code:a",
                &format_ms(T0 + 5_000),
                Some("prompt_input_exit")
            )
            .unwrap());
        assert!(!s
            .end_session("claude_code:none", &format_ms(T0), None)
            .unwrap());
        // 10 minutes after the end the session leaves the active list
        let active = s
            .list_active_sessions(&format_ms(T0 + 5_000 - 600_000))
            .unwrap();
        assert_eq!(
            active
                .iter()
                .map(|r| r.session_key.as_str())
                .collect::<Vec<_>>(),
            vec!["claude_code:b", "claude_code:a"]
        );
        let active = s.list_active_sessions(&format_ms(T0 + 5_000 + 1)).unwrap();
        assert_eq!(
            active
                .iter()
                .map(|r| r.session_key.as_str())
                .collect::<Vec<_>>(),
            vec!["claude_code:b"]
        );
    }

    #[test]
    fn adapter_state_and_review_findings() {
        let s = Store::open_in_memory().unwrap();
        let row = |status: &str, t: i64| AdapterStateRow {
            agent_kind: "codex".into(),
            status: status.into(),
            mode: Some("hooks_cli".into()),
            detail: Some("hooks trusted".into()),
            updated_at: format_ms(t),
        };
        s.upsert_adapter_state(row("degraded", T0)).unwrap();
        s.upsert_adapter_state(row("connected", T0 + 1)).unwrap();
        assert_eq!(
            s.list_adapter_states().unwrap(),
            vec![row("connected", T0 + 1)]
        );
        s.insert_review_finding(NewReviewFinding {
            session_key: "codex:x".into(),
            review_id: "r1".into(),
            ts: format_ms(T0),
            priority: Some(1),
            title: "t".into(),
            body: Some("é".repeat(3000)),
            file_path: None,
            line_start: None,
            line_end: None,
            confidence: None,
            source: "app_server_text".into(),
        })
        .unwrap();
        let len: i64 = s
            .read(|c| {
                Ok(c.query_row(
                    "SELECT LENGTH(CAST(body AS BLOB)) FROM review_findings",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert!(len <= 2048);
    }

    #[test]
    fn settings_reject_forbidden_keys_and_bad_ttl() {
        let s = Store::open_in_memory().unwrap();
        s.setting_set("approval.ttl_s", &json!(120), &format_ms(T0))
            .unwrap();
        assert_eq!(s.setting_get("approval.ttl_s").unwrap(), Some(json!(120)));
        s.setting_set("approval.ttl_s", &json!(60), &format_ms(T0))
            .unwrap();
        for bad in [json!(59), json!(181), json!(300), json!("120")] {
            assert!(
                s.setting_set("approval.ttl_s", &bad, &format_ms(T0))
                    .is_err(),
                "{bad}"
            );
        }
        for key in [
            "auto_allow_low",
            "approval.auto_allow_all",
            "skip_auth_for_low",
            "allow_for_session",
            "trust_all_certs",
            "bind_hooks_all_interfaces",
            "hook_bind_addr",
            "disable_biometric",
            "risk_overrides",
            "risk_rules_path",
            "RISK_OVERRIDES",
        ] {
            assert!(is_forbidden_setting_key(key), "{key}");
            assert!(
                s.setting_set(key, &json!(true), &format_ms(T0)).is_err(),
                "{key}"
            );
        }
        for key in ["approval.critical_remote", "link.enabled", "codex.mode"] {
            assert!(!is_forbidden_setting_key(key), "{key}");
        }
        assert_eq!(s.setting_get("missing").unwrap(), None);
    }
}
