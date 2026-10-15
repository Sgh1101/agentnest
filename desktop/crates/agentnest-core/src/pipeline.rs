//! The event pipeline: from a normalised [`AgentEvent`] to the replay stream, the session reducers, the database and
//! the live fan-out (docs/architecture.md 5.1 steps 5-7).
//!
//! # Ordering
//!
//! Every write to the replay stream and the broadcast to connected phones goes through one `tokio` mutex, so the
//! broadcast order equals the `seq` order (a phone that sees `seq` 6 before 5 would have to discard 5 on its next
//! `ack`). The approval broker publishes through the same object.
//!
//! # What lives here
//!
//! * per-session [`SessionReducer`]s (the state derivation of protocol.md 5.4) with their timers ([`Pipeline::tick`]),
//! * persistence of sessions and projects (`sessions`, `projects`),
//! * the replayable messages: `event`, `session_state`, `approval_request`, `approval_resolved`, `adapter_status`,
//! * adapter health,
//! * the inputs of a `snapshot` ([`Pipeline::snapshot_sessions`]).
//!
//! It makes **no decision** and never touches an approval row.

use std::collections::HashMap;
use std::sync::Arc;

use agentnest_adapter_api::SessionMetaPatch;
use agentnest_protocol::{
    AdapterMode, AdapterStatus, AdapterStatusKind, AgentEvent, AgentKind, ApprovalRequest,
    ApprovalResolvedPayload, EventKind, ProjectRef, RemoteApproval, SessionState,
};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::events::{DaemonEvent, EventBus};
use crate::link::registry::{Published, Registry};
use crate::state::reducer::{agent_label, remote_approval_for_mode};
use crate::state::timers::{format_ms, parse_ms, Clock, ENDED_REMOVE_AFTER_MS};
use crate::state::{resolve_focus, FocusSession, LinkState, SessionReducer};
use crate::store::{
    AdapterStateRow, AppendOutcome, NewStreamMessage, ProjectRecord, SessionExtras, SessionRecord,
    Store, StoreError,
};

struct SessionEntry {
    reducer: SessionReducer,
    native_session_id: String,
    source_channel: String,
    project: Option<ProjectRef>,
    ended_at: Option<String>,
    end_reason: Option<String>,
}

struct State {
    sessions: HashMap<String, SessionEntry>,
    adapters: HashMap<String, AdapterStatus>,
    paused: bool,
}

/// What [`Pipeline::ingest_event`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngestOutcome {
    /// Stored with this `seq`.
    Stored(i64),
    /// The same hook was already stored (unique `dedupe_key`); nothing changed.
    Duplicate,
    /// The store failed; the event was dropped (logged without values).
    Failed,
}

/// The pipeline. Share it as `Arc<Pipeline>`.
pub struct Pipeline {
    store: Store,
    clock: Arc<dyn Clock>,
    registry: Arc<Registry>,
    bus: EventBus,
    state: Mutex<State>,
}

impl std::fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipeline").finish_non_exhaustive()
    }
}

fn project_record(p: &ProjectRef, now: &str) -> Option<ProjectRecord> {
    if p.project_key == "unknown" {
        return None;
    }
    Some(ProjectRecord {
        project_key: p.project_key.clone(),
        name: p.name.clone(),
        // The full path stays on the PC; the project key is the normalised path.
        path: p.project_key.clone(),
        repo: p.repo.clone(),
        branch: p.branch.clone(),
        seen_at: now.to_owned(),
    })
}

fn session_record(entry: &SessionEntry, state: &SessionState) -> SessionRecord {
    SessionRecord::from_state(
        state,
        SessionExtras {
            native_session_id: entry.native_session_id.clone(),
            source_channel: entry.source_channel.clone(),
            transcript_path: None,
            ended_at: entry.ended_at.clone(),
            end_reason: entry.end_reason.clone(),
        },
    )
}

impl Pipeline {
    /// A pipeline writing to `store` and publishing through `registry` and `bus`.
    pub fn new(store: Store, clock: Arc<dyn Clock>, registry: Arc<Registry>, bus: EventBus) -> Self {
        Self {
            store,
            clock,
            registry,
            bus,
            state: Mutex::new(State {
                sessions: HashMap::new(),
                adapters: HashMap::new(),
                paused: false,
            }),
        }
    }

    async fn db<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Store) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || f(&store))
            .await
            .map_err(|e| StoreError::Panicked(e.to_string()))?
    }

    fn broadcast(&self, seq: i64, msg_type: &str, payload: Value, expires_at: Option<String>) {
        self.registry.broadcast(Published {
            seq,
            msg_type: msg_type.to_owned(),
            payload,
            expires_at,
        });
    }

    /// Stores and publishes an event, runs it through the session reducer and publishes the resulting `session_state`.
    ///
    /// `dedupe_key` must only be a key derived from a `tool_use_id` (the unique index; see `normalize::dedupe`).
    pub async fn ingest_event(&self, event: AgentEvent, dedupe_key: Option<String>) -> IngestOutcome {
        let mut st = self.state.lock().await;
        let now_ms = self.clock.now_ms();
        let now = format_ms(now_ms);
        let (event_for_db, now_db) = (event.clone(), now.clone());
        let appended = self
            .db(move |s| s.append_event(event_for_db, dedupe_key, &now_db))
            .await;
        let stored = match appended {
            Ok(AppendOutcome::Appended(ev)) => *ev,
            Ok(AppendOutcome::Duplicate) => return IngestOutcome::Duplicate,
            Err(e) => {
                tracing::warn!(error = %e, kind = %event.kind, "could not store an event");
                return IngestOutcome::Failed;
            }
        };
        let seq = stored.seq.unwrap_or_default();
        match serde_json::to_value(&stored) {
            Ok(v) => self.broadcast(seq, "event", v, None),
            Err(e) => tracing::warn!(error = %e, "could not serialise an event"),
        }
        self.bus.emit(DaemonEvent::Event(Box::new(stored.clone())));

        let key = stored.session_key.clone();
        let paused = st.paused;
        let entry = st.sessions.entry(key.clone()).or_insert_with(|| SessionEntry {
            reducer: SessionReducer::new(key.clone(), stored.agent_kind, now_ms),
            native_session_id: key
                .split_once(':')
                .map(|(_, id)| id.to_owned())
                .unwrap_or_else(|| key.clone()),
            source_channel: stored.source.channel.as_str().to_owned(),
            project: None,
            ended_at: None,
            end_reason: None,
        });
        if let Some(p) = &stored.project {
            entry.reducer.set_project(p.clone());
            entry.project = Some(p.clone());
        }
        let update = entry.reducer.apply(&stored, now_ms);
        if paused {
            entry
                .reducer
                .set_remote_approval(RemoteApproval::Paused, now_ms);
        }
        if stored.kind == EventKind::SessionEnded {
            entry.ended_at = Some(now.clone());
            entry.end_reason = stored
                .detail
                .get("reason")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        if update.changed || stored.kind == EventKind::SessionEnded {
            self.publish_session_state(entry, now_ms, &now).await;
        }
        IngestOutcome::Stored(seq)
    }

    async fn publish_session_state(&self, entry: &SessionEntry, now_ms: i64, now: &str) {
        let state = entry.reducer.session_state(now_ms);
        let record = session_record(entry, &state);
        let project = entry
            .project
            .as_ref()
            .and_then(|p| project_record(p, now));
        let msg = match serde_json::to_value(&state) {
            Ok(payload) => NewStreamMessage {
                msg_type: "session_state".to_owned(),
                ts: now.to_owned(),
                session_key: Some(state.session_key.clone()),
                ref_id: None,
                payload,
                expires_at: None,
                inject_seq: false,
            },
            Err(e) => {
                tracing::warn!(error = %e, "could not serialise a session state");
                return;
            }
        };
        let payload = msg.payload.clone();
        let session_key = state.session_key.clone();
        let result = self
            .db(move |s| {
                let seq = s.stream_append(msg)?;
                s.upsert_session(record, project)?;
                Ok(seq)
            })
            .await;
        match result {
            Ok(seq) => {
                self.broadcast(seq, "session_state", payload, None);
                self.bus.emit(DaemonEvent::SessionState(Box::new(state)));
            }
            Err(e) => {
                tracing::warn!(error = %e, session = %crate::redact::session_key_prefix(&session_key), "could not store a session state")
            }
        }
    }

    /// Applies a metadata patch (statusline, Codex thread name, ...) to a session.
    pub async fn apply_meta(&self, session_key: &str, agent_kind: AgentKind, patch: &SessionMetaPatch) {
        let mut st = self.state.lock().await;
        let now_ms = self.clock.now_ms();
        let now = format_ms(now_ms);
        let paused = st.paused;
        let key = session_key.to_owned();
        let entry = st.sessions.entry(key.clone()).or_insert_with(|| SessionEntry {
            reducer: SessionReducer::new(key.clone(), agent_kind, now_ms),
            native_session_id: key
                .split_once(':')
                .map(|(_, id)| id.to_owned())
                .unwrap_or_else(|| key.clone()),
            source_channel: "claude_code.statusline".to_owned(),
            project: None,
            ended_at: None,
            end_reason: None,
        });
        let update = entry.reducer.apply_meta(patch, now_ms);
        if paused {
            entry
                .reducer
                .set_remote_approval(RemoteApproval::Paused, now_ms);
        }
        if update.changed {
            self.publish_session_state(entry, now_ms, &now).await;
        }
    }

    /// Publishes an `approval_request` card (the wire message; the timeline event is published separately by the
    /// broker). Returns its `seq`.
    pub async fn publish_approval_request(&self, card: &ApprovalRequest) -> Option<i64> {
        let _st = self.state.lock().await;
        let payload = serde_json::to_value(card).ok()?;
        let msg = NewStreamMessage {
            msg_type: "approval_request".to_owned(),
            ts: format_ms(self.clock.now_ms()),
            session_key: Some(card.session_key.clone()),
            ref_id: Some(card.request_id.clone()),
            payload: payload.clone(),
            expires_at: Some(card.expires_at.clone()),
            inject_seq: false,
        };
        match self.db(move |s| s.stream_append(msg)).await {
            Ok(seq) => {
                self.broadcast(seq, "approval_request", payload, Some(card.expires_at.clone()));
                Some(seq)
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not store an approval request message");
                None
            }
        }
    }

    /// Publishes an `approval_resolved` message (also used to re-send with an updated `observed_result`).
    pub async fn publish_approval_resolved(&self, resolved: &ApprovalResolvedPayload) -> Option<i64> {
        let _st = self.state.lock().await;
        let payload = serde_json::to_value(resolved).ok()?;
        let msg = NewStreamMessage {
            msg_type: "approval_resolved".to_owned(),
            ts: format_ms(self.clock.now_ms()),
            session_key: Some(resolved.session_key.clone()),
            ref_id: Some(resolved.request_id.clone()),
            payload: payload.clone(),
            expires_at: None,
            inject_seq: false,
        };
        match self.db(move |s| s.stream_append(msg)).await {
            Ok(seq) => {
                self.broadcast(seq, "approval_resolved", payload, None);
                Some(seq)
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not store an approval resolution message");
                None
            }
        }
    }

    /// Records and publishes the health of an adapter.
    pub async fn set_adapter_status(
        &self,
        kind: AgentKind,
        status: AdapterStatusKind,
        mode: AdapterMode,
        detail: Option<String>,
    ) {
        let mut st = self.state.lock().await;
        let now = format_ms(self.clock.now_ms());
        let entry = AdapterStatus {
            agent_kind: kind,
            status: status.clone(),
            mode: mode.clone(),
            detail: detail.clone(),
            updated_at: now.clone(),
        };
        if let Some(prev) = st.adapters.get(kind.as_str()) {
            if prev.status == entry.status && prev.mode == entry.mode && prev.detail == entry.detail {
                return;
            }
        }
        st.adapters.insert(kind.as_str().to_owned(), entry.clone());
        let row = AdapterStateRow {
            agent_kind: kind.as_str().to_owned(),
            status: status.as_str().to_owned(),
            mode: Some(mode.as_str().to_owned()),
            detail,
            updated_at: now.clone(),
        };
        let Ok(payload) = serde_json::to_value(&entry) else {
            return;
        };
        let msg = NewStreamMessage {
            msg_type: "adapter_status".to_owned(),
            ts: now,
            session_key: None,
            ref_id: Some(kind.as_str().to_owned()),
            payload: payload.clone(),
            expires_at: None,
            inject_seq: false,
        };
        let result = self
            .db(move |s| {
                s.upsert_adapter_state(row)?;
                s.stream_append(msg)
            })
            .await;
        match result {
            Ok(seq) => {
                self.broadcast(seq, "adapter_status", payload, None);
                self.bus.emit(DaemonEvent::Adapter(entry));
            }
            Err(e) => tracing::warn!(error = %e, "could not store an adapter status"),
        }
    }

    /// The adapter statuses (snapshot `adapters`), sorted by agent kind.
    pub async fn adapters(&self) -> Vec<AdapterStatus> {
        let st = self.state.lock().await;
        let mut v: Vec<AdapterStatus> = st.adapters.values().cloned().collect();
        v.sort_by(|a, b| a.agent_kind.as_str().cmp(b.agent_kind.as_str()));
        v
    }

    /// Pauses or resumes remote approval for display purposes: every session shows `remote_approval: paused`.
    pub async fn set_paused(&self, paused: bool) {
        let mut st = self.state.lock().await;
        if st.paused == paused {
            return;
        }
        st.paused = paused;
        let now_ms = self.clock.now_ms();
        let now = format_ms(now_ms);
        let keys: Vec<String> = st.sessions.keys().cloned().collect();
        for key in keys {
            let Some(entry) = st.sessions.get_mut(&key) else { continue };
            let current = entry.reducer.session_state(now_ms);
            let target = if paused {
                RemoteApproval::Paused
            } else if current.agent_kind == AgentKind::ClaudeCode {
                current
                    .permission_mode
                    .as_deref()
                    .map(remote_approval_for_mode)
                    .unwrap_or(RemoteApproval::Available)
            } else {
                RemoteApproval::PolicyUnknown
            };
            let update = entry.reducer.set_remote_approval(target, now_ms);
            if update.changed {
                if let Some(entry) = st.sessions.get(&key) {
                    self.publish_session_state(entry, now_ms, &now).await;
                }
            }
        }
    }

    /// Fires due session timers (`completed` -> `idle`, error latches, `stale`, `disconnected`, removal of ended
    /// sessions) and publishes the changes. Call about once a second.
    pub async fn tick(&self) {
        let mut st = self.state.lock().await;
        let now_ms = self.clock.now_ms();
        let now = format_ms(now_ms);
        let keys: Vec<String> = st.sessions.keys().cloned().collect();
        let mut remove = Vec::new();
        for key in keys {
            let Some(entry) = st.sessions.get_mut(&key) else { continue };
            let update = entry.reducer.tick(now_ms);
            if update.changed {
                if let Some(entry) = st.sessions.get(&key) {
                    self.publish_session_state(entry, now_ms, &now).await;
                }
            }
            if let Some(entry) = st.sessions.get(&key) {
                if entry
                    .ended_at
                    .as_deref()
                    .and_then(parse_ms)
                    .is_some_and(|t| now_ms - t >= ENDED_REMOVE_AFTER_MS)
                {
                    remove.push(key.clone());
                }
            }
        }
        for key in remove {
            st.sessions.remove(&key);
        }
    }

    /// The sessions for a `snapshot`: live reducers plus sessions that were stored before a restart and have not been
    /// seen since (ended less than 10 minutes ago or still open). At most `max` entries, newest activity first.
    pub async fn snapshot_sessions(&self, max: usize) -> Vec<SessionState> {
        let (mut states, known): (Vec<SessionState>, Vec<String>) = {
            let st = self.state.lock().await;
            let now_ms = self.clock.now_ms();
            let states: Vec<SessionState> = st
                .sessions
                .values()
                .map(|e| e.reducer.session_state(now_ms))
                .collect();
            let known = st.sessions.keys().cloned().collect();
            (states, known)
        };
        let cutoff = format_ms(self.clock.now_ms() - ENDED_REMOVE_AFTER_MS);
        let stored = self.db(move |s| s.list_active_sessions(&cutoff)).await.unwrap_or_default();
        for rec in stored {
            if known.contains(&rec.session_key) {
                continue;
            }
            let project = match &rec.project_key {
                Some(k) => {
                    let key = k.clone();
                    self.db(move |s| s.get_project(&key))
                        .await
                        .ok()
                        .flatten()
                        .map(|p| ProjectRef {
                            project_key: p.project_key.clone(),
                            name: p.name,
                            path_hint: Some(crate::normalize::path::path_hint(&p.path)),
                            repo: p.repo,
                            branch: p.branch,
                        })
                }
                None => None,
            }
            .unwrap_or_else(|| ProjectRef {
                project_key: "unknown".to_owned(),
                name: "알 수 없음".to_owned(),
                path_hint: None,
                repo: None,
                branch: None,
            });
            let label = agent_label(AgentKind::from_wire(&rec.agent_kind));
            states.push(rec.to_session_state(project, label));
        }
        states.sort_by(|a, b| b.last_event_at.cmp(&a.last_event_at));
        states.truncate(max);
        states
    }

    /// The focused session of the current live sessions (`snapshot.focus`).
    pub async fn focus(&self) -> Option<(String, agentnest_protocol::AgentState)> {
        let st = self.state.lock().await;
        let now_ms = self.clock.now_ms();
        let sessions: Vec<FocusSession> = st
            .sessions
            .values()
            .map(|e| {
                let s = e.reducer.session_state(now_ms);
                FocusSession {
                    session_key: s.session_key.clone(),
                    state: s.state.clone(),
                    state_since_ms: parse_ms(&s.state_since).unwrap_or(now_ms),
                    last_event_ms: parse_ms(&s.last_event_at).unwrap_or(now_ms),
                    ended: s.ended,
                }
            })
            .collect();
        let focus = resolve_focus(&sessions, LinkState::Connected, now_ms);
        let key = focus.focus_session_key?;
        let state = sessions.iter().find(|s| s.session_key == key)?.state.clone();
        Some((key, state))
    }

    /// The session state of one live session (tests, desktop).
    pub async fn session(&self, session_key: &str) -> Option<SessionState> {
        let st = self.state.lock().await;
        let now_ms = self.clock.now_ms();
        st.sessions
            .get(session_key)
            .map(|e| e.reducer.session_state(now_ms))
    }

    /// Wire helper: the JSON of a `session_state` payload.
    pub fn session_state_json(state: &SessionState) -> Value {
        serde_json::to_value(state).unwrap_or_else(|_| json!({}))
    }
}
