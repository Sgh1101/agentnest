//! Replay stream and event history (docs/storage.md `stream`, `events`; protocol.md 4.15, 8).
//!
//! * `stream` is the PC-global replay log of server-to-phone messages (`event`, `session_state`, `approval_request`,
//!   `approval_resolved`, `adapter_status`). One `seq` space for all of them; `snapshot`, `events_page`, `hosts_update`,
//!   `welcome` ... are never stored and never consume a `seq` (protocol.md 4.6).
//! * `events` is the queryable history behind `events_request` (`before_seq` is **exclusive**), with its own retention.
//!   An event row and its stream row share the same `seq`, assigned in one transaction by [`Store::append_event`].

use agentnest_protocol::{
    Actor, AgentEvent, AgentKind, AgentState, EventCategory, EventKind, EventSource, EventSummary,
    Severity,
};
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row, Transaction};
use serde_json::{json, Value};

use super::{is_constraint_violation, Store, StoreError};

/// Maximum number of `kinds` accepted by [`Store::events_page`] (protocol.md 4.15).
pub const EVENTS_KINDS_MAX: usize = 16;
/// Maximum `limit` of [`Store::events_page`] (protocol.md 4.15).
pub const EVENTS_PAGE_LIMIT_MAX: u32 = 100;

/// A message to append to the replay stream.
#[derive(Clone, Debug)]
pub struct NewStreamMessage {
    /// `event`, `session_state`, `approval_request`, `approval_resolved` or `adapter_status`.
    pub msg_type: String,
    /// Time (RFC 3339).
    pub ts: String,
    /// Related session, if any.
    pub session_key: Option<String>,
    /// `event_id` or `request_id`.
    pub ref_id: Option<String>,
    /// The wire payload, already bounded and masked.
    pub payload: Value,
    /// `approval_request` only: when the card expires (replay uses it).
    pub expires_at: Option<String>,
    /// Write the assigned `seq` into `payload["seq"]` (the `event` payload carries its own `seq`).
    pub inject_seq: bool,
}

/// A stored stream row.
#[derive(Clone, Debug, PartialEq)]
pub struct StreamRow {
    /// PC-global sequence number.
    pub seq: i64,
    /// Time.
    pub ts: String,
    /// Message type.
    pub msg_type: String,
    /// Related session.
    pub session_key: Option<String>,
    /// `event_id` / `request_id`.
    pub ref_id: Option<String>,
    /// The wire payload.
    pub payload: Value,
    /// `approval_request` only.
    pub expires_at: Option<String>,
}

/// What became of an `approval_request` that is being replayed (protocol.md 8.4: an expired or already closed request is
/// never replayed as a live card).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalReplayState {
    /// Still pending and not expired: replay the card.
    Pending,
    /// Pending but past `expires_at`: send `approval_resolved{expired}` instead.
    Expired,
    /// Closed: send `approval_resolved` with these values instead.
    Resolved {
        /// `approvals.status`.
        status: String,
        /// `approvals.outcome`.
        outcome: Option<String>,
        /// `approvals.resolved_by`.
        resolved_by: Option<String>,
        /// `approvals.resolved_at`.
        resolved_at: Option<String>,
        /// `approvals.delivery`.
        delivery: Option<String>,
        /// `approvals.observed_result`.
        observed_result: String,
    },
    /// The approval row no longer exists (pruned): treat like expired.
    Gone,
}

/// One item of a replay: the stored row plus, for `approval_request` rows, the current state of the approval.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplayItem {
    /// The stream row.
    pub row: StreamRow,
    /// `Some` only for `approval_request` rows.
    pub approval: Option<ApprovalReplayState>,
}

/// Smallest and largest `seq` in the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamBounds {
    /// Oldest stored `seq`, `None` if the stream is empty.
    pub min_seq: Option<i64>,
    /// Largest `seq` ever issued (0 if none); survives deletion of old rows.
    pub max_seq: i64,
}

/// The `welcome.resync` decision for a `hello.last_seq` (protocol.md 4.5, 8.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResyncPlan {
    /// The phone is up to date (`resync.mode = none`).
    None,
    /// Replay `from..=to` (`resync.mode = replay`).
    Replay {
        /// First `seq` to send.
        from: i64,
        /// Last `seq` to send.
        to: i64,
    },
    /// The gap is not covered (first connect, retention, or a `last_seq` from the future): send a snapshot.
    Snapshot,
}

/// Result of [`Store::append_event`].
#[derive(Clone, Debug, PartialEq)]
pub enum AppendOutcome {
    /// Stored; the event now carries its `seq`.
    Appended(Box<AgentEvent>),
    /// The `dedupe_key` was already stored; nothing changed and no `seq` was consumed.
    Duplicate,
}

/// Parameters of [`Store::events_page`].
#[derive(Clone, Debug)]
pub struct EventsQuery {
    /// Restrict to one session.
    pub session_key: Option<String>,
    /// **Exclusive** upper bound: only `seq < before_seq`.
    pub before_seq: i64,
    /// Page size, clamped to 1..=100.
    pub limit: u32,
    /// Restrict to these kinds (at most 16 are used).
    pub kinds: Vec<String>,
    /// Response byte budget (`limits.events_page_max_bytes`).
    pub max_bytes: usize,
}

/// A page of events (protocol.md 4.15).
#[derive(Clone, Debug, PartialEq)]
pub struct EventsPage {
    /// Events in ascending `seq` order.
    pub events: Vec<AgentEvent>,
    /// More (older) events exist.
    pub has_more: bool,
    /// The `before_seq` to ask for the next page (the oldest `seq` of this page) when `has_more`.
    pub next_before_seq: Option<i64>,
    /// `detail` objects were removed to fit the byte budget.
    pub detail_omitted: bool,
}

fn next_seq(tx: &Transaction<'_>) -> Result<i64, StoreError> {
    let current: Option<i64> = tx
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name='stream'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    Ok(current.unwrap_or(0) + 1)
}

fn insert_stream_row(
    tx: &Transaction<'_>,
    seq: i64,
    msg: &NewStreamMessage,
    payload: &Value,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO stream(seq, ts, msg_type, session_key, ref_id, payload_json, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            seq,
            msg.ts,
            msg.msg_type,
            msg.session_key,
            msg.ref_id,
            payload.to_string(),
            msg.expires_at
        ],
    )?;
    Ok(())
}

const EVENT_COLUMNS: &str =
    "event_id, seq, ts, session_key, agent_kind, actor_json, kind, category, severity, \
headline, detail_text, state_hint, detail_json, source_json, redacted";

fn event_from_row(r: &Row<'_>) -> rusqlite::Result<AgentEvent> {
    let actor_json: Option<String> = r.get(5)?;
    let detail_json: Option<String> = r.get(12)?;
    let source_json: String = r.get(13)?;
    let agent_kind: String = r.get(4)?;
    let kind: String = r.get(6)?;
    let category: String = r.get(7)?;
    let severity: String = r.get(8)?;
    let state_hint: Option<String> = r.get(11)?;
    let redacted: i64 = r.get(14)?;
    let bad = |what: &str, e: serde_json::Error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            format!("{what}: {e}").into(),
        )
    };
    Ok(AgentEvent {
        event_id: r.get(0)?,
        seq: Some(r.get(1)?),
        ts: r.get(2)?,
        agent_kind: AgentKind::from_wire(&agent_kind),
        session_key: r.get(3)?,
        actor: match actor_json {
            Some(j) => Some(serde_json::from_str::<Actor>(&j).map_err(|e| bad("actor_json", e))?),
            None => None,
        },
        project: None,
        kind: EventKind::from_wire(&kind),
        category: EventCategory::from_wire(&category),
        severity: Severity::from_wire(&severity),
        summary: EventSummary {
            headline: r.get(9)?,
            detail: r.get(10)?,
        },
        state_hint: state_hint.map(|s| AgentState::from_wire(&s)),
        detail: match detail_json {
            Some(j) => serde_json::from_str(&j).map_err(|e| bad("detail_json", e))?,
            None => json!({}),
        },
        source: serde_json::from_str::<EventSource>(&source_json)
            .map_err(|e| bad("source_json", e))?,
        redacted: redacted != 0,
    })
}

fn stream_bounds_conn(c: &Connection) -> Result<StreamBounds, StoreError> {
    let min_seq: Option<i64> = c.query_row("SELECT MIN(seq) FROM stream", [], |r| r.get(0))?;
    let max_seq: Option<i64> = c
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name='stream'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    Ok(StreamBounds {
        min_seq,
        max_seq: max_seq.unwrap_or(0),
    })
}

impl Store {
    /// Appends a message to the replay stream and returns its `seq`.
    pub fn stream_append(&self, msg: NewStreamMessage) -> Result<i64, StoreError> {
        self.run(move |conn| {
            let tx = conn.transaction()?;
            let seq = next_seq(&tx)?;
            let mut payload = msg.payload.clone();
            if msg.inject_seq {
                if let Value::Object(map) = &mut payload {
                    map.insert("seq".to_owned(), json!(seq));
                }
            }
            insert_stream_row(&tx, seq, &msg, &payload)?;
            tx.commit()?;
            Ok(seq)
        })
    }

    /// Stores an event: one transaction assigns the next `seq`, writes the `stream` row (`msg_type='event'`, payload =
    /// the event with its `seq`) and the `events` row. `dedupe_key` (only keys derived from a `tool_use_id`, see
    /// `normalize::dedupe`) makes a repeated hook a [`AppendOutcome::Duplicate`] instead of a second row.
    pub fn append_event(
        &self,
        event: AgentEvent,
        dedupe_key: Option<String>,
        now: &str,
    ) -> Result<AppendOutcome, StoreError> {
        let now = now.to_owned();
        let has_key = dedupe_key.is_some();
        let result = self.run(move |conn| {
            let tx = conn.transaction()?;
            let seq = next_seq(&tx)?;
            let mut event = event;
            event.seq = Some(seq);
            let payload = serde_json::to_value(&event)?;
            let msg = NewStreamMessage {
                msg_type: "event".to_owned(),
                ts: event.ts.clone(),
                session_key: Some(event.session_key.clone()),
                ref_id: Some(event.event_id.clone()),
                payload: payload.clone(),
                expires_at: None,
                inject_seq: false,
            };
            insert_stream_row(&tx, seq, &msg, &payload)?;
            let actor_json = event.actor.as_ref().map(serde_json::to_string).transpose()?;
            let detail_json = serde_json::to_string(&event.detail)?;
            let source_json = serde_json::to_string(&event.source)?;
            tx.execute(
                "INSERT INTO events(event_id, seq, ts, session_key, agent_kind, actor_json, kind, category, severity, \
                 headline, detail_text, state_hint, detail_json, source_json, redacted, dedupe_key, created_at) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                params![
                    event.event_id,
                    seq,
                    event.ts,
                    event.session_key,
                    event.agent_kind.as_str(),
                    actor_json,
                    event.kind.as_str(),
                    event.category.as_str(),
                    event.severity.as_str(),
                    event.summary.headline,
                    event.summary.detail,
                    event.state_hint.as_ref().map(|s| s.as_str().to_owned()),
                    detail_json,
                    source_json,
                    i64::from(event.redacted),
                    dedupe_key,
                    now
                ],
            )?;
            tx.commit()?;
            Ok(AppendOutcome::Appended(Box::new(event)))
        });
        match result {
            Err(e) if has_key && is_constraint_violation(&e) => Ok(AppendOutcome::Duplicate),
            other => other,
        }
    }

    /// `seq` bounds of the stream.
    pub fn stream_bounds(&self) -> Result<StreamBounds, StoreError> {
        self.read(stream_bounds_conn)
    }

    /// The resync decision for `hello.last_seq`. `last_seq <= 0` (first connect) and a `last_seq` ahead of the PC (a
    /// database that was reset) both yield [`ResyncPlan::Snapshot`]; so does a gap that retention has already deleted.
    pub fn plan_resync(&self, last_seq: i64) -> Result<ResyncPlan, StoreError> {
        let b = self.stream_bounds()?;
        if last_seq <= 0 || last_seq > b.max_seq {
            return Ok(ResyncPlan::Snapshot);
        }
        if last_seq == b.max_seq {
            return Ok(ResyncPlan::None);
        }
        let Some(min) = b.min_seq else {
            return Ok(ResyncPlan::Snapshot);
        };
        if last_seq + 1 >= min {
            Ok(ResyncPlan::Replay {
                from: last_seq + 1,
                to: b.max_seq,
            })
        } else {
            Ok(ResyncPlan::Snapshot)
        }
    }

    /// `SELECT ... FROM stream WHERE seq > ? ORDER BY seq` (at most `limit` rows), with the current approval state joined
    /// onto `approval_request` rows so the link layer can replace expired or closed cards by `approval_resolved`
    /// (protocol.md 8.4).
    pub fn stream_replay_since(
        &self,
        after_seq: i64,
        limit: u32,
        now: &str,
    ) -> Result<Vec<ReplayItem>, StoreError> {
        let now = now.to_owned();
        self.read(move |c| {
            let mut stmt = c.prepare(
                "SELECT s.seq, s.ts, s.msg_type, s.session_key, s.ref_id, s.payload_json, s.expires_at, \
                 a.status, a.outcome, a.resolved_by, a.resolved_at, a.delivery, a.observed_result \
                 FROM stream s LEFT JOIN approvals a ON s.msg_type='approval_request' AND a.request_id = s.ref_id \
                 WHERE s.seq > ?1 ORDER BY s.seq LIMIT ?2",
            )?;
            let mut rows = stmt.query(params![after_seq, limit.min(100_000)])?;
            let mut out = Vec::new();
            while let Some(r) = rows.next()? {
                let msg_type: String = r.get(2)?;
                let payload_json: String = r.get(5)?;
                let payload: Value = serde_json::from_str(&payload_json)?;
                let expires_at: Option<String> = r.get(6)?;
                let status: Option<String> = r.get(7)?;
                let approval = if msg_type == "approval_request" {
                    Some(match status {
                        None => ApprovalReplayState::Gone,
                        Some(st) if st != "pending" => ApprovalReplayState::Resolved {
                            status: st,
                            outcome: r.get(8)?,
                            resolved_by: r.get(9)?,
                            resolved_at: r.get(10)?,
                            delivery: r.get(11)?,
                            observed_result: r.get::<_, Option<String>>(12)?.unwrap_or_else(|| "unknown".to_owned()),
                        },
                        Some(_) => {
                            if expires_at.as_deref().is_some_and(|e| e <= now.as_str()) {
                                ApprovalReplayState::Expired
                            } else {
                                ApprovalReplayState::Pending
                            }
                        }
                    })
                } else {
                    None
                };
                out.push(ReplayItem {
                    row: StreamRow {
                        seq: r.get(0)?,
                        ts: r.get(1)?,
                        msg_type,
                        session_key: r.get(3)?,
                        ref_id: r.get(4)?,
                        payload,
                        expires_at,
                    },
                    approval,
                });
            }
            Ok(out)
        })
    }

    /// `events_request`: `SELECT ... FROM events WHERE seq < :before_seq [AND session_key = :k] [AND kind IN (...)]
    /// ORDER BY seq DESC LIMIT :limit`, then the byte budget: first the `detail` of every event is dropped
    /// (`detail_omitted`), then the oldest events are dropped (`has_more`).
    pub fn events_page(&self, q: &EventsQuery) -> Result<EventsPage, StoreError> {
        let q = q.clone();
        self.read(move |c| {
            let limit = q.limit.clamp(1, EVENTS_PAGE_LIMIT_MAX) as usize;
            let kinds: Vec<&String> = q.kinds.iter().take(EVENTS_KINDS_MAX).collect();
            let mut sql = format!("SELECT {EVENT_COLUMNS} FROM events WHERE seq < ?");
            let mut args: Vec<rusqlite::types::Value> = vec![q.before_seq.into()];
            if let Some(k) = &q.session_key {
                sql.push_str(" AND session_key = ?");
                args.push(k.clone().into());
            }
            if !kinds.is_empty() {
                sql.push_str(" AND kind IN (");
                sql.push_str(&vec!["?"; kinds.len()].join(","));
                sql.push(')');
                for k in &kinds {
                    args.push((*k).clone().into());
                }
            }
            sql.push_str(" ORDER BY seq DESC LIMIT ?");
            args.push(((limit + 1) as i64).into());
            let mut stmt = c.prepare(&sql)?;
            let rows = stmt.query_map(params_from_iter(args), event_from_row)?;
            let mut events: Vec<AgentEvent> = rows.collect::<Result<_, _>>()?;
            let mut has_more = events.len() > limit;
            events.truncate(limit);
            events.reverse(); // ascending
            let size =
                |e: &[AgentEvent]| serde_json::to_vec(e).map(|v| v.len()).unwrap_or(usize::MAX);
            let mut detail_omitted = false;
            if size(&events) > q.max_bytes {
                for e in &mut events {
                    e.detail = json!({});
                }
                detail_omitted = true;
            }
            while size(&events) > q.max_bytes && events.len() > 1 {
                events.remove(0); // the oldest
                has_more = true;
            }
            let next_before_seq = if has_more {
                events.first().and_then(|e| e.seq)
            } else {
                None
            };
            Ok(EventsPage {
                events,
                has_more,
                next_before_seq,
                detail_omitted,
            })
        })
    }

    /// The newest `limit` events in ascending `seq` order (snapshot `recent_events`).
    pub fn recent_events(&self, limit: u32) -> Result<Vec<AgentEvent>, StoreError> {
        self.read(move |c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {EVENT_COLUMNS} FROM events ORDER BY seq DESC LIMIT ?1"
            ))?;
            let rows = stmt.query_map([limit.min(1000)], event_from_row)?;
            let mut v: Vec<AgentEvent> = rows.collect::<Result<_, _>>()?;
            v.reverse();
            Ok(v)
        })
    }

    /// The newest `limit` events with severity `warning` or `error` (snapshot `recent_errors`), ascending.
    pub fn recent_errors(&self, limit: u32) -> Result<Vec<AgentEvent>, StoreError> {
        self.read(move |c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {EVENT_COLUMNS} FROM events WHERE severity IN ('warning','error') ORDER BY seq DESC LIMIT ?1"
            ))?;
            let rows = stmt.query_map([limit.min(1000)], event_from_row)?;
            let mut v: Vec<AgentEvent> = rows.collect::<Result<_, _>>()?;
            v.reverse();
            Ok(v)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::timers::format_ms;
    use crate::store::approvals::testing::{new_approval, resolve_request};
    use agentnest_protocol::SourceChannel;
    use std::collections::BTreeMap;

    const T0: i64 = 1_760_000_000_000;

    pub(crate) fn test_event(id: u32, session: &str, kind: &str, severity: Severity) -> AgentEvent {
        let kind = EventKind::from_wire(kind);
        AgentEvent {
            event_id: format!("01929f1a-7a00-7b3c-9e4d-{id:012x}"),
            seq: None,
            ts: format_ms(T0 + i64::from(id)),
            agent_kind: AgentKind::ClaudeCode,
            session_key: session.to_owned(),
            actor: Some(Actor {
                agent_id: Some("a1".into()),
                agent_type: Some("Explore".into()),
                is_subagent: true,
            }),
            project: None,
            category: kind.category().unwrap_or(EventCategory::Notification),
            kind,
            severity,
            summary: EventSummary {
                headline: format!("헤드라인 {id}"),
                detail: Some("상세".to_owned()),
            },
            state_hint: Some(AgentState::Working),
            detail: json!({"tool_name": "Bash", "note": "x".repeat(100)}),
            source: EventSource {
                channel: SourceChannel::ClaudeCodeHookHttp,
                native_event: Some("PreToolUse".to_owned()),
                native_ids: BTreeMap::from([("tool_use_id".to_owned(), format!("toolu_{id}"))]),
            },
            redacted: id.is_multiple_of(2),
        }
    }

    pub(crate) fn append(s: &Store, id: u32, session: &str, kind: &str) -> i64 {
        match s
            .append_event(
                test_event(id, session, kind, Severity::Info),
                Some(format!("k{id}")),
                &format_ms(T0),
            )
            .unwrap()
        {
            AppendOutcome::Appended(e) => e.seq.unwrap(),
            AppendOutcome::Duplicate => panic!("unexpected duplicate"),
        }
    }

    #[test]
    fn append_event_assigns_gapless_increasing_seq_and_round_trips() {
        let s = Store::open_in_memory().unwrap();
        let seqs: Vec<i64> = (1..=5)
            .map(|i| append(&s, i, "claude_code:a", "tool_started"))
            .collect();
        assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
        let page = s
            .events_page(&EventsQuery {
                session_key: None,
                before_seq: 100,
                limit: 10,
                kinds: vec![],
                max_bytes: 1 << 20,
            })
            .unwrap();
        assert_eq!(page.events.len(), 5);
        let got = &page.events[2];
        let mut want = test_event(3, "claude_code:a", "tool_started", Severity::Info);
        want.seq = Some(3);
        assert_eq!(
            got, &want,
            "everything but the project survives the round trip"
        );
        // the stream row carries the same seq inside the payload
        let replay = s.stream_replay_since(2, 100, &format_ms(T0)).unwrap();
        assert_eq!(replay.len(), 3);
        assert_eq!(replay[0].row.seq, 3);
        assert_eq!(replay[0].row.payload["seq"], 3);
        assert_eq!(replay[0].row.msg_type, "event");
        assert_eq!(
            replay[0].row.ref_id.as_deref(),
            Some(want.event_id.as_str())
        );
        assert!(replay[0].approval.is_none());
    }

    #[test]
    fn duplicate_dedupe_keys_do_not_consume_a_seq() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(append(&s, 1, "s", "tool_started"), 1);
        let dup = s
            .append_event(
                test_event(2, "s", "tool_started", Severity::Info),
                Some("k1".to_owned()),
                &format_ms(T0),
            )
            .unwrap();
        assert_eq!(dup, AppendOutcome::Duplicate);
        assert_eq!(
            append(&s, 3, "s", "tool_started"),
            2,
            "no gap after the duplicate"
        );
        assert_eq!(
            s.stream_bounds().unwrap(),
            StreamBounds {
                min_seq: Some(1),
                max_seq: 2
            }
        );
        // events without a key are never deduplicated by the database
        for i in 10..13 {
            let r = s
                .append_event(
                    test_event(i, "s", "idle", Severity::Info),
                    None,
                    &format_ms(T0),
                )
                .unwrap();
            assert!(matches!(r, AppendOutcome::Appended(_)));
        }
        // a duplicate event_id without a key is a real error
        let r = s.append_event(
            test_event(10, "s", "idle", Severity::Info),
            None,
            &format_ms(T0),
        );
        assert!(r.is_err());
    }

    #[test]
    fn stream_append_injects_seq_and_shares_the_counter() {
        let s = Store::open_in_memory().unwrap();
        let a = s
            .stream_append(NewStreamMessage {
                msg_type: "session_state".into(),
                ts: format_ms(T0),
                session_key: Some("s".into()),
                ref_id: None,
                payload: json!({"x": 1}),
                expires_at: None,
                inject_seq: false,
            })
            .unwrap();
        let e = append(&s, 1, "s", "idle");
        let b = s
            .stream_append(NewStreamMessage {
                msg_type: "approval_resolved".into(),
                ts: format_ms(T0),
                session_key: None,
                ref_id: Some("ar_1".into()),
                payload: json!({"request_id": "ar_1"}),
                expires_at: None,
                inject_seq: true,
            })
            .unwrap();
        assert_eq!((a, e, b), (1, 2, 3));
        let rows = s.stream_replay_since(0, 10, &format_ms(T0)).unwrap();
        assert_eq!(rows[0].row.payload.get("seq"), None);
        assert_eq!(rows[2].row.payload["seq"], 3);
    }

    #[test]
    fn replay_replaces_expired_and_closed_approval_requests() {
        let s = Store::open_in_memory().unwrap();
        for (id, ttl) in [
            ("ar_live", 120_000),
            ("ar_old", 1_000),
            ("ar_done", 120_000),
            ("ar_gone", 120_000),
        ] {
            s.insert_approval(new_approval(id, "s", T0, ttl), 0)
                .unwrap();
            s.stream_append(NewStreamMessage {
                msg_type: "approval_request".into(),
                ts: format_ms(T0),
                session_key: Some("s".into()),
                ref_id: Some(id.into()),
                payload: json!({"request_id": id}),
                expires_at: Some(format_ms(T0 + ttl)),
                inject_seq: false,
            })
            .unwrap();
        }
        s.resolve_approval_conditional(resolve_request("ar_done", "d1", T0 + 500))
            .unwrap();
        s.run(|c| Ok(c.execute("DELETE FROM approvals WHERE request_id='ar_gone'", [])?))
            .unwrap();
        let items = s
            .stream_replay_since(0, 100, &format_ms(T0 + 10_000))
            .unwrap();
        let state = |i: usize| items[i].approval.clone().unwrap();
        assert_eq!(state(0), ApprovalReplayState::Pending);
        assert_eq!(state(1), ApprovalReplayState::Expired);
        assert!(
            matches!(state(2), ApprovalReplayState::Resolved { ref status, ref outcome, ref resolved_by, .. } if status == "resolved" && outcome.as_deref() == Some("allowed") && resolved_by.as_deref() == Some("desktop"))
        );
        assert_eq!(state(3), ApprovalReplayState::Gone);
    }

    #[test]
    fn resync_plans() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(
            s.plan_resync(0).unwrap(),
            ResyncPlan::Snapshot,
            "first connect"
        );
        assert_eq!(
            s.plan_resync(5).unwrap(),
            ResyncPlan::Snapshot,
            "empty stream, phone ahead"
        );
        for i in 1..=10 {
            append(&s, i, "s", "idle");
        }
        assert_eq!(s.plan_resync(10).unwrap(), ResyncPlan::None);
        assert_eq!(
            s.plan_resync(7).unwrap(),
            ResyncPlan::Replay { from: 8, to: 10 }
        );
        assert_eq!(
            s.plan_resync(11).unwrap(),
            ResyncPlan::Snapshot,
            "phone ahead of the PC (database was reset)"
        );
        assert_eq!(s.plan_resync(-3).unwrap(), ResyncPlan::Snapshot);
        // retention removed the first 6 rows: last_seq 3 is outside the window
        s.run(|c| Ok(c.execute("DELETE FROM stream WHERE seq <= 6", [])?))
            .unwrap();
        assert_eq!(s.plan_resync(3).unwrap(), ResyncPlan::Snapshot);
        assert_eq!(
            s.plan_resync(6).unwrap(),
            ResyncPlan::Replay { from: 7, to: 10 },
            "the next row exists, no gap"
        );
        assert_eq!(
            s.plan_resync(5).unwrap(),
            ResyncPlan::Snapshot,
            "row 6 is gone: the gap is not covered"
        );
        // the counter survives an empty stream
        s.run(|c| Ok(c.execute("DELETE FROM stream", [])?)).unwrap();
        assert_eq!(
            s.stream_bounds().unwrap(),
            StreamBounds {
                min_seq: None,
                max_seq: 10
            }
        );
        assert_eq!(s.plan_resync(10).unwrap(), ResyncPlan::None);
        assert_eq!(s.plan_resync(9).unwrap(), ResyncPlan::Snapshot);
        assert_eq!(
            append(&s, 99, "s", "idle"),
            11,
            "seq keeps counting after retention emptied the stream"
        );
    }

    #[test]
    fn events_page_boundaries_filters_and_limits() {
        let s = Store::open_in_memory().unwrap();
        for i in 1..=30u32 {
            let session = if i % 2 == 0 { "s_even" } else { "s_odd" };
            let kind = if i % 3 == 0 {
                "turn_failed"
            } else {
                "tool_started"
            };
            append(&s, i, session, kind);
        }
        let q = |before: i64, limit: u32, session: Option<&str>, kinds: &[&str]| EventsQuery {
            session_key: session.map(str::to_owned),
            before_seq: before,
            limit,
            kinds: kinds.iter().map(|k| (*k).to_owned()).collect(),
            max_bytes: 1 << 20,
        };
        // exclusive bound
        let p = s.events_page(&q(11, 5, None, &[])).unwrap();
        assert_eq!(
            p.events.iter().map(|e| e.seq.unwrap()).collect::<Vec<_>>(),
            vec![6, 7, 8, 9, 10]
        );
        assert!(p.has_more);
        assert_eq!(p.next_before_seq, Some(6));
        // the next page continues exactly there
        let p2 = s.events_page(&q(6, 5, None, &[])).unwrap();
        assert_eq!(p2.events.last().unwrap().seq, Some(5));
        // the first page has no more
        let p = s.events_page(&q(4, 50, None, &[])).unwrap();
        assert_eq!(p.events.len(), 3);
        assert!(!p.has_more && p.next_before_seq.is_none());
        // session filter
        let p = s.events_page(&q(100, 50, Some("s_even"), &[])).unwrap();
        assert_eq!(p.events.len(), 15);
        assert!(p.events.iter().all(|e| e.session_key == "s_even"));
        // kinds filter (unknown kinds are simply not matched)
        let p = s
            .events_page(&q(100, 50, None, &["turn_failed", "does_not_exist"]))
            .unwrap();
        assert_eq!(p.events.len(), 10);
        assert!(p.events.iter().all(|e| e.kind == EventKind::TurnFailed));
        // limit is clamped to 100 and to at least 1
        let p = s.events_page(&q(100, 10_000, None, &[])).unwrap();
        assert_eq!(p.events.len(), 30);
        let p = s.events_page(&q(100, 0, None, &[])).unwrap();
        assert_eq!(p.events.len(), 1);
        // more than 16 kinds: only the first 16 are used
        let many: Vec<String> = (0..20).map(|i| format!("kind_{i}")).collect();
        let mut query = q(100, 5, None, &[]);
        query.kinds = many;
        assert!(s.events_page(&query).unwrap().events.is_empty());
        assert_eq!(EVENTS_KINDS_MAX, 16);
    }

    #[test]
    fn events_page_byte_budget_drops_detail_then_rows() {
        let s = Store::open_in_memory().unwrap();
        for i in 1..=20u32 {
            append(&s, i, "s", "tool_started");
        }
        let full = s
            .events_page(&EventsQuery {
                session_key: None,
                before_seq: 100,
                limit: 20,
                kinds: vec![],
                max_bytes: 1 << 20,
            })
            .unwrap();
        let full_size = serde_json::to_vec(&full.events).unwrap().len();
        // a budget slightly below the full size: details go first, all rows stay
        let mut no_detail = full.events.clone();
        for e in &mut no_detail {
            e.detail = json!({});
        }
        let nd_size = serde_json::to_vec(&no_detail).unwrap().len();
        assert!(nd_size < full_size);
        let p = s
            .events_page(&EventsQuery {
                session_key: None,
                before_seq: 100,
                limit: 20,
                kinds: vec![],
                max_bytes: nd_size,
            })
            .unwrap();
        assert!(p.detail_omitted && !p.has_more);
        assert_eq!(p.events.len(), 20);
        assert!(p.events.iter().all(|e| e.detail == json!({})));
        // a much smaller budget: the oldest rows are dropped and has_more is set
        let p = s
            .events_page(&EventsQuery {
                session_key: None,
                before_seq: 100,
                limit: 20,
                kinds: vec![],
                max_bytes: nd_size / 2,
            })
            .unwrap();
        assert!(p.detail_omitted && p.has_more);
        assert!(p.events.len() < 20 && !p.events.is_empty());
        assert_eq!(
            p.events.last().unwrap().seq,
            Some(20),
            "the newest rows are kept"
        );
        assert_eq!(p.next_before_seq, p.events.first().and_then(|e| e.seq));
        assert!(serde_json::to_vec(&p.events).unwrap().len() <= nd_size / 2 || p.events.len() == 1);
        // no events: empty page, no more
        let p = s
            .events_page(&EventsQuery {
                session_key: Some("none".into()),
                before_seq: 100,
                limit: 5,
                kinds: vec![],
                max_bytes: 10,
            })
            .unwrap();
        assert!(p.events.is_empty() && !p.has_more);
    }

    #[test]
    fn snapshot_helpers() {
        let s = Store::open_in_memory().unwrap();
        for i in 1..=6u32 {
            let sev = if i % 3 == 0 {
                Severity::Error
            } else {
                Severity::Info
            };
            s.append_event(
                test_event(i, "s", "tool_started", sev),
                None,
                &format_ms(T0),
            )
            .unwrap();
        }
        let recent = s.recent_events(3).unwrap();
        assert_eq!(
            recent.iter().map(|e| e.seq.unwrap()).collect::<Vec<_>>(),
            vec![4, 5, 6]
        );
        let errors = s.recent_errors(5).unwrap();
        assert_eq!(
            errors.iter().map(|e| e.seq.unwrap()).collect::<Vec<_>>(),
            vec![3, 6]
        );
    }
}

/// Helpers shared with the retention tests.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    use crate::state::timers::format_ms;

    /// A stream message with a payload of roughly `bytes` bytes at `ts_ms`.
    pub fn stream_message(ts_ms: i64, bytes: usize) -> NewStreamMessage {
        NewStreamMessage {
            msg_type: "session_state".to_owned(),
            ts: format_ms(ts_ms),
            session_key: Some("s".to_owned()),
            ref_id: None,
            payload: json!({ "pad": "x".repeat(bytes) }),
            expires_at: None,
            inject_seq: false,
        }
    }

    /// Appends an event of `kind` at `ts_ms` (no dedupe key).
    pub fn append_event_at(s: &Store, id: u32, session: &str, kind: &str, ts_ms: i64) {
        let mut e = super::tests::test_event(id, session, kind, Severity::Info);
        e.ts = format_ms(ts_ms);
        s.append_event(e, None, &format_ms(ts_ms)).unwrap();
    }
}
