//! Retention rules (storage.md 3). [`run`] is called at start-up and hourly by the daemon.
//!
//! **Deletion independence**: no rule deletes rows of another table. `sessions` can be deleted while their `approvals`,
//! `decisions`, `approval_audit`, `review_findings` and `events` stay until *their own* rule applies (there is no foreign
//! key to cascade through, storage.md "FK 원칙"). This is what keeps the evidence of "what was approved and what
//! happened" alive for 365 days.
//!
//! | data | rule |
//! | --- | --- |
//! | `events` | older than 14 days (30 days for failures, approvals, reviews and `turn_completed`) or beyond 100,000 rows; the newest 200 per session always stay |
//! | `stream` | `max(48 h, newest 10,000 rows)`, then a 64 MiB payload cap (which may shorten the window) |
//! | `approvals.details_json` | NULL after 7 days; rows deleted after 90 days (never while `pending`) |
//! | `decisions`, `approval_audit`, `audit_log` | 365 days |
//! | `sessions` | 30 days after `ended_at` |
//! | `review_findings` | 180 days |
//! | `pairings` | 24 hours after expiry |
//! | `devices` | 365 days after revocation (unless still referenced) |
//!
//! **Clock-jump guard.** Every age rule compares stored timestamps with "now". A system clock that jumps forward (a wrong
//! RTC, a manual change, a VM resume) would make everything look ancient and delete the evidence of what was approved.
//! The job therefore never uses a "now" later than **the newest timestamp already stored plus
//! [`RetentionConfig::max_clock_advance_days`]** (2 days): a ten-year jump deletes what a two-day advance would, which is
//! nothing the normal schedule would not delete anyway. When data really stops arriving (the app idle for weeks) the
//! cleanup simply waits; the first new row brings it up to date. Limit: rows stamped *by* a wrong clock raise the
//! "newest" themselves - this guard bounds a single jump, it cannot recognise a clock that has been wrong from the start.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::json;

use super::approvals::{insert_audit_log_tx, NewAuditLog};
use super::{Store, StoreError};
use crate::state::timers::format_ms;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const HOUR_MS: i64 = 60 * 60 * 1000;

/// The numbers of storage.md 3. `Default` is the documented configuration.
#[derive(Clone, Debug)]
pub struct RetentionConfig {
    /// `events` older than this are deleted (days).
    pub events_days: i64,
    /// Same for failures, approvals, reviews and `turn_completed` (days).
    pub events_important_days: i64,
    /// `events` beyond this many rows are deleted, oldest first.
    pub events_max_rows: i64,
    /// The newest this-many events per session are kept regardless of age.
    pub events_keep_per_session: i64,
    /// `stream` rows younger than this are kept (hours).
    pub stream_min_age_hours: i64,
    /// The newest this-many `stream` rows are kept regardless of age.
    pub stream_min_rows: i64,
    /// Cap of the summed `stream.payload_json` size (bytes).
    pub stream_max_bytes: i64,
    /// `approvals.details_json` is cleared after this (days).
    pub approval_details_days: i64,
    /// Non-pending `approvals` rows are deleted after this (days).
    pub approvals_days: i64,
    /// `decisions`, `approval_audit` and `audit_log` are deleted after this (days).
    pub audit_days: i64,
    /// Ended `sessions` are deleted after this (days).
    pub sessions_days: i64,
    /// `review_findings` are deleted after this (days).
    pub review_findings_days: i64,
    /// Expired `pairings` are deleted after this (hours).
    pub pairings_hours: i64,
    /// Revoked `devices` are deleted after this (days).
    pub devices_revoked_days: i64,
    /// If set, devices not seen for this many days are revoked (`inactive_90d`); off by default (a setting).
    pub auto_revoke_inactive_days: Option<i64>,
    /// Above this database size the oldest `events` are deleted in addition (bytes in use).
    pub db_max_bytes: i64,
    /// The job never works with a "now" later than the newest stored timestamp plus this many days (clock-jump guard,
    /// see the module docs).
    pub max_clock_advance_days: i64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            events_days: 14,
            events_important_days: 30,
            events_max_rows: 100_000,
            events_keep_per_session: 200,
            stream_min_age_hours: 48,
            stream_min_rows: 10_000,
            stream_max_bytes: 64 * 1024 * 1024,
            approval_details_days: 7,
            approvals_days: 90,
            audit_days: 365,
            sessions_days: 30,
            review_findings_days: 180,
            pairings_hours: 24,
            devices_revoked_days: 365,
            auto_revoke_inactive_days: None,
            db_max_bytes: 500 * 1024 * 1024,
            max_clock_advance_days: 2,
        }
    }
}

/// How many rows each rule removed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct RetentionReport {
    pub events_deleted: usize,
    pub events_deleted_for_size: usize,
    pub stream_deleted: usize,
    pub stream_deleted_for_size: usize,
    pub approval_details_cleared: usize,
    pub approvals_deleted: usize,
    pub decisions_deleted: usize,
    pub approval_audit_deleted: usize,
    pub audit_log_deleted: usize,
    pub sessions_deleted: usize,
    pub review_findings_deleted: usize,
    pub pairings_deleted: usize,
    pub devices_deleted: usize,
    pub devices_auto_revoked: usize,
}

impl RetentionReport {
    /// Total number of rows removed or changed.
    pub fn total(&self) -> usize {
        self.events_deleted
            + self.events_deleted_for_size
            + self.stream_deleted
            + self.stream_deleted_for_size
            + self.approval_details_cleared
            + self.approvals_deleted
            + self.decisions_deleted
            + self.approval_audit_deleted
            + self.audit_log_deleted
            + self.sessions_deleted
            + self.review_findings_deleted
            + self.pairings_deleted
            + self.devices_deleted
            + self.devices_auto_revoked
    }
}

/// The newest timestamp (ms) stored anywhere that records when something happened; `None` for an empty database.
fn newest_timestamp_ms(tx: &rusqlite::Transaction<'_>) -> Result<Option<i64>, StoreError> {
    const SOURCES: [(&str, &str); 9] = [
        ("events", "ts"),
        ("stream", "ts"),
        ("audit_log", "ts"),
        ("approval_audit", "ts"),
        ("decisions", "received_at"),
        ("approvals", "created_at"),
        ("sessions", "started_at"),
        ("pairings", "created_at"),
        ("devices", "paired_at"),
    ];
    let mut newest: Option<i64> = None;
    for (table, column) in SOURCES {
        let max: Option<String> =
            tx.query_row(&format!("SELECT MAX({column}) FROM {table}"), [], |r| r.get(0))?;
        if let Some(ms) = max.as_deref().and_then(crate::state::timers::parse_ms) {
            newest = Some(newest.map_or(ms, |n| n.max(ms)));
        }
    }
    Ok(newest)
}

/// Applies every retention rule at `now_ms` in one transaction and records `audit_log(retention_pruned)` if anything
/// changed. Time is a parameter so tests can move it by days.
pub fn run(
    conn: &mut Connection,
    now_ms: i64,
    cfg: &RetentionConfig,
) -> Result<RetentionReport, StoreError> {
    let tx = conn.transaction()?;
    let mut rep = RetentionReport::default();
    // clock-jump guard: the age rules never see a "now" far beyond the newest thing that was ever stored
    let real_now_ms = now_ms;
    let now_ms = match newest_timestamp_ms(&tx)? {
        Some(newest) => {
            let cap = newest.saturating_add(cfg.max_clock_advance_days.saturating_mul(DAY_MS));
            if now_ms > cap {
                tracing::warn!(
                    jump_days = (now_ms - newest) / DAY_MS,
                    "retention: the clock is far ahead of the newest stored data; using a bounded time"
                );
            }
            now_ms.min(cap)
        }
        None => now_ms,
    };
    let at = |ms: i64| format_ms(now_ms - ms);

    // events: age (kind dependent) except the newest N per session
    rep.events_deleted = tx.execute(
        "DELETE FROM events WHERE rowid IN ( \
           SELECT rowid FROM ( \
             SELECT rowid, ts, kind, ROW_NUMBER() OVER (PARTITION BY session_key ORDER BY seq DESC) AS rn FROM events \
           ) WHERE rn > ?1 AND ts < CASE \
               WHEN kind IN ('turn_failed','agent_error','test_failed','turn_completed') \
                 OR kind LIKE 'approval%' OR kind LIKE 'review%' THEN ?2 ELSE ?3 END)",
        params![
            cfg.events_keep_per_session,
            at(cfg.events_important_days * DAY_MS),
            at(cfg.events_days * DAY_MS)
        ],
    )?;
    // events: row cap (oldest first), again sparing the newest N per session
    rep.events_deleted += tx.execute(
        "DELETE FROM events WHERE rowid IN ( \
           SELECT rowid FROM ( \
             SELECT rowid, ROW_NUMBER() OVER (ORDER BY seq DESC) AS g, \
                    ROW_NUMBER() OVER (PARTITION BY session_key ORDER BY seq DESC) AS s FROM events \
           ) WHERE g > ?1 AND s > ?2)",
        params![cfg.events_max_rows, cfg.events_keep_per_session],
    )?;

    // stream: only rows that are older than the window AND outside the newest N rows
    let nth_newest: Option<i64> = tx
        .query_row(
            "SELECT seq FROM stream ORDER BY seq DESC LIMIT 1 OFFSET ?1",
            [cfg.stream_min_rows.max(1) - 1],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(threshold) = nth_newest {
        rep.stream_deleted = tx.execute(
            "DELETE FROM stream WHERE ts < ?1 AND seq < ?2",
            params![at(cfg.stream_min_age_hours * HOUR_MS), threshold],
        )?;
    }
    // stream: size cap. Rows from the oldest up to the first one whose cumulative size (counted from the newest) exceeds
    // the cap are deleted, so the window can become shorter than 48 hours (the phone then gets a snapshot).
    let cut: Option<i64> = tx
        .query_row(
            "SELECT seq FROM (SELECT seq, SUM(LENGTH(payload_json)) OVER (ORDER BY seq DESC) AS cum FROM stream) \
             WHERE cum > ?1 ORDER BY seq DESC LIMIT 1",
            [cfg.stream_max_bytes],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(cut_seq) = cut {
        rep.stream_deleted_for_size =
            tx.execute("DELETE FROM stream WHERE seq <= ?1", [cut_seq])?;
    }

    // approvals
    rep.approval_details_cleared = tx.execute(
        "UPDATE approvals SET details_json=NULL WHERE details_json IS NOT NULL AND status != 'pending' AND created_at < ?1",
        [at(cfg.approval_details_days * DAY_MS)],
    )?;
    rep.approvals_deleted = tx.execute(
        "DELETE FROM approvals WHERE status != 'pending' AND created_at < ?1",
        [at(cfg.approvals_days * DAY_MS)],
    )?;

    // evidence: decisions, approval audit, audit log
    let audit_cut = at(cfg.audit_days * DAY_MS);
    rep.decisions_deleted =
        tx.execute("DELETE FROM decisions WHERE received_at < ?1", [&audit_cut])?;
    rep.approval_audit_deleted =
        tx.execute("DELETE FROM approval_audit WHERE ts < ?1", [&audit_cut])?;
    rep.audit_log_deleted = tx.execute("DELETE FROM audit_log WHERE ts < ?1", [&audit_cut])?;

    // sessions: nothing else is deleted with them
    rep.sessions_deleted = tx.execute(
        "DELETE FROM sessions WHERE ended_at IS NOT NULL AND ended_at < ?1",
        [at(cfg.sessions_days * DAY_MS)],
    )?;
    rep.review_findings_deleted = tx.execute(
        "DELETE FROM review_findings WHERE ts < ?1",
        [at(cfg.review_findings_days * DAY_MS)],
    )?;

    // pairings and devices
    rep.pairings_deleted = tx.execute(
        "DELETE FROM pairings WHERE expires_at < ?1",
        [at(cfg.pairings_hours * HOUR_MS)],
    )?;
    if let Some(days) = cfg.auto_revoke_inactive_days {
        rep.devices_auto_revoked = tx.execute(
            "UPDATE devices SET revoked_at=?1, revoked_reason='inactive_90d' \
             WHERE revoked_at IS NULL AND COALESCE(last_seen_at, paired_at) < ?2",
            params![format_ms(real_now_ms), at(days * DAY_MS)],
        )?;
    }
    rep.devices_deleted = tx.execute(
        "DELETE FROM devices WHERE revoked_at IS NOT NULL AND revoked_at < ?1 \
         AND NOT EXISTS (SELECT 1 FROM approvals a WHERE a.resolved_device_id = devices.device_id) \
         AND NOT EXISTS (SELECT 1 FROM pairings p WHERE p.device_id = devices.device_id)",
        [at(cfg.devices_revoked_days * DAY_MS)],
    )?;

    // database size: delete the oldest events in batches while the data in use is above the cap
    for _ in 0..20 {
        let used: i64 = tx.query_row(
            "SELECT (page_count - freelist_count) * page_size FROM pragma_page_count(), pragma_freelist_count(), pragma_page_size()",
            [],
            |r| r.get(0),
        )?;
        if used <= cfg.db_max_bytes {
            break;
        }
        let n = tx.execute(
            "DELETE FROM events WHERE rowid IN (SELECT rowid FROM events ORDER BY seq LIMIT 5000)",
            [],
        )?;
        rep.events_deleted_for_size += n;
        if n == 0 {
            break;
        }
    }

    if rep.total() > 0 {
        insert_audit_log_tx(
            &tx,
            &NewAuditLog {
                ts: format_ms(real_now_ms),
                actor: "system".to_owned(),
                action: "retention_pruned".to_owned(),
                target: None,
                details_json: Some(
                    json!({
                        "events": rep.events_deleted + rep.events_deleted_for_size,
                        "stream": rep.stream_deleted + rep.stream_deleted_for_size,
                        "approval_details_cleared": rep.approval_details_cleared,
                        "approvals": rep.approvals_deleted,
                        "decisions": rep.decisions_deleted,
                        "approval_audit": rep.approval_audit_deleted,
                        "audit_log": rep.audit_log_deleted,
                        "sessions": rep.sessions_deleted,
                        "review_findings": rep.review_findings_deleted,
                        "pairings": rep.pairings_deleted,
                        "devices": rep.devices_deleted,
                    })
                    .to_string(),
                ),
            },
        )?;
    }
    tx.commit()?;
    Ok(rep)
}

impl Store {
    /// Runs the retention job at `now_ms`.
    pub fn run_retention(
        &self,
        now_ms: i64,
        cfg: &RetentionConfig,
    ) -> Result<RetentionReport, StoreError> {
        let cfg = cfg.clone();
        self.run(move |c| run(c, now_ms, &cfg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::approvals::testing::{new_approval, resolve_request};
    use crate::store::approvals::{NewApprovalAudit, NewDecision};
    use crate::store::sessions::{NewReviewFinding, SessionExtras, SessionRecord};
    use crate::store::stream::tests_support::{append_event_at, stream_message};
    use serde_json::json;

    const T0: i64 = 1_760_000_000_000;

    /// The documented numbers without the clock-jump guard: these tests move "now" by days on purpose.
    fn unguarded() -> RetentionConfig {
        RetentionConfig {
            max_clock_advance_days: 1_000_000,
            ..RetentionConfig::default()
        }
    }

    fn count(s: &Store, table: &str) -> i64 {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        s.run(move |c| Ok(c.query_row(&sql, [], |r| r.get(0))?))
            .unwrap()
    }

    fn session_record(key: &str, ended_ms: Option<i64>) -> SessionRecord {
        let mut r = SessionRecord::from_state(
            &crate::state::reducer::SessionReducer::new(
                key,
                agentnest_protocol::AgentKind::ClaudeCode,
                T0,
            )
            .session_state(T0),
            SessionExtras {
                native_session_id: "n".into(),
                source_channel: "claude_code.hook.http".into(),
                ..Default::default()
            },
        );
        r.ended_at = ended_ms.map(format_ms);
        r
    }

    #[test]
    fn retention_regression_sessions_go_but_evidence_stays() {
        let s = Store::open_in_memory().unwrap();
        let cfg = unguarded();
        // a session that ended at T0 with one resolved approval, its decision, audit rows, a review finding and an event
        s.upsert_session(session_record("claude_code:s1", Some(T0)), None)
            .unwrap();
        s.insert_approval(new_approval("ar_1", "claude_code:s1", T0, 120_000), 0)
            .unwrap();
        s.resolve_approval_conditional(resolve_request("ar_1", "d1", T0 + 1_000))
            .unwrap();
        s.insert_approval_audit(NewApprovalAudit {
            request_id: "ar_1".into(),
            ts: format_ms(T0 + 2_000),
            actor: "daemon".into(),
            action: "delivered".into(),
            detail_json: None,
        })
        .unwrap();
        s.insert_review_finding(NewReviewFinding {
            session_key: "claude_code:s1".into(),
            review_id: "r".into(),
            ts: format_ms(T0),
            priority: Some(0),
            title: "t".into(),
            body: None,
            file_path: None,
            line_start: None,
            line_end: None,
            confidence: None,
            source: "app_server_text".into(),
        })
        .unwrap();
        append_event_at(&s, 1, "claude_code:s1", "turn_failed", T0);
        let day = |d: i64| T0 + d * DAY_MS;

        // +8 days: only the display details of the approval are cleared
        let r = s.run_retention(day(8) + 5_000, &cfg).unwrap();
        assert_eq!(r.approval_details_cleared, 1);
        assert_eq!(count(&s, "approvals"), 1);
        assert!(
            s.get_approval("ar_1")
                .unwrap()
                .unwrap()
                .details_json
                .is_none(),
            "details_json is NULL after 7 days"
        );
        assert!(
            !s.get_approval("ar_1").unwrap().unwrap().title.is_empty(),
            "the row itself stays"
        );

        // +31 days: the session row is gone, everything else is still there
        let r = s.run_retention(day(31), &cfg).unwrap();
        assert_eq!(r.sessions_deleted, 1);
        assert_eq!(count(&s, "sessions"), 0);
        assert_eq!(count(&s, "approvals"), 1, "approvals outlive their session");
        assert_eq!(count(&s, "decisions"), 1);
        assert_eq!(
            count(&s, "approval_audit"),
            3,
            "opened + decision_received + delivered"
        );
        assert_eq!(count(&s, "review_findings"), 1);
        assert_eq!(
            count(&s, "events"),
            1,
            "turn_failed is an important kind: 30 days, and it is the session's newest event"
        );

        // +91 days: the approval row goes, decisions and audit stay
        s.run_retention(day(91), &cfg).unwrap();
        assert_eq!(count(&s, "approvals"), 0);
        assert_eq!(count(&s, "decisions"), 1);
        assert_eq!(count(&s, "approval_audit"), 3);
        assert_eq!(count(&s, "review_findings"), 1);
        let opened: String = s
            .run(|c| {
                Ok(c.query_row(
                    "SELECT detail_json FROM approval_audit WHERE action='opened'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert!(
            opened.contains("recursive_delete") && opened.contains("\"tool_name\":\"Bash\""),
            "the opened snapshot is self-contained"
        );

        // +181 days: review findings go
        s.run_retention(day(181), &cfg).unwrap();
        assert_eq!(count(&s, "review_findings"), 0);
        assert_eq!(count(&s, "decisions"), 1);

        // +366 days: decisions and approval audit go; the retention_pruned rows of the earlier runs are younger than
        // 365 days at that point and stay
        s.run_retention(day(366), &cfg).unwrap();
        assert_eq!(count(&s, "decisions"), 0);
        assert_eq!(count(&s, "approval_audit"), 0);
        let log = s.list_audit_log(10).unwrap();
        assert_eq!(log.len(), 5, "{log:?}");
        assert!(log.iter().all(|l| l.action == "retention_pruned"));
    }

    #[test]
    fn pending_approvals_are_never_pruned() {
        let s = Store::open_in_memory().unwrap();
        s.insert_approval(new_approval("ar_p", "s", T0, 120_000), 0)
            .unwrap();
        let r = s
            .run_retention(T0 + 400 * DAY_MS, &unguarded())
            .unwrap();
        assert_eq!(r.approvals_deleted, 0);
        assert_eq!(r.approval_details_cleared, 0);
        assert_eq!(count(&s, "approvals"), 1);
    }

    #[test]
    fn event_rules_age_kind_and_per_session_minimum() {
        let s = Store::open_in_memory().unwrap();
        let cfg = RetentionConfig {
            events_keep_per_session: 2,
            ..unguarded()
        };
        // session A: 4 old ordinary events; session B: 1 old ordinary event
        for i in 1..=4 {
            append_event_at(&s, i, "A", "tool_started", T0);
        }
        append_event_at(&s, 5, "B", "tool_started", T0);
        // an important kind of the same age in session C (with two newer events so it is not "recent")
        append_event_at(&s, 6, "C", "test_failed", T0);
        append_event_at(&s, 7, "C", "tool_started", T0 + 100 * DAY_MS);
        append_event_at(&s, 8, "C", "tool_started", T0 + 100 * DAY_MS);
        // 15 days later: ordinary events older than 14 days go, except the newest 2 of each session
        let r = s.run_retention(T0 + 15 * DAY_MS, &cfg).unwrap();
        // 14 days: A keeps its newest 2 (seq 3,4), B keeps its only one, C's test_failed is important (30 days)
        assert_eq!(r.events_deleted, 2);
        assert_eq!(count(&s, "events"), 6);
        // 31 days later the important one goes as well (it is no longer among C's newest 2)
        let r = s.run_retention(T0 + 31 * DAY_MS, &cfg).unwrap();
        assert_eq!(
            r.events_deleted, 1,
            "only the important event of C, which is not among C's newest 2"
        );
        assert_eq!(count(&s, "events"), 5);
    }

    #[test]
    fn events_row_cap_spares_the_newest_per_session() {
        let s = Store::open_in_memory().unwrap();
        let cfg = RetentionConfig {
            events_max_rows: 5,
            events_keep_per_session: 1,
            ..unguarded()
        };
        for i in 1..=8 {
            append_event_at(&s, i, "A", "tool_started", T0);
        }
        append_event_at(&s, 9, "B", "tool_started", T0);
        let r = s.run_retention(T0 + 1_000, &cfg).unwrap();
        assert_eq!(r.events_deleted, 4);
        assert_eq!(count(&s, "events"), 5);
        let newest_a: i64 = s
            .run(|c| {
                Ok(c.query_row(
                    "SELECT MAX(seq) FROM events WHERE session_key='A'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(newest_a, 8);
    }

    #[test]
    fn stream_keeps_the_larger_of_48_hours_and_10000_rows() {
        let s = Store::open_in_memory().unwrap();
        let cfg = RetentionConfig {
            stream_min_rows: 5,
            ..unguarded()
        };
        // 8 rows at T0, older than 48 h when retention runs
        for _ in 0..8 {
            s.stream_append(stream_message(T0, 10)).unwrap();
        }
        let r = s.run_retention(T0 + 50 * HOUR_MS, &cfg).unwrap();
        assert_eq!(r.stream_deleted, 3, "old AND outside the newest 5");
        assert_eq!(count(&s, "stream"), 5);
        // rows younger than 48 h are never deleted by the row rule, however many there are
        for _ in 0..20 {
            s.stream_append(stream_message(T0 + 49 * HOUR_MS, 10))
                .unwrap();
        }
        let r = s.run_retention(T0 + 50 * HOUR_MS, &cfg).unwrap();
        assert_eq!(
            r.stream_deleted, 5,
            "the 5 old rows go, the 20 young rows stay"
        );
        assert_eq!(count(&s, "stream"), 20);
        // fewer rows than the minimum: nothing is deleted regardless of age
        let s2 = Store::open_in_memory().unwrap();
        for _ in 0..3 {
            s2.stream_append(stream_message(T0, 10)).unwrap();
        }
        let r = s2
            .run_retention(T0 + 500 * HOUR_MS, &unguarded())
            .unwrap();
        assert_eq!(r.stream_deleted, 0);
    }

    #[test]
    fn stream_size_cap_shortens_the_window_and_forces_a_snapshot() {
        let s = Store::open_in_memory().unwrap();
        let cfg = RetentionConfig {
            stream_max_bytes: 2_000,
            ..unguarded()
        };
        for _ in 0..10 {
            s.stream_append(stream_message(T0, 500)).unwrap();
        }
        let r = s.run_retention(T0 + 1_000, &cfg).unwrap();
        assert!(r.stream_deleted_for_size > 0);
        assert_eq!(r.stream_deleted, 0, "all rows are younger than 48 h");
        let remaining: i64 = s
            .run(|c| {
                Ok(c.query_row(
                    "SELECT COALESCE(SUM(LENGTH(payload_json)),0) FROM stream",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert!(remaining <= 2_000);
        let b = s.stream_bounds().unwrap();
        assert_eq!(b.max_seq, 10);
        assert!(b.min_seq.unwrap() > 1);
        // a phone that last saw seq 2 now needs a snapshot (and gets no replay of a window that no longer exists)
        assert_eq!(
            s.plan_resync(2).unwrap(),
            crate::store::stream::ResyncPlan::Snapshot
        );
        // a phone at the newest row only needs the tail
        assert_eq!(
            s.plan_resync(10).unwrap(),
            crate::store::stream::ResyncPlan::None
        );
    }

    #[test]
    fn pairings_and_devices() {
        let s = Store::open_in_memory().unwrap();
        s.run(|c| {
            c.execute("INSERT INTO devices(device_id,name,platform,token_hash,paired_at,revoked_at,revoked_reason) VALUES ('dev_old','a','android',x'01','t',?1,'user_desktop')", [format_ms(T0)])?;
            c.execute("INSERT INTO devices(device_id,name,platform,token_hash,paired_at,revoked_at,revoked_reason) VALUES ('dev_ref','b','android',x'02','t',?1,'user_desktop')", [format_ms(T0)])?;
            c.execute("INSERT INTO devices(device_id,name,platform,token_hash,paired_at,last_seen_at) VALUES ('dev_idle','c','android',x'03',?1,?1)", [format_ms(T0)])?;
            c.execute("INSERT INTO pairings(pairing_id,secret_sha256,created_at,expires_at) VALUES ('p_1',x'00',?1,?1)", [format_ms(T0)])?;
            Ok(())
        }).unwrap();
        // an approval (resolved by dev_ref) keeps its device row alive
        s.insert_approval(new_approval("ar_1", "s", T0 + 366 * DAY_MS, 120_000), 0)
            .unwrap();
        let mut req = resolve_request("ar_1", "d1", T0 + 366 * DAY_MS + 1_000);
        req.resolved_device_id = Some("dev_ref".to_owned());
        req.resolved_by = "phone".to_owned();
        req.actor = "device:dev_ref".to_owned();
        s.resolve_approval_conditional(req).unwrap();
        let cfg = RetentionConfig {
            auto_revoke_inactive_days: Some(90),
            ..unguarded()
        };
        let r = s.run_retention(T0 + 366 * DAY_MS + 5_000, &cfg).unwrap();
        assert_eq!(r.pairings_deleted, 1);
        assert_eq!(
            r.devices_auto_revoked, 1,
            "dev_idle was not seen for 90 days"
        );
        assert_eq!(
            r.devices_deleted, 1,
            "dev_old goes; dev_ref is still referenced by an approval"
        );
        let ids: Vec<String> = s
            .run(|c| {
                let mut st = c.prepare("SELECT device_id FROM devices ORDER BY device_id")?;
                let v = st
                    .query_map([], |r| r.get(0))?
                    .collect::<Result<Vec<String>, _>>()?;
                Ok(v)
            })
            .unwrap();
        assert_eq!(ids, vec!["dev_idle", "dev_ref"]);
        let reason: String = s
            .run(|c| {
                Ok(c.query_row(
                    "SELECT revoked_reason FROM devices WHERE device_id='dev_idle'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(reason, "inactive_90d");
    }

    /// Review finding: a system clock that jumps forward made every row look ancient.
    #[test]
    fn a_ten_year_clock_jump_deletes_nothing_the_normal_schedule_would_keep() {
        let s = Store::open_in_memory().unwrap();
        let day = |d: i64| T0 + d * DAY_MS;
        // data of the last ten days (all of it inside every retention window) at "real" now = day(10)
        for d in 0..10 {
            let id = format!("ar_{d}");
            let sk = format!("claude_code:s{d}");
            s.insert_approval(new_approval(&id, &sk, day(d), 120_000), 0).unwrap();
            s.resolve_approval_conditional(resolve_request(&id, &format!("d{d}"), day(d) + 5_000))
                .unwrap();
            append_event_at(&s, d as u32 + 1, &sk, "command_started", day(d));
            s.stream_append(stream_message(day(d), 10)).unwrap();
        }
        let before = (
            count(&s, "approvals"),
            count(&s, "decisions"),
            count(&s, "approval_audit"),
            count(&s, "events"),
            count(&s, "stream"),
        );
        assert!(before.0 == 10 && before.1 == 10 && before.3 == 10 && before.4 >= 10, "{before:?}");
        // the clock jumps +10 years
        let jumped = day(10) + 10 * 365 * DAY_MS;
        let r = s
            .run_retention(jumped, &RetentionConfig::default())
            .unwrap();
        let after = (
            count(&s, "approvals"),
            count(&s, "decisions"),
            count(&s, "approval_audit"),
            count(&s, "events"),
            count(&s, "stream"),
        );
        assert_eq!(after, before, "nothing was deleted: {r:?}");
        assert_eq!(r.approvals_deleted + r.decisions_deleted + r.events_deleted + r.stream_deleted, 0);
        // the same data at a plausible later date is cleaned by the normal rules (the guard is not a no-op switch)
        let r = s
            .run_retention(day(10) + 2 * DAY_MS, &RetentionConfig::default())
            .unwrap();
        assert_eq!(r.approvals_deleted, 0, "still inside every window: {r:?}");
        // and an empty database has nothing to guard
        let empty = Store::open_in_memory().unwrap();
        empty.run_retention(jumped, &RetentionConfig::default()).unwrap();
    }

    #[test]
    fn nothing_to_do_writes_no_audit_row() {
        let s = Store::open_in_memory().unwrap();
        let r = s.run_retention(T0, &unguarded()).unwrap();
        assert_eq!(r, RetentionReport::default());
        assert_eq!(r.total(), 0);
        assert!(s.list_audit_log(5).unwrap().is_empty());
    }

    #[test]
    fn no_rule_cascades_a_decision_row_survives_its_approval_and_session() {
        // direct SQL proof of the "no cascade" invariant, independent of the retention job
        let s = Store::open_in_memory().unwrap();
        s.upsert_session(session_record("claude_code:s1", None), None)
            .unwrap();
        s.insert_approval(new_approval("ar_1", "claude_code:s1", T0, 1_000), 0)
            .unwrap();
        s.insert_decision(NewDecision {
            id: "d".into(),
            request_id: "ar_1".into(),
            actor: "desktop".into(),
            decision: "allow".into(),
            decided_at: format_ms(T0),
            received_at: format_ms(T0),
            auth_method: None,
            extra_confirmation: None,
            verify_result: "APPLIED".into(),
            signature: None,
        })
        .unwrap();
        s.run(|c| {
            c.execute("DELETE FROM sessions", [])?;
            c.execute("DELETE FROM approvals", [])?;
            Ok(())
        })
        .unwrap();
        assert_eq!(count(&s, "decisions"), 1);
        assert_eq!(count(&s, "approval_audit"), 1);
        let _ = json!(null);
    }
}
