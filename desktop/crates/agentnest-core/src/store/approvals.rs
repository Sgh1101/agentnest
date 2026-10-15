//! Approval persistence: the single conditional transition, decisions, audit rows (docs/storage.md 1 and 2).
//!
//! Every function here that writes runs with `synchronous=FULL` ([`super::with_full_sync`]). The approval broker
//! (next implementation step) calls them in this order for a decision:
//!
//! 1. `decision_verify_result(decision_id)`: idempotency (a re-sent decision gets the stored result, nothing is
//!    re-applied);
//! 2. validation steps 1-9 (security.md 6.2), which change nothing;
//! 3. [`Store::resolve_approval_conditional`]: *one* transaction with the conditional `UPDATE`, the `decisions` row
//!    and the `approval_audit` row. Only [`ResolveOutcome::Applied`] lets the broker answer the agent;
//! 4. the adapter reply (only after that commit), then `set_delivery`.
//!
//! Rejected attempts are recorded too (`insert_decision` with the verify result, `insert_approval_audit` with
//! `decision_rejected`): "every received decision attempt is audit evidence".

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use serde_json::json;

use super::{with_full_sync, Store, StoreError};
use crate::redact::session_key_prefix;
use crate::state::timers::{format_ms, parse_ms};

/// Maximum size of a JSON detail column written by callers (audit details and similar).
const MAX_JSON_COLUMN_BYTES: usize = 16 * 1024;

fn check_json_size(name: &str, value: &Option<String>) -> Result<(), StoreError> {
    if let Some(v) = value {
        if v.len() > MAX_JSON_COLUMN_BYTES {
            return Err(StoreError::Invalid(format!("{name} is too large")));
        }
    }
    Ok(())
}

/// A new approval (status `pending`). Field meanings: docs/storage.md `approvals`.
#[derive(Clone, Debug)]
#[allow(missing_docs)]
pub struct NewApproval {
    pub request_id: String,
    pub nonce: Vec<u8>,
    pub session_key: String,
    pub agent_kind: String,
    /// Sub-agent id, `""` for the main agent or when the hook input has none.
    pub agent_id: String,
    pub origin: String,
    pub native_binding_json: String,
    pub tool_name: String,
    pub tool_kind: String,
    /// 32 raw bytes.
    pub tool_input_sha256: Vec<u8>,
    pub created_at: String,
    pub expires_at: String,
    pub title: String,
    pub purpose: Option<String>,
    pub details_json: Option<String>,
    pub risk_level: String,
    pub risk_reasons_json: String,
    pub extra_confirmation: String,
    pub allowed_decisions_json: String,
    pub permission_mode: Option<String>,
}

/// Result of [`Store::insert_approval`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsertApproval {
    /// A new pending approval was stored.
    Inserted,
    /// The same hook arrived again within the merge window (same session, agent, tool and input hash): the caller adds
    /// its HTTP handle to the existing request instead of creating a second card.
    Merged {
        /// The existing request.
        request_id: String,
    },
}

/// A row of `approvals`. Field meanings: docs/storage.md `approvals`.
#[derive(Clone, Debug, PartialEq)]
#[allow(missing_docs)]
pub struct ApprovalRow {
    pub request_id: String,
    pub nonce: Vec<u8>,
    pub session_key: String,
    pub agent_kind: String,
    pub agent_id: String,
    pub origin: String,
    pub native_binding_json: String,
    pub tool_name: String,
    pub tool_kind: String,
    pub tool_input_sha256: Vec<u8>,
    pub created_at: String,
    pub expires_at: String,
    pub title: String,
    pub purpose: Option<String>,
    pub details_json: Option<String>,
    pub risk_level: String,
    pub risk_reasons_json: String,
    pub extra_confirmation: String,
    pub allowed_decisions_json: String,
    pub permission_mode: Option<String>,
    pub status: String,
    pub outcome: Option<String>,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<String>,
    pub resolved_device_id: Option<String>,
    pub decision_msg_id: Option<String>,
    pub decision_auth_json: Option<String>,
    pub delivery: Option<String>,
    pub observed_result: String,
    pub observed_event_id: Option<String>,
    pub delivered_to_json: String,
}

pub(crate) const APPROVAL_COLUMNS: &str = "request_id, nonce, session_key, agent_kind, agent_id, origin, \
native_binding_json, tool_name, tool_kind, tool_input_sha256, created_at, expires_at, title, purpose, details_json, \
risk_level, risk_reasons_json, extra_confirmation, allowed_decisions_json, permission_mode, status, outcome, \
resolved_by, resolved_at, resolved_device_id, decision_msg_id, decision_auth_json, delivery, observed_result, \
observed_event_id, delivered_to_json";

pub(crate) fn approval_from_row(r: &Row<'_>) -> rusqlite::Result<ApprovalRow> {
    Ok(ApprovalRow {
        request_id: r.get(0)?,
        nonce: r.get(1)?,
        session_key: r.get(2)?,
        agent_kind: r.get(3)?,
        agent_id: r.get(4)?,
        origin: r.get(5)?,
        native_binding_json: r.get(6)?,
        tool_name: r.get(7)?,
        tool_kind: r.get(8)?,
        tool_input_sha256: r.get(9)?,
        created_at: r.get(10)?,
        expires_at: r.get(11)?,
        title: r.get(12)?,
        purpose: r.get(13)?,
        details_json: r.get(14)?,
        risk_level: r.get(15)?,
        risk_reasons_json: r.get(16)?,
        extra_confirmation: r.get(17)?,
        allowed_decisions_json: r.get(18)?,
        permission_mode: r.get(19)?,
        status: r.get(20)?,
        outcome: r.get(21)?,
        resolved_by: r.get(22)?,
        resolved_at: r.get(23)?,
        resolved_device_id: r.get(24)?,
        decision_msg_id: r.get(25)?,
        decision_auth_json: r.get(26)?,
        delivery: r.get(27)?,
        observed_result: r.get(28)?,
        observed_event_id: r.get(29)?,
        delivered_to_json: r.get(30)?,
    })
}

/// A received decision attempt (`decisions`). The store sets `verify_result` itself in
/// [`Store::resolve_approval_conditional`]; for attempts that fail validation earlier the broker uses
/// [`Store::insert_decision`] with the reason.
#[derive(Clone, Debug, PartialEq)]
#[allow(missing_docs)]
pub struct NewDecision {
    /// The `decision` envelope id (idempotency key).
    pub id: String,
    pub request_id: String,
    /// `device:<id>` or `desktop`.
    pub actor: String,
    /// `allow` / `deny` / `deny_and_stop`.
    pub decision: String,
    pub decided_at: String,
    pub received_at: String,
    pub auth_method: Option<String>,
    pub extra_confirmation: Option<String>,
    /// `APPLIED`, `EXPIRED`, `ALREADY_RESOLVED`, `BINDING_MISMATCH`, ... (protocol.md 4.11).
    pub verify_result: String,
    /// Phase 3 signature (public information).
    pub signature: Option<Vec<u8>>,
}

/// A new `approval_audit` row.
#[derive(Clone, Debug, PartialEq)]
#[allow(missing_docs)]
pub struct NewApprovalAudit {
    pub request_id: String,
    pub ts: String,
    /// `daemon`, `phone:<device_id>`, `desktop` or `agent`.
    pub actor: String,
    /// `opened`, `sent_to_phone`, `acked`, `seen`, `decision_received`, `decision_rejected`, `delivered`, `expired`,
    /// `handed_off`, `superseded`, `observed`, `late_decision`.
    pub action: String,
    /// Redacted details (no commands or diffs).
    pub detail_json: Option<String>,
}

/// A stored `approval_audit` row.
#[derive(Clone, Debug, PartialEq)]
#[allow(missing_docs)]
pub struct ApprovalAuditRow {
    pub id: i64,
    pub request_id: String,
    pub ts: String,
    pub actor: String,
    pub action: String,
    pub detail_json: Option<String>,
}

/// A new `audit_log` row.
#[derive(Clone, Debug, PartialEq)]
#[allow(missing_docs)]
pub struct NewAuditLog {
    pub ts: String,
    /// `system`, `desktop_user`, `device:<id>` or `adapter:<kind>`.
    pub actor: String,
    /// `pairing_started`, `device_revoked`, `hooks_installed`, `retention_pruned`, ... (storage.md).
    pub action: String,
    pub target: Option<String>,
    pub details_json: Option<String>,
}

/// A stored `audit_log` row.
#[derive(Clone, Debug, PartialEq)]
#[allow(missing_docs)]
pub struct AuditLogRow {
    pub id: i64,
    pub ts: String,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub details_json: Option<String>,
}

/// Everything [`Store::resolve_approval_conditional`] needs.
#[derive(Clone, Debug)]
#[allow(missing_docs)]
pub struct ResolveRequest {
    pub request_id: String,
    /// `allowed`, `denied` or `denied_and_stopped`.
    pub outcome: String,
    /// `phone` or `desktop`.
    pub resolved_by: String,
    pub resolved_device_id: Option<String>,
    /// Server time (RFC 3339, millisecond UTC). The `UPDATE` requires `expires_at > now`.
    pub now: String,
    /// `decisions.id` = the decision envelope id (also stored as `approvals.decision_msg_id`).
    pub decision_id: String,
    /// `device:<id>` or `desktop`.
    pub actor: String,
    /// `allow` / `deny` / `deny_and_stop`.
    pub decision: String,
    pub decided_at: String,
    pub auth_method: Option<String>,
    pub extra_confirmation: Option<String>,
    /// `approvals.decision_auth_json`: `{method, authenticated_at, extra_confirmation}`.
    pub auth_json: Option<String>,
    pub signature: Option<Vec<u8>>,
    /// Actor of the audit row: `phone:<device_id>` or `desktop`.
    pub audit_actor: String,
    pub audit_detail_json: Option<String>,
}

/// Why a conditional resolve did not apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotApplied {
    /// No such request.
    UnknownRequest,
    /// The request is no longer pending (resolved, expired, handed off, superseded or failed).
    AlreadyResolved,
    /// The request is still `pending` but `expires_at <= now`.
    Expired,
}

impl NotApplied {
    /// The `decision_result.reason` / `decisions.verify_result` spelling.
    pub fn as_reason(self) -> &'static str {
        match self {
            NotApplied::UnknownRequest => "UNKNOWN_REQUEST",
            NotApplied::AlreadyResolved => "ALREADY_RESOLVED",
            NotApplied::Expired => "EXPIRED",
        }
    }
}

/// Result of [`Store::resolve_approval_conditional`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// The conditional `UPDATE` changed exactly one row; decision and audit rows are committed.
    Applied,
    /// Nothing changed in `approvals`; the attempt was recorded in `decisions` / `approval_audit`.
    NotApplied(NotApplied),
}

/// How a pending approval ends without a decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseStatus {
    /// TTL elapsed.
    Expired,
    /// Handed to the local prompt (no device online, disconnect, "handle locally", pause, link off).
    HandedOffLocal,
    /// The agent or another client resolved first.
    Superseded,
    /// Delivery failed.
    Failed,
}

impl CloseStatus {
    /// The `status` / `outcome` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            CloseStatus::Expired => "expired",
            CloseStatus::HandedOffLocal => "handed_off_local",
            CloseStatus::Superseded => "superseded",
            CloseStatus::Failed => "failed",
        }
    }
}

/// Everything [`Store::close_approval`] needs.
#[derive(Clone, Debug)]
#[allow(missing_docs)]
pub struct CloseRequest {
    pub request_id: String,
    pub status: CloseStatus,
    /// `phone`, `desktop`, `timeout`, `agent` or `system`.
    pub resolved_by: String,
    pub now: String,
    pub audit_actor: String,
    /// `expired`, `handed_off` or `superseded`.
    pub audit_action: String,
    pub audit_detail_json: Option<String>,
}

/// An approval that [`Store::expire_due`] / [`Store::expire_all_pending_on_startup`] moved to `expired`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpiredApproval {
    /// The request.
    pub request_id: String,
    /// Its session (for the `approval_resolved{expired}` stream message).
    pub session_key: String,
}

fn insert_audit_tx(tx: &Transaction<'_>, a: &NewApprovalAudit) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO approval_audit(request_id, ts, actor, action, detail_json) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![a.request_id, a.ts, a.actor, a.action, a.detail_json],
    )?;
    Ok(())
}

/// Inserts one decision attempt. The envelope id is the phone's choice and therefore not unique over time: if a row
/// with that id exists (an earlier, rejected attempt; or another request's decision) the new attempt is stored under
/// `<id>#<n>` instead of failing the whole transition (a rejected attempt must never be able to block the next valid
/// one that reuses its id). [`Store::decision_applied_replay`] knows the suffix form.
fn insert_decision_tx(tx: &Transaction<'_>, d: &NewDecision) -> Result<(), StoreError> {
    for n in 0..16u32 {
        let id = if n == 0 {
            d.id.clone()
        } else {
            format!("{}#{n}", d.id)
        };
        let inserted = tx.execute(
            "INSERT INTO decisions(id, request_id, actor, decision, decided_at, received_at, auth_method, \
             extra_confirmation, verify_result, signature) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
             ON CONFLICT(id) DO NOTHING",
            params![
                id,
                d.request_id,
                d.actor,
                d.decision,
                d.decided_at,
                d.received_at,
                d.auth_method,
                d.extra_confirmation,
                d.verify_result,
                d.signature
            ],
        )?;
        if inserted == 1 {
            return Ok(());
        }
    }
    Err(StoreError::Invalid(
        "too many attempts with one decision id".to_owned(),
    ))
}

impl Store {
    /// Stores a new pending approval, or reports that it merges into an existing one.
    ///
    /// The merge decision is made here, inside the single writer: a pending approval with the same
    /// `(session_key, agent_id, tool_name, tool_input_sha256)` created less than `merge_window_ms` before
    /// `new.created_at` absorbs the new one. `merge_window_ms == 0` never merges, and **a request without an
    /// `agent_id` (empty string) never merges whatever the window is** (claude-code.md 6: without an `agent_id` two
    /// identical requests may be two parallel sub-agents, and one approval must not satisfy both). The `approval_audit` row `opened` (a self-contained snapshot: tool, risk, hash,
    /// origin) is written in the same transaction.
    pub fn insert_approval(
        &self,
        new: NewApproval,
        merge_window_ms: i64,
    ) -> Result<InsertApproval, StoreError> {
        if new.tool_input_sha256.len() != 32 || new.nonce.len() != 16 {
            return Err(StoreError::Invalid(
                "nonce must be 16 bytes and the input hash 32 bytes".to_owned(),
            ));
        }
        check_json_size("details_json", &new.details_json)?;
        self.run(move |conn| {
            with_full_sync(conn, |tx| {
                if merge_window_ms > 0 && !new.agent_id.is_empty() {
                    let created_ms = parse_ms(&new.created_at)
                        .ok_or_else(|| StoreError::Invalid("created_at is not RFC 3339".to_owned()))?;
                    let cutoff = format_ms(created_ms - merge_window_ms);
                    let existing: Option<String> = tx
                        .query_row(
                            "SELECT request_id FROM approvals WHERE session_key=?1 AND agent_id=?2 AND tool_name=?3 \
                             AND tool_input_sha256=?4 AND status='pending' AND created_at >= ?5 \
                             ORDER BY created_at DESC LIMIT 1",
                            params![new.session_key, new.agent_id, new.tool_name, new.tool_input_sha256, cutoff],
                            |r| r.get(0),
                        )
                        .optional()?;
                    if let Some(request_id) = existing {
                        return Ok(InsertApproval::Merged { request_id });
                    }
                }
                tx.execute(
                    "INSERT INTO approvals(request_id, nonce, session_key, agent_kind, agent_id, origin, \
                     native_binding_json, tool_name, tool_kind, tool_input_sha256, created_at, expires_at, title, \
                     purpose, details_json, risk_level, risk_reasons_json, extra_confirmation, \
                     allowed_decisions_json, permission_mode, status) \
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,'pending')",
                    params![
                        new.request_id,
                        new.nonce,
                        new.session_key,
                        new.agent_kind,
                        new.agent_id,
                        new.origin,
                        new.native_binding_json,
                        new.tool_name,
                        new.tool_kind,
                        new.tool_input_sha256,
                        new.created_at,
                        new.expires_at,
                        new.title,
                        new.purpose,
                        new.details_json,
                        new.risk_level,
                        new.risk_reasons_json,
                        new.extra_confirmation,
                        new.allowed_decisions_json,
                        new.permission_mode
                    ],
                )?;
                // Self-contained snapshot so the audit trail survives the deletion of the approval row (storage.md 1).
                let reasons: serde_json::Value =
                    serde_json::from_str(&new.risk_reasons_json).unwrap_or(serde_json::Value::Null);
                let snapshot = json!({
                    "session_key": session_key_prefix(&new.session_key),
                    "agent_kind": new.agent_kind,
                    "tool_name": new.tool_name,
                    "tool_kind": new.tool_kind,
                    "risk_level": new.risk_level,
                    "risk_reasons": reasons,
                    "tool_input_sha256": hex::encode(&new.tool_input_sha256),
                    "origin": new.origin,
                    "expires_at": new.expires_at,
                });
                insert_audit_tx(
                    tx,
                    &NewApprovalAudit {
                        request_id: new.request_id.clone(),
                        ts: new.created_at.clone(),
                        actor: "daemon".to_owned(),
                        action: "opened".to_owned(),
                        detail_json: Some(snapshot.to_string()),
                    },
                )?;
                Ok(InsertApproval::Inserted)
            })
        })
    }

    /// The single approval transition (docs/storage.md 2 "승인 적용"):
    /// `UPDATE approvals SET status='resolved', ... WHERE request_id=? AND status='pending' AND expires_at > ?`,
    /// plus the `decisions` and `approval_audit` rows, in one `synchronous=FULL` transaction.
    ///
    /// Zero affected rows means [`ResolveOutcome::NotApplied`]: the attempt is still recorded (`verify_result`
    /// `ALREADY_RESOLVED` / `EXPIRED` / `UNKNOWN_REQUEST`, audit `decision_rejected`) and `approvals` is untouched.
    /// Two concurrent calls for the same request: exactly one gets [`ResolveOutcome::Applied`].
    pub fn resolve_approval_conditional(
        &self,
        req: ResolveRequest,
    ) -> Result<ResolveOutcome, StoreError> {
        check_json_size("audit_detail_json", &req.audit_detail_json)?;
        self.run(move |conn| {
            with_full_sync(conn, |tx| {
                let changed = tx.execute(
                    "UPDATE approvals SET status='resolved', outcome=?1, resolved_by=?2, resolved_at=?3, \
                     resolved_device_id=?4, decision_msg_id=?5, decision_auth_json=?6 \
                     WHERE request_id=?7 AND status='pending' AND expires_at > ?3",
                    params![
                        req.outcome,
                        req.resolved_by,
                        req.now,
                        req.resolved_device_id,
                        req.decision_id,
                        req.auth_json,
                        req.request_id
                    ],
                )?;
                let (outcome, verify, action) = if changed == 1 {
                    (ResolveOutcome::Applied, "APPLIED", "decision_received")
                } else {
                    let state: Option<(String, String)> = tx
                        .query_row(
                            "SELECT status, expires_at FROM approvals WHERE request_id=?1",
                            [&req.request_id],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .optional()?;
                    let why = match state {
                        None => NotApplied::UnknownRequest,
                        Some((status, expires_at)) => {
                            if status == "pending" && expires_at <= req.now {
                                NotApplied::Expired
                            } else {
                                NotApplied::AlreadyResolved
                            }
                        }
                    };
                    (ResolveOutcome::NotApplied(why), why.as_reason(), "decision_rejected")
                };
                insert_decision_tx(
                    tx,
                    &NewDecision {
                        id: req.decision_id.clone(),
                        request_id: req.request_id.clone(),
                        actor: req.actor.clone(),
                        decision: req.decision.clone(),
                        decided_at: req.decided_at.clone(),
                        received_at: req.now.clone(),
                        auth_method: req.auth_method.clone(),
                        extra_confirmation: req.extra_confirmation.clone(),
                        verify_result: verify.to_owned(),
                        signature: req.signature.clone(),
                    },
                )?;
                insert_audit_tx(
                    tx,
                    &NewApprovalAudit {
                        request_id: req.request_id.clone(),
                        ts: req.now.clone(),
                        actor: req.audit_actor.clone(),
                        action: action.to_owned(),
                        detail_json: req.audit_detail_json.clone(),
                    },
                )?;
                Ok(outcome)
            })
        })
    }

    /// Ends a pending approval without a decision (`expired`, `handed_off_local`, `superseded`, `failed`), conditional on
    /// `status='pending'`, with an audit row. Returns `false` if it was not pending (nothing changes).
    pub fn close_approval(&self, req: CloseRequest) -> Result<bool, StoreError> {
        check_json_size("audit_detail_json", &req.audit_detail_json)?;
        self.run(move |conn| {
            with_full_sync(conn, |tx| {
                let changed = tx.execute(
                    "UPDATE approvals SET status=?1, outcome=?1, resolved_by=?2, resolved_at=?3 \
                     WHERE request_id=?4 AND status='pending'",
                    params![
                        req.status.as_str(),
                        req.resolved_by,
                        req.now,
                        req.request_id
                    ],
                )?;
                if changed == 1 {
                    insert_audit_tx(
                        tx,
                        &NewApprovalAudit {
                            request_id: req.request_id.clone(),
                            ts: req.now.clone(),
                            actor: req.audit_actor.clone(),
                            action: req.audit_action.clone(),
                            detail_json: req.audit_detail_json.clone(),
                        },
                    )?;
                }
                Ok(changed == 1)
            })
        })
    }

    /// The expiry timer: `UPDATE ... SET status='expired' ... WHERE status='pending' AND expires_at <= now`. Returns the
    /// affected requests so the caller can emit `approval_resolved{expired}` for each.
    pub fn expire_due(&self, now: &str) -> Result<Vec<ExpiredApproval>, StoreError> {
        let now = now.to_owned();
        self.run(move |conn| expire_where(conn, &now, "timeout", "expires_at <= ?1"))
    }

    /// Daemon start: every `pending` approval becomes `expired` (`resolved_by='system'`). A restarted daemon cannot
    /// answer the old hook connections, so none of them may stay pending (security.md 7).
    pub fn expire_all_pending_on_startup(
        &self,
        now: &str,
    ) -> Result<Vec<ExpiredApproval>, StoreError> {
        let now = now.to_owned();
        self.run(move |conn| expire_where(conn, &now, "system", "1 = 1"))
    }

    /// One approval.
    pub fn get_approval(&self, request_id: &str) -> Result<Option<ApprovalRow>, StoreError> {
        let id = request_id.to_owned();
        self.read(move |c| {
            Ok(c.query_row(
                &format!("SELECT {APPROVAL_COLUMNS} FROM approvals WHERE request_id=?1"),
                [id],
                approval_from_row,
            )
            .optional()?)
        })
    }

    /// Pending approvals; with `not_expired_at` only those with `expires_at > not_expired_at` (snapshot contents).
    pub fn list_pending_approvals(
        &self,
        not_expired_at: Option<&str>,
    ) -> Result<Vec<ApprovalRow>, StoreError> {
        let cutoff = not_expired_at.map(str::to_owned);
        self.read(move |c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {APPROVAL_COLUMNS} FROM approvals WHERE status='pending' AND (?1 IS NULL OR expires_at > ?1) \
                 ORDER BY created_at"
            ))?;
            let rows = stmt.query_map([cutoff], approval_from_row)?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    /// Records whether the reply reached the agent (`delivered` / `not_delivered`).
    pub fn set_delivery(
        &self,
        request_id: &str,
        delivered: bool,
        ts: &str,
    ) -> Result<(), StoreError> {
        let (id, ts) = (request_id.to_owned(), ts.to_owned());
        self.run(move |conn| {
            with_full_sync(conn, |tx| {
                tx.execute(
                    "UPDATE approvals SET delivery=?1 WHERE request_id=?2",
                    params![
                        if delivered {
                            "delivered"
                        } else {
                            "not_delivered"
                        },
                        id
                    ],
                )?;
                insert_audit_tx(
                    tx,
                    &NewApprovalAudit {
                        request_id: id.clone(),
                        ts,
                        actor: "daemon".to_owned(),
                        action: if delivered { "delivered" } else { "handed_off" }.to_owned(),
                        detail_json: Some(json!({ "delivered": delivered }).to_string()),
                    },
                )?;
                Ok(())
            })
        })
    }

    /// Records the later observation of the tool call (`executed` / `declined`) and its evidence event.
    pub fn set_observed_result(
        &self,
        request_id: &str,
        observed: &str,
        evidence_event_id: &str,
        ts: &str,
    ) -> Result<(), StoreError> {
        if !matches!(observed, "executed" | "declined" | "unknown") {
            return Err(StoreError::Invalid("observed_result".to_owned()));
        }
        let (id, observed, ev, ts) = (
            request_id.to_owned(),
            observed.to_owned(),
            evidence_event_id.to_owned(),
            ts.to_owned(),
        );
        self.run(move |conn| {
            with_full_sync(conn, |tx| {
                tx.execute(
                    "UPDATE approvals SET observed_result=?1, observed_event_id=?2 WHERE request_id=?3",
                    params![observed, ev, id],
                )?;
                insert_audit_tx(
                    tx,
                    &NewApprovalAudit {
                        request_id: id.clone(),
                        ts,
                        actor: "daemon".to_owned(),
                        action: "observed".to_owned(),
                        detail_json: Some(json!({ "observed_result": observed, "event_id": ev }).to_string()),
                    },
                )?;
                Ok(())
            })
        })
    }

    /// Replaces `approvals.delivered_to_json` (`{device_id: {sent_at, acked_at, seen_at}}`).
    pub fn set_delivered_to(
        &self,
        request_id: &str,
        delivered_to_json: &str,
    ) -> Result<(), StoreError> {
        if delivered_to_json.len() > MAX_JSON_COLUMN_BYTES {
            return Err(StoreError::Invalid(
                "delivered_to_json is too large".to_owned(),
            ));
        }
        let (id, json) = (request_id.to_owned(), delivered_to_json.to_owned());
        self.run(move |c| {
            c.execute(
                "UPDATE approvals SET delivered_to_json=?1 WHERE request_id=?2",
                params![json, id],
            )?;
            Ok(())
        })
    }

    /// Stores a decision attempt that was rejected before reaching the conditional update (validation steps 1-9).
    pub fn insert_decision(&self, d: NewDecision) -> Result<(), StoreError> {
        self.run(move |conn| with_full_sync(conn, |tx| insert_decision_tx(tx, &d)))
    }

    /// `true` if this exact decision - the same envelope id, for the same request, by the same actor - was **applied**
    /// before (`verify_result = 'APPLIED'`): the idempotency check of security.md 6.3.
    ///
    /// Only an *applied* decision is replayed. A decision that was rejected (no authentication, a bad hash, expired, ...)
    /// is not a result worth repeating: the same id may come again, valid this time, and is then evaluated afresh. An
    /// id that was applied for another request or by another actor is not this decision either.
    pub fn decision_applied_replay(
        &self,
        decision_id: &str,
        request_id: &str,
        actor: &str,
    ) -> Result<bool, StoreError> {
        let (id, rid, actor) = (
            decision_id.to_owned(),
            request_id.to_owned(),
            actor.to_owned(),
        );
        self.read(move |c| {
            Ok(c.query_row(
                "SELECT 1 FROM decisions WHERE request_id=?2 AND actor=?3 AND verify_result='APPLIED' \
                 AND (id=?1 OR substr(id, 1, length(?1) + 1) = ?1 || '#') LIMIT 1",
                params![id, rid, actor],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false))
        })
    }

    /// The stored `verify_result` of the decision row with this exact id (tests, diagnostics).
    pub fn decision_verify_result(&self, decision_id: &str) -> Result<Option<String>, StoreError> {
        let id = decision_id.to_owned();
        self.read(move |c| {
            Ok(c.query_row(
                "SELECT verify_result FROM decisions WHERE id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()?)
        })
    }

    /// The decision attempts of a request, oldest first.
    pub fn list_decisions(&self, request_id: &str) -> Result<Vec<NewDecision>, StoreError> {
        let id = request_id.to_owned();
        self.read(move |c| {
            let mut stmt = c.prepare(
                "SELECT id, request_id, actor, decision, decided_at, received_at, auth_method, extra_confirmation, \
                 verify_result, signature FROM decisions WHERE request_id=?1 ORDER BY received_at, id",
            )?;
            let rows = stmt.query_map([id], |r| {
                Ok(NewDecision {
                    id: r.get(0)?,
                    request_id: r.get(1)?,
                    actor: r.get(2)?,
                    decision: r.get(3)?,
                    decided_at: r.get(4)?,
                    received_at: r.get(5)?,
                    auth_method: r.get(6)?,
                    extra_confirmation: r.get(7)?,
                    verify_result: r.get(8)?,
                    signature: r.get(9)?,
                })
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    /// Appends an `approval_audit` row (`sent_to_phone`, `acked`, `seen`, `late_decision`, ...).
    pub fn insert_approval_audit(&self, a: NewApprovalAudit) -> Result<(), StoreError> {
        check_json_size("detail_json", &a.detail_json)?;
        self.run(move |conn| with_full_sync(conn, |tx| insert_audit_tx(tx, &a)))
    }

    /// The audit rows of a request in insertion order.
    pub fn list_approval_audit(
        &self,
        request_id: &str,
    ) -> Result<Vec<ApprovalAuditRow>, StoreError> {
        let id = request_id.to_owned();
        self.read(move |c| {
            let mut stmt = c.prepare(
                "SELECT id, request_id, ts, actor, action, detail_json FROM approval_audit WHERE request_id=?1 ORDER BY id",
            )?;
            let rows = stmt.query_map([id], |r| {
                Ok(ApprovalAuditRow {
                    id: r.get(0)?,
                    request_id: r.get(1)?,
                    ts: r.get(2)?,
                    actor: r.get(3)?,
                    action: r.get(4)?,
                    detail_json: r.get(5)?,
                })
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    /// Appends an `audit_log` row (pairing, revocation, hook installation, retention, ...).
    pub fn insert_audit_log(&self, a: NewAuditLog) -> Result<(), StoreError> {
        check_json_size("details_json", &a.details_json)?;
        self.run(move |conn| {
            with_full_sync(conn, |tx| {
                insert_audit_log_tx(tx, &a)?;
                Ok(())
            })
        })
    }

    /// The newest audit log rows, newest first.
    pub fn list_audit_log(&self, limit: u32) -> Result<Vec<AuditLogRow>, StoreError> {
        self.read(move |c| {
            let mut stmt = c.prepare(
                "SELECT id, ts, actor, action, target, details_json FROM audit_log ORDER BY id DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map([limit.min(1000)], |r| {
                Ok(AuditLogRow {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    actor: r.get(2)?,
                    action: r.get(3)?,
                    target: r.get(4)?,
                    details_json: r.get(5)?,
                })
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }
}

pub(crate) fn insert_audit_log_tx(tx: &Transaction<'_>, a: &NewAuditLog) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO audit_log(ts, actor, action, target, details_json) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![a.ts, a.actor, a.action, a.target, a.details_json],
    )?;
    Ok(())
}

fn expire_where(
    conn: &mut Connection,
    now: &str,
    resolved_by: &str,
    condition: &str,
) -> Result<Vec<ExpiredApproval>, StoreError> {
    with_full_sync(conn, |tx| {
        let sql = format!(
            "UPDATE approvals SET status='expired', outcome='expired', resolved_by='{resolved_by}', resolved_at=?1 \
             WHERE status='pending' AND {condition} RETURNING request_id, session_key"
        );
        let expired: Vec<ExpiredApproval> = {
            let mut stmt = tx.prepare(&sql)?;
            let rows = stmt.query_map([now], |r| {
                Ok(ExpiredApproval {
                    request_id: r.get(0)?,
                    session_key: r.get(1)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        for e in &expired {
            insert_audit_tx(
                tx,
                &NewApprovalAudit {
                    request_id: e.request_id.clone(),
                    ts: now.to_owned(),
                    actor: "daemon".to_owned(),
                    action: "expired".to_owned(),
                    detail_json: Some(json!({ "by": resolved_by }).to_string()),
                },
            )?;
        }
        Ok(expired)
    })
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    pub fn new_approval(id: &str, session: &str, created_ms: i64, ttl_ms: i64) -> NewApproval {
        NewApproval {
            request_id: id.to_owned(),
            nonce: vec![7u8; 16],
            session_key: session.to_owned(),
            agent_kind: "claude_code".to_owned(),
            agent_id: "abc123".to_owned(),
            origin: "claude_code.hook.http".to_owned(),
            native_binding_json: "{}".to_owned(),
            tool_name: "Bash".to_owned(),
            tool_kind: "command".to_owned(),
            tool_input_sha256: vec![9u8; 32],
            created_at: format_ms(created_ms),
            expires_at: format_ms(created_ms + ttl_ms),
            title: "명령을 실행하려고 해요".to_owned(),
            purpose: Some("node_modules 를 지워요".to_owned()),
            details_json: Some(
                "{\"kind\":\"command\",\"command\":\"rm -rf node_modules\"}".to_owned(),
            ),
            risk_level: "high".to_owned(),
            risk_reasons_json: "[\"recursive_delete\"]".to_owned(),
            extra_confirmation: "hold".to_owned(),
            allowed_decisions_json: "[\"allow\",\"deny\",\"deny_and_stop\"]".to_owned(),
            permission_mode: Some("default".to_owned()),
        }
    }

    pub fn resolve_request(id: &str, decision_id: &str, now_ms: i64) -> ResolveRequest {
        ResolveRequest {
            request_id: id.to_owned(),
            outcome: "allowed".to_owned(),
            resolved_by: "desktop".to_owned(),
            resolved_device_id: None,
            now: format_ms(now_ms),
            decision_id: decision_id.to_owned(),
            actor: "desktop".to_owned(),
            decision: "allow".to_owned(),
            decided_at: format_ms(now_ms),
            auth_method: Some("biometric".to_owned()),
            extra_confirmation: Some("hold".to_owned()),
            auth_json: Some("{\"method\":\"biometric\"}".to_owned()),
            signature: None,
            audit_actor: "desktop".to_owned(),
            audit_detail_json: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use std::sync::Arc;

    const T0: i64 = 1_760_000_000_000;

    #[test]
    fn insert_get_and_the_opened_audit_snapshot() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(
            s.insert_approval(
                new_approval("ar_1", "claude_code:7f1e2d3c-4b5a", T0, 120_000),
                2_000
            )
            .unwrap(),
            InsertApproval::Inserted
        );
        let row = s.get_approval("ar_1").unwrap().unwrap();
        assert_eq!(row.status, "pending");
        assert_eq!(row.observed_result, "unknown");
        assert_eq!(row.delivered_to_json, "{}");
        assert_eq!(row.tool_input_sha256, vec![9u8; 32]);
        let audit = s.list_approval_audit("ar_1").unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, "opened");
        let snap: serde_json::Value =
            serde_json::from_str(audit[0].detail_json.as_deref().unwrap()).unwrap();
        assert_eq!(snap["session_key"], "claude_code:");
        assert_eq!(snap["tool_name"], "Bash");
        assert_eq!(snap["risk_level"], "high");
        assert_eq!(snap["risk_reasons"][0], "recursive_delete");
        assert_eq!(snap["tool_input_sha256"], "09".repeat(32));
        assert!(
            !audit[0]
                .detail_json
                .as_deref()
                .unwrap()
                .contains("node_modules"),
            "no command text in the audit snapshot"
        );
        assert!(s.get_approval("nope").unwrap().is_none());
    }

    #[test]
    fn invalid_inputs_are_rejected_before_any_write() {
        let s = Store::open_in_memory().unwrap();
        let mut bad = new_approval("ar_x", "s", T0, 1000);
        bad.nonce = vec![1; 3];
        assert!(matches!(
            s.insert_approval(bad, 0),
            Err(StoreError::Invalid(_))
        ));
        let mut huge = new_approval("ar_y", "s", T0, 1000);
        huge.details_json = Some("x".repeat(20_000));
        assert!(matches!(
            s.insert_approval(huge, 0),
            Err(StoreError::Invalid(_))
        ));
        assert!(s.list_pending_approvals(None).unwrap().is_empty());
    }

    #[test]
    fn duplicate_hooks_merge_only_inside_the_window_and_for_the_same_agent() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(
            s.insert_approval(new_approval("ar_1", "s", T0, 120_000), 2_000)
                .unwrap(),
            InsertApproval::Inserted
        );
        // same key 1.5 s later: one card
        assert_eq!(
            s.insert_approval(new_approval("ar_2", "s", T0 + 1_500, 120_000), 2_000)
                .unwrap(),
            InsertApproval::Merged {
                request_id: "ar_1".to_owned()
            }
        );
        // a different sub-agent: a second card
        let mut other_agent = new_approval("ar_3", "s", T0 + 1_600, 120_000);
        other_agent.agent_id = "def456".to_owned();
        assert_eq!(
            s.insert_approval(other_agent, 2_000).unwrap(),
            InsertApproval::Inserted
        );
        // the same key 5 s later: a second card
        assert_eq!(
            s.insert_approval(new_approval("ar_4", "s", T0 + 5_000, 120_000), 2_000)
                .unwrap(),
            InsertApproval::Inserted
        );
        // merge window 0 never merges
        assert_eq!(
            s.insert_approval(new_approval("ar_5", "s", T0 + 5_100, 120_000), 0)
                .unwrap(),
            InsertApproval::Inserted
        );
        // a different tool input hash is a different card
        let mut other_input = new_approval("ar_6", "s", T0 + 5_200, 120_000);
        other_input.tool_input_sha256 = vec![1u8; 32];
        assert_eq!(
            s.insert_approval(other_input, 2_000).unwrap(),
            InsertApproval::Inserted
        );
        assert_eq!(s.list_pending_approvals(None).unwrap().len(), 5);
        // only resolved/closed cards stop merging
        s.resolve_approval_conditional(resolve_request("ar_4", "d1", T0 + 5_300))
            .unwrap();
        assert_eq!(
            s.insert_approval(new_approval("ar_7", "s", T0 + 5_400, 120_000), 2_000)
                .unwrap(),
            InsertApproval::Merged {
                request_id: "ar_5".to_owned()
            }
        );
    }

    #[test]
    fn a_request_without_an_agent_id_never_merges() {
        let s = Store::open_in_memory().unwrap();
        for (i, dt) in [0, 100, 900].into_iter().enumerate() {
            let mut n = new_approval(&format!("ar_{i}"), "s", T0 + dt, 120_000);
            n.agent_id = String::new();
            assert_eq!(
                s.insert_approval(n, 2_000).unwrap(),
                InsertApproval::Inserted,
                "identical requests without an agent_id are separate cards, even inside the window"
            );
        }
        assert_eq!(s.list_pending_approvals(None).unwrap().len(), 3);
    }

    #[test]
    fn conditional_resolve_applies_once_and_records_everything() {
        let s = Store::open_in_memory().unwrap();
        s.insert_approval(new_approval("ar_1", "s", T0, 120_000), 0)
            .unwrap();
        let r = s
            .resolve_approval_conditional(resolve_request("ar_1", "d1", T0 + 10_000))
            .unwrap();
        assert_eq!(r, ResolveOutcome::Applied);
        let row = s.get_approval("ar_1").unwrap().unwrap();
        assert_eq!(
            (
                row.status.as_str(),
                row.outcome.as_deref(),
                row.resolved_by.as_deref()
            ),
            ("resolved", Some("allowed"), Some("desktop"))
        );
        assert_eq!(row.decision_msg_id.as_deref(), Some("d1"));
        assert_eq!(
            row.resolved_at.as_deref(),
            Some(format_ms(T0 + 10_000).as_str())
        );
        // a second decision (different envelope id) does not apply and is recorded as rejected
        let r2 = s
            .resolve_approval_conditional(resolve_request("ar_1", "d2", T0 + 11_000))
            .unwrap();
        assert_eq!(r2, ResolveOutcome::NotApplied(NotApplied::AlreadyResolved));
        let decisions = s.list_decisions("ar_1").unwrap();
        assert_eq!(
            decisions
                .iter()
                .map(|d| (d.id.as_str(), d.verify_result.as_str()))
                .collect::<Vec<_>>(),
            vec![("d1", "APPLIED"), ("d2", "ALREADY_RESOLVED")]
        );
        let actions: Vec<String> = s
            .list_approval_audit("ar_1")
            .unwrap()
            .into_iter()
            .map(|a| a.action)
            .collect();
        assert_eq!(
            actions,
            vec!["opened", "decision_received", "decision_rejected"]
        );
        // the stored approval still shows the first decision
        assert_eq!(
            s.get_approval("ar_1")
                .unwrap()
                .unwrap()
                .decision_msg_id
                .as_deref(),
            Some("d1")
        );
        // idempotency lookup: only an APPLIED decision of the same id, request and actor is a replay
        assert_eq!(
            s.decision_verify_result("d1").unwrap().as_deref(),
            Some("APPLIED")
        );
        assert_eq!(s.decision_verify_result("nope").unwrap(), None);
        let actor = resolve_request("ar_1", "d1", 0).actor;
        assert!(s.decision_applied_replay("d1", "ar_1", &actor).unwrap());
        assert!(!s.decision_applied_replay("d1", "ar_2", &actor).unwrap(), "another request");
        assert!(!s.decision_applied_replay("d1", "ar_1", "device:other").unwrap(), "another actor");
        assert!(!s.decision_applied_replay("nope", "ar_1", &actor).unwrap());
        // re-sending the same envelope id is just another recorded attempt (stored under a derived id, the original
        // row stays): the request is already resolved, nothing changes in `approvals`
        let again = s
            .resolve_approval_conditional(resolve_request("ar_1", "d1", T0 + 12_000))
            .unwrap();
        assert_eq!(again, ResolveOutcome::NotApplied(NotApplied::AlreadyResolved));
        assert_eq!(s.list_decisions("ar_1").unwrap().len(), 3);
        assert_eq!(s.decision_verify_result("d1").unwrap().as_deref(), Some("APPLIED"));
        assert_eq!(s.decision_verify_result("d1#1").unwrap().as_deref(), Some("ALREADY_RESOLVED"));
    }

    #[test]
    fn expired_and_unknown_requests_are_not_applied() {
        let s = Store::open_in_memory().unwrap();
        s.insert_approval(new_approval("ar_1", "s", T0, 120_000), 0)
            .unwrap();
        // exactly at expires_at the decision is too late (`expires_at > now` is strict)
        let r = s
            .resolve_approval_conditional(resolve_request("ar_1", "d1", T0 + 120_000))
            .unwrap();
        assert_eq!(r, ResolveOutcome::NotApplied(NotApplied::Expired));
        assert_eq!(
            s.get_approval("ar_1").unwrap().unwrap().status,
            "pending",
            "an expired decision changes nothing"
        );
        // one millisecond earlier it applies
        let r = s
            .resolve_approval_conditional(resolve_request("ar_1", "d2", T0 + 119_999))
            .unwrap();
        assert_eq!(r, ResolveOutcome::Applied);
        let r = s
            .resolve_approval_conditional(resolve_request("nope", "d3", T0))
            .unwrap();
        assert_eq!(r, ResolveOutcome::NotApplied(NotApplied::UnknownRequest));
        assert_eq!(NotApplied::Expired.as_reason(), "EXPIRED");
        assert_eq!(
            s.list_decisions("nope").unwrap()[0].verify_result,
            "UNKNOWN_REQUEST"
        );
    }

    #[test]
    fn concurrent_double_resolve_has_exactly_one_winner() {
        let s = Store::open_in_memory().unwrap();
        s.insert_approval(new_approval("ar_1", "s", T0, 120_000), 0)
            .unwrap();
        let s = Arc::new(s);
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let s = s.clone();
                std::thread::spawn(move || {
                    s.resolve_approval_conditional(resolve_request(
                        "ar_1",
                        &format!("d{i}"),
                        T0 + 1_000,
                    ))
                    .unwrap()
                })
            })
            .collect();
        let results: Vec<ResolveOutcome> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == ResolveOutcome::Applied)
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, ResolveOutcome::NotApplied(NotApplied::AlreadyResolved)))
                .count(),
            15
        );
        assert_eq!(
            s.list_decisions("ar_1").unwrap().len(),
            16,
            "every attempt is evidence"
        );
    }

    #[test]
    fn two_connections_to_one_file_also_have_one_winner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("race.db");
        let a = Store::open(&path).unwrap();
        let b = Store::open(&path).unwrap();
        a.insert_approval(new_approval("ar_1", "s", T0, 120_000), 0)
            .unwrap();
        let (a2, b2) = (a.clone(), b.clone());
        let ha = std::thread::spawn(move || {
            a2.resolve_approval_conditional(resolve_request("ar_1", "da", T0 + 1_000))
                .unwrap()
        });
        let hb = std::thread::spawn(move || {
            b2.resolve_approval_conditional(resolve_request("ar_1", "db", T0 + 1_000))
                .unwrap()
        });
        let results = [ha.join().unwrap(), hb.join().unwrap()];
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == ResolveOutcome::Applied)
                .count(),
            1,
            "{results:?}"
        );
    }

    #[test]
    fn resolve_runs_with_synchronous_full_and_restores_normal() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("sync.db")).unwrap();
        s.insert_approval(new_approval("ar_1", "s", T0, 120_000), 0)
            .unwrap();
        s.resolve_approval_conditional(resolve_request("ar_1", "d1", T0 + 1))
            .unwrap();
        assert_eq!(
            s.pragma_synchronous().unwrap(),
            1,
            "NORMAL after the transition"
        );
    }

    #[test]
    fn expiry_timer_and_startup_expiry() {
        let s = Store::open_in_memory().unwrap();
        s.insert_approval(new_approval("ar_1", "s1", T0, 60_000), 0)
            .unwrap();
        s.insert_approval(new_approval("ar_2", "s2", T0 + 1, 180_000), 0)
            .unwrap();
        assert!(s.expire_due(&format_ms(T0 + 59_999)).unwrap().is_empty());
        let due = s.expire_due(&format_ms(T0 + 60_000)).unwrap();
        assert_eq!(
            due,
            vec![ExpiredApproval {
                request_id: "ar_1".to_owned(),
                session_key: "s1".to_owned()
            }]
        );
        let row = s.get_approval("ar_1").unwrap().unwrap();
        assert_eq!(
            (
                row.status.as_str(),
                row.outcome.as_deref(),
                row.resolved_by.as_deref()
            ),
            ("expired", Some("expired"), Some("timeout"))
        );
        assert!(
            s.expire_due(&format_ms(T0 + 70_000)).unwrap().is_empty(),
            "only pending rows are touched"
        );
        let started = s
            .expire_all_pending_on_startup(&format_ms(T0 + 100_000))
            .unwrap();
        assert_eq!(started.len(), 1);
        assert_eq!(started[0].request_id, "ar_2");
        let row = s.get_approval("ar_2").unwrap().unwrap();
        assert_eq!(
            (row.status.as_str(), row.resolved_by.as_deref()),
            ("expired", Some("system"))
        );
        assert!(s.list_pending_approvals(None).unwrap().is_empty());
        let actions: Vec<String> = s
            .list_approval_audit("ar_2")
            .unwrap()
            .into_iter()
            .map(|a| a.action)
            .collect();
        assert_eq!(actions, vec!["opened", "expired"]);
    }

    #[test]
    fn close_approval_is_conditional() {
        let s = Store::open_in_memory().unwrap();
        s.insert_approval(new_approval("ar_1", "s", T0, 120_000), 0)
            .unwrap();
        let close = |status, now| CloseRequest {
            request_id: "ar_1".to_owned(),
            status,
            resolved_by: "system".to_owned(),
            now: format_ms(now),
            audit_actor: "daemon".to_owned(),
            audit_action: "handed_off".to_owned(),
            audit_detail_json: None,
        };
        assert!(s
            .close_approval(close(CloseStatus::HandedOffLocal, T0 + 1))
            .unwrap());
        assert!(
            !s.close_approval(close(CloseStatus::Superseded, T0 + 2))
                .unwrap(),
            "already closed"
        );
        let row = s.get_approval("ar_1").unwrap().unwrap();
        assert_eq!(
            (row.status.as_str(), row.outcome.as_deref()),
            ("handed_off_local", Some("handed_off_local"))
        );
        // a decision after the hand-off is rejected
        assert_eq!(
            s.resolve_approval_conditional(resolve_request("ar_1", "late", T0 + 3))
                .unwrap(),
            ResolveOutcome::NotApplied(NotApplied::AlreadyResolved)
        );
        for (st, text) in [
            (CloseStatus::Expired, "expired"),
            (CloseStatus::Superseded, "superseded"),
            (CloseStatus::Failed, "failed"),
        ] {
            assert_eq!(st.as_str(), text);
        }
    }

    #[test]
    fn delivery_observation_and_audit_helpers() {
        let s = Store::open_in_memory().unwrap();
        s.insert_approval(new_approval("ar_1", "s", T0, 120_000), 0)
            .unwrap();
        s.set_delivery("ar_1", true, &format_ms(T0 + 1)).unwrap();
        s.set_observed_result("ar_1", "executed", "ev1", &format_ms(T0 + 2))
            .unwrap();
        assert!(s
            .set_observed_result("ar_1", "maybe", "ev1", &format_ms(T0))
            .is_err());
        s.set_delivered_to("ar_1", "{\"dev_1\":{\"sent_at\":\"x\"}}")
            .unwrap();
        let row = s.get_approval("ar_1").unwrap().unwrap();
        assert_eq!(row.delivery.as_deref(), Some("delivered"));
        assert_eq!(row.observed_result, "executed");
        assert_eq!(row.observed_event_id.as_deref(), Some("ev1"));
        assert!(row.delivered_to_json.contains("dev_1"));
        s.insert_approval_audit(NewApprovalAudit {
            request_id: "ar_1".into(),
            ts: format_ms(T0 + 3),
            actor: "phone:dev_1".into(),
            action: "late_decision".into(),
            detail_json: None,
        })
        .unwrap();
        let actions: Vec<String> = s
            .list_approval_audit("ar_1")
            .unwrap()
            .into_iter()
            .map(|a| a.action)
            .collect();
        assert_eq!(
            actions,
            vec!["opened", "delivered", "observed", "late_decision"]
        );
        s.insert_audit_log(NewAuditLog {
            ts: format_ms(T0),
            actor: "system".into(),
            action: "hooks_installed".into(),
            target: Some("claude_code".into()),
            details_json: None,
        })
        .unwrap();
        let log = s.list_audit_log(10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].action, "hooks_installed");
        assert!(s
            .insert_audit_log(NewAuditLog {
                ts: String::new(),
                actor: "x".into(),
                action: "y".into(),
                target: None,
                details_json: Some("z".repeat(20_000))
            })
            .is_err());
    }

    #[test]
    fn rejected_attempts_can_be_stored_without_a_resolve() {
        let s = Store::open_in_memory().unwrap();
        s.insert_approval(new_approval("ar_1", "s", T0, 120_000), 0)
            .unwrap();
        s.insert_decision(NewDecision {
            id: "dx".into(),
            request_id: "ar_1".into(),
            actor: "device:dev_1".into(),
            decision: "allow".into(),
            decided_at: format_ms(T0),
            received_at: format_ms(T0),
            auth_method: Some("none".into()),
            extra_confirmation: None,
            verify_result: "AUTH_REQUIRED".into(),
            signature: None,
        })
        .unwrap();
        assert_eq!(
            s.decision_verify_result("dx").unwrap().as_deref(),
            Some("AUTH_REQUIRED")
        );
        assert_eq!(s.get_approval("ar_1").unwrap().unwrap().status, "pending");
    }

    #[test]
    fn a_panic_inside_the_transition_rolls_everything_back() {
        let s = Store::open_in_memory().unwrap();
        s.insert_approval(new_approval("ar_1", "s", T0, 120_000), 0)
            .unwrap();
        let r: Result<(), _> = s.run(|conn| {
            with_full_sync(conn, |tx| {
                tx.execute("UPDATE approvals SET status='resolved', outcome='allowed' WHERE request_id='ar_1'", [])?;
                panic!("panic between the UPDATE and the commit");
            })
        });
        assert!(matches!(r, Err(StoreError::Panicked(_))));
        assert_eq!(s.get_approval("ar_1").unwrap().unwrap().status, "pending");
        assert_eq!(s.pragma_synchronous().unwrap(), 1);
    }

    #[test]
    fn check_constraints_reject_unknown_statuses() {
        let s = Store::open_in_memory().unwrap();
        s.insert_approval(new_approval("ar_1", "s", T0, 120_000), 0)
            .unwrap();
        let r = s.run(|c| {
            Ok(c.execute(
                "UPDATE approvals SET status='approved' WHERE request_id='ar_1'",
                [],
            )?)
        });
        assert!(r.is_err());
        let r = s.run(|c| {
            Ok(c.execute(
                "UPDATE approvals SET risk_level='none' WHERE request_id='ar_1'",
                [],
            )?)
        });
        assert!(r.is_err());
    }
}
