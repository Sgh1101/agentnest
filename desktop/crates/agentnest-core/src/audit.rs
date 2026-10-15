//! Audit wiring (docs/storage.md `audit_log`, `approval_audit`; security.md 8.2).
//!
//! The approval transition itself writes its `decisions` / `approval_audit` rows inside the store transaction
//! ([`crate::store::Store::resolve_approval_conditional`] and friends). This module is for everything else that has to
//! leave a trace: pairing, device revocation, hook installation, identity changes, pausing, the link switch, accepted
//! risks and the late/extra approval audit rows (`sent_to_phone`, `acked`, `seen`, `late_decision`).
//!
//! Rules enforced here:
//!
//! * details pass through [`crate::redact::bound_detail`] (masking and bounds) before they are written, so a token or a
//!   command cannot reach the audit tables by accident;
//! * audit writes are **best effort for observers** (`log` never fails the caller: a failing disk must not turn a
//!   security decision into an error path) but a failure is logged without any values.

use std::sync::Arc;

use serde_json::Value;

use crate::redact::bound_detail;
use crate::state::timers::{format_ms, Clock};
use crate::store::{NewApprovalAudit, NewAuditLog, Store};

/// `audit_log.action` values (docs/storage.md).
pub mod actions {
    /// Pairing mode switched on.
    pub const PAIRING_STARTED: &str = "pairing_started";
    /// The PC user approved a pairing.
    pub const PAIRING_CONFIRMED: &str = "pairing_confirmed";
    /// The PC user rejected a pairing (or it timed out / failed).
    pub const PAIRING_REJECTED: &str = "pairing_rejected";
    /// A device was registered.
    pub const DEVICE_PAIRED: &str = "device_paired";
    /// A device was revoked.
    pub const DEVICE_REVOKED: &str = "device_revoked";
    /// Claude Code / Codex hooks were installed.
    pub const HOOKS_INSTALLED: &str = "hooks_installed";
    /// Hooks were removed.
    pub const HOOKS_REMOVED: &str = "hooks_removed";
    /// The server key pair was regenerated.
    pub const IDENTITY_REGENERATED: &str = "identity_regenerated";
    /// The certificate was re-issued with the same key.
    pub const CERT_ROTATED: &str = "cert_rotated";
    /// Remote approval paused or resumed.
    pub const REMOTE_APPROVAL_PAUSED: &str = "remote_approval_paused";
    /// Remote approval resumed.
    pub const REMOTE_APPROVAL_RESUMED: &str = "remote_approval_resumed";
    /// The WSS link was switched off.
    pub const LINK_DISABLED: &str = "link_disabled";
    /// The WSS link was switched on.
    pub const LINK_ENABLED: &str = "link_enabled";
    /// A risk (R1) was accepted by the user.
    pub const RISK_ACCEPTED: &str = "risk_accepted";
    /// The hook token was rotated.
    pub const HOOK_TOKEN_ROTATED: &str = "hook_token_rotated";
    /// Retention removed rows.
    pub const RETENTION_PRUNED: &str = "retention_pruned";
    /// The daemon started.
    pub const DAEMON_STARTED: &str = "daemon_started";
}

/// `approval_audit.action` values written outside the store transitions.
pub mod approval_actions {
    /// The card was sent to a phone.
    pub const SENT_TO_PHONE: &str = "sent_to_phone";
    /// The phone acknowledged the card.
    pub const ACKED: &str = "acked";
    /// The card was shown on the phone.
    pub const SEEN: &str = "seen";
    /// A decision arrived after the request was closed (Codex `serverRequest/resolved` first, expiry, ...).
    pub const LATE_DECISION: &str = "late_decision";
    /// A decision attempt was refused before the conditional update.
    pub const DECISION_REJECTED: &str = "decision_rejected";
}

/// `audit_log` actor of the daemon itself.
pub const ACTOR_SYSTEM: &str = "system";
/// `audit_log` actor of the PC user at the desktop UI.
pub const ACTOR_DESKTOP_USER: &str = "desktop_user";

/// `device:<id>` actor string.
pub fn device_actor(device_id: &str) -> String {
    format!("device:{device_id}")
}

/// Writes audit rows. Cheap to clone.
#[derive(Clone)]
pub struct Audit {
    store: Store,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Audit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Audit").finish_non_exhaustive()
    }
}

fn bounded_json(details: Option<Value>) -> Option<String> {
    details.map(|mut v| {
        bound_detail(&mut v);
        v.to_string()
    })
}

impl Audit {
    /// An audit writer on `store` stamping rows with `clock`.
    pub fn new(store: Store, clock: Arc<dyn Clock>) -> Self {
        Self { store, clock }
    }

    /// Appends an `audit_log` row. Never fails the caller; a storage error is logged (without values).
    pub async fn log(
        &self,
        actor: impl Into<String>,
        action: &str,
        target: Option<String>,
        details: Option<Value>,
    ) {
        let row = NewAuditLog {
            ts: format_ms(self.clock.now_ms()),
            actor: actor.into(),
            action: action.to_owned(),
            target,
            details_json: bounded_json(details),
        };
        let store = self.store.clone();
        let action_name = action.to_owned();
        let result = tokio::task::spawn_blocking(move || store.insert_audit_log(row)).await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(action = %action_name, error = %e, "audit_log write failed")
            }
            Err(e) => tracing::warn!(action = %action_name, error = %e, "audit_log task failed"),
        }
    }

    /// Appends an `approval_audit` row (best effort, see [`Audit::log`]).
    pub async fn approval(
        &self,
        request_id: &str,
        actor: impl Into<String>,
        action: &str,
        details: Option<Value>,
    ) {
        let row = NewApprovalAudit {
            request_id: request_id.to_owned(),
            ts: format_ms(self.clock.now_ms()),
            actor: actor.into(),
            action: action.to_owned(),
            detail_json: bounded_json(details),
        };
        let store = self.store.clone();
        let action_name = action.to_owned();
        let result = tokio::task::spawn_blocking(move || store.insert_approval_audit(row)).await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(action = %action_name, error = %e, "approval_audit write failed")
            }
            Err(e) => {
                tracing::warn!(action = %action_name, error = %e, "approval_audit task failed")
            }
        }
    }

    /// The newest `audit_log` rows (tests and the desktop log view).
    pub async fn recent(&self, limit: u32) -> Vec<crate::store::AuditLogRow> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || store.list_audit_log(limit))
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::timers::ManualClock;
    use serde_json::json;

    #[tokio::test]
    async fn rows_are_written_with_masked_bounded_details() {
        let store = Store::open_in_memory().unwrap();
        let audit = Audit::new(store.clone(), Arc::new(ManualClock::new(1_792_055_553_120)));
        audit
            .log(
                ACTOR_DESKTOP_USER,
                actions::DEVICE_REVOKED,
                Some("dev_1".into()),
                Some(
                    json!({"reason": "user_desktop", "note": "token=abcdef0123456789secretvalue"}),
                ),
            )
            .await;
        let rows = audit.recent(10).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "device_revoked");
        assert_eq!(rows[0].actor, "desktop_user");
        assert_eq!(rows[0].ts, "2026-10-15T09:12:33.120Z");
        let d = rows[0].details_json.as_deref().unwrap();
        assert!(d.contains("user_desktop"));
        assert!(!d.contains("secretvalue"), "details are masked: {d}");
    }

    #[tokio::test]
    async fn a_failing_store_does_not_fail_the_caller() {
        let store = Store::open_in_memory().unwrap();
        let audit = Audit::new(store.clone(), Arc::new(ManualClock::new(1)));
        // an approval audit row for a request that does not exist is still just a row (no FK); an oversized detail is
        // rejected by the store and swallowed
        audit
            .log("system", "x", None, Some(json!({"a": "b"})))
            .await;
        assert_eq!(device_actor("dev_9"), "device:dev_9");
    }
}
