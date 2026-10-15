//! `approvals_history(limit)`: the "last 50 requests" list of the approvals screen (docs/desktop.md 3.1).
//!
//! A read-only query over the `approvals` table the broker writes (docs/storage.md). Only display fields come out:
//! title, tool name, risk level, outcome, who resolved it and the deciding phone's name. Nothing from `details_json`
//! (the command), the nonce or the hash is selected.

use agentnest_core::store::{Store, StoreError};
use rusqlite::params;

use crate::dto::HistoryEntry;

/// Most rows one call returns.
pub const HISTORY_MAX: u32 = 200;

/// The newest resolved requests, newest first. `limit` is clamped to `1..=200`.
pub fn approvals_history(store: &Store, limit: u32) -> Result<Vec<HistoryEntry>, StoreError> {
    let limit = i64::from(limit.clamp(1, HISTORY_MAX));
    store.read(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT a.request_id, a.title, a.tool_name, a.risk_level, \
                    COALESCE(a.outcome, a.status), \
                    COALESCE(a.resolved_by, CASE a.status WHEN 'expired' THEN 'timeout' ELSE 'system' END), \
                    d.name, COALESCE(a.resolved_at, a.expires_at) \
             FROM approvals a LEFT JOIN devices d ON d.device_id = a.resolved_device_id \
             WHERE a.status <> 'pending' \
             ORDER BY COALESCE(a.resolved_at, a.expires_at) DESC, a.request_id DESC \
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            Ok(HistoryEntry {
                request_id: r.get(0)?,
                title: r.get(1)?,
                tool_name: r.get(2)?,
                risk_level: r.get(3)?,
                outcome: r.get(4)?,
                resolved_by: r.get(5)?,
                resolved_device_name: r.get(6)?,
                resolved_at: r.get(7)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    })
}

/// The last event time per agent kind (`daemon_status.last_event_at`), read from the small `sessions` table.
pub fn last_event_times(store: &Store) -> Result<Vec<(String, String)>, StoreError> {
    store.read(|conn| {
        let mut stmt = conn
            .prepare("SELECT agent_kind, MAX(last_event_at) FROM sessions GROUP BY agent_kind")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentnest_core::store::NewApproval;

    fn approval(id: &str, created_ms: i64) -> NewApproval {
        NewApproval {
            request_id: id.to_owned(),
            nonce: vec![7u8; 16],
            session_key: "claude_code:s1".to_owned(),
            agent_kind: "claude_code".to_owned(),
            agent_id: String::new(),
            origin: "claude_code.hook.http".to_owned(),
            native_binding_json: "{}".to_owned(),
            tool_name: "Bash".to_owned(),
            tool_kind: "command".to_owned(),
            tool_input_sha256: vec![9u8; 32],
            created_at: agentnest_core::state::timers::format_ms(created_ms),
            expires_at: agentnest_core::state::timers::format_ms(created_ms + 120_000),
            title: "명령 실행".to_owned(),
            purpose: None,
            details_json: Some("{\"command\":\"rm -rf /very/secret\"}".to_owned()),
            risk_level: "high".to_owned(),
            risk_reasons_json: "[]".to_owned(),
            extra_confirmation: "hold".to_owned(),
            allowed_decisions_json: "[\"allow\",\"deny\"]".to_owned(),
            permission_mode: None,
        }
    }

    fn store_with_rows() -> Store {
        let store = Store::open_in_memory().unwrap();
        for (i, id) in ["ar_1", "ar_2", "ar_3", "ar_4"].iter().enumerate() {
            store
                .insert_approval(approval(id, 1_792_000_000_000 + (i as i64) * 1000), 0)
                .unwrap();
        }
        store
            .run(|c| {
                c.execute(
                    "INSERT INTO devices(device_id, name, platform, token_hash, paired_at) \
                     VALUES ('dev_1', 'Pixel 9', 'android', x'01', '2026-10-01T00:00:00.000Z')",
                    [],
                )?;
                c.execute(
                    "UPDATE approvals SET status='resolved', outcome='allowed', resolved_by='phone', \
                     resolved_device_id='dev_1', resolved_at='2026-10-15T09:00:10.000Z' WHERE request_id='ar_1'",
                    [],
                )?;
                c.execute(
                    "UPDATE approvals SET status='resolved', outcome='denied', resolved_by='desktop', \
                     resolved_at='2026-10-15T09:00:20.000Z' WHERE request_id='ar_2'",
                    [],
                )?;
                c.execute(
                    "UPDATE approvals SET status='expired', outcome='expired' WHERE request_id='ar_3'",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        store
    }

    #[test]
    fn history_lists_resolved_requests_newest_first_without_pending_ones() {
        let store = store_with_rows();
        let h = approvals_history(&store, 50).unwrap();
        let ids: Vec<&str> = h.iter().map(|e| e.request_id.as_str()).collect();
        // ar_4 is still pending; ar_3 expired without resolved_at (its expiry time counts)
        assert_eq!(ids.len(), 3);
        assert!(!ids.contains(&"ar_4"));
        assert_eq!(h[0].request_id, "ar_2");
        assert_eq!(h[1].request_id, "ar_1");
        let phone = h.iter().find(|e| e.request_id == "ar_1").unwrap();
        assert_eq!(phone.outcome, "allowed");
        assert_eq!(phone.resolved_by, "phone");
        assert_eq!(phone.resolved_device_name.as_deref(), Some("Pixel 9"));
        assert_eq!(phone.title, "명령 실행");
        assert_eq!(phone.risk_level, "high");
        let expired = h.iter().find(|e| e.request_id == "ar_3").unwrap();
        assert_eq!(expired.outcome, "expired");
        assert_eq!(expired.resolved_by, "timeout");
        assert_eq!(expired.resolved_device_name, None);
        let desktop = h.iter().find(|e| e.request_id == "ar_2").unwrap();
        assert_eq!(desktop.resolved_by, "desktop");
    }

    #[test]
    fn history_never_carries_the_command_or_the_nonce() {
        let store = store_with_rows();
        let text = serde_json::to_string(&approvals_history(&store, 50).unwrap()).unwrap();
        assert!(!text.contains("secret"));
        assert!(!text.contains("nonce"));
    }

    #[test]
    fn limit_is_clamped() {
        let store = store_with_rows();
        assert_eq!(approvals_history(&store, 1).unwrap().len(), 1);
        assert_eq!(approvals_history(&store, 0).unwrap().len(), 1);
        assert_eq!(approvals_history(&store, u32::MAX).unwrap().len(), 3);
    }

    #[test]
    fn an_empty_store_gives_an_empty_list() {
        let store = Store::open_in_memory().unwrap();
        assert!(approvals_history(&store, 50).unwrap().is_empty());
        assert!(last_event_times(&store).unwrap().is_empty());
    }
}
