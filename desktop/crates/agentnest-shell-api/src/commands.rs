//! The command contract between the shell and the front end (docs/desktop.md 3 / 3.1,
//! `desktop/apps/desktop/src/api/backend.ts` `COMMANDS`).
//!
//! [`COMMAND_NAMES`] and [`COMMAND_ARGS`] are the Rust side of that contract. The tests in `contract_tests.rs` read the
//! TypeScript sources and the glue crate's `commands.rs` as text and fail when a command, an argument name or an error
//! code drifts apart.

/// Name of the Tauri event that carries [`crate::Envelope`]s.
pub const DAEMON_EVENT_NAME: &str = "daemon-event";

/// The `kind` values of the `daemon-event` envelope. `resync` is shell-generated (not a daemon event): the pump lagged
/// behind the daemon and the UI must re-read the approvals, sessions, devices and status (payload `{"missed": n}`).
pub const EVENT_KINDS: [&str; 8] = [
    "event",
    "session_state",
    "approval",
    "device",
    "pairing",
    "adapter",
    "link",
    "resync",
];

/// Every Tauri command, in the order of `COMMANDS` in `backend.ts`.
pub const COMMAND_NAMES: [&str; 27] = [
    "daemon_status",
    "diagnostics_run",
    "firewall_rule_create",
    "firewall_rule_remove",
    "link_set_enabled",
    "risk_accept",
    "pairing_start",
    "pairing_cancel",
    "pairing_confirm",
    "devices_list",
    "device_revoke",
    "sessions_list",
    "events_recent",
    "approvals_pending",
    "approvals_history",
    "approval_handoff_local",
    "approval_decide_local",
    "remote_approval_pause",
    "remote_approval_resume",
    "hooks_install",
    "hooks_uninstall",
    "hooks_status",
    "codex_probe",
    "settings_get",
    "settings_set",
    "logs_open_dir",
    "logs_tail",
];

/// The argument names (snake_case, `#[tauri::command(rename_all = "snake_case")]`) each command takes, besides the
/// injected Tauri state / handle.
pub const COMMAND_ARGS: [(&str, &[&str]); 27] = [
    ("daemon_status", &[]),
    ("diagnostics_run", &[]),
    ("firewall_rule_create", &[]),
    ("firewall_rule_remove", &[]),
    ("link_set_enabled", &["enabled"]),
    ("risk_accept", &["risk_id"]),
    ("pairing_start", &[]),
    ("pairing_cancel", &["pairing_id"]),
    ("pairing_confirm", &["pairing_id", "approve"]),
    ("devices_list", &[]),
    ("device_revoke", &["device_id", "name_typed"]),
    ("sessions_list", &[]),
    ("events_recent", &["session_key", "limit"]),
    ("approvals_pending", &[]),
    ("approvals_history", &["limit"]),
    ("approval_handoff_local", &["request_id"]),
    (
        "approval_decide_local",
        &[
            "request_id",
            "decision",
            "tool_input_sha256",
            "confirm_ack",
            "reason",
        ],
    ),
    ("remote_approval_pause", &[]),
    ("remote_approval_resume", &[]),
    ("hooks_install", &["agent", "mode"]),
    ("hooks_uninstall", &["agent", "mode"]),
    ("hooks_status", &["agent", "mode"]),
    ("codex_probe", &[]),
    ("settings_get", &[]),
    ("settings_set", &["key", "value"]),
    ("logs_open_dir", &[]),
    ("logs_tail", &["limit"]),
];

/// The argument names of `command`, if it exists.
pub fn args_of(command: &str) -> Option<&'static [&'static str]> {
    COMMAND_ARGS
        .iter()
        .find(|(name, _)| *name == command)
        .map(|(_, args)| *args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_args_tables_agree() {
        for (i, name) in COMMAND_NAMES.iter().enumerate() {
            assert_eq!(COMMAND_ARGS[i].0, *name, "same order and names");
        }
        let mut sorted = COMMAND_NAMES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), COMMAND_NAMES.len(), "no duplicates");
    }

    #[test]
    fn args_of_finds_commands() {
        assert_eq!(
            args_of("pairing_confirm"),
            Some(&["pairing_id", "approve"][..])
        );
        assert_eq!(args_of("nope"), None);
    }
}
