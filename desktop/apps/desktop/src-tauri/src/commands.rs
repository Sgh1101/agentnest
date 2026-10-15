//! The `#[tauri::command]` wrappers: one line each into `agentnest_shell_api::ShellApi`.
//!
//! The names and argument names are the contract with `desktop/apps/desktop/src/api` (docs/desktop.md 3.1) and are
//! checked as text by `agentnest-shell-api`'s contract tests, so keep each signature on the pattern
//! `pub async fn name(shell: State<'_, Shell>, arg: Type, ...) -> Result<T, IpcError>`.
//! Argument names are snake_case on the wire (`rename_all = "snake_case"`).

use agentnest_core::daemon::{HookAgent, HooksMode};
use agentnest_protocol::{Decision, SessionState};
use agentnest_shell_api::diagnostics::DiagnosticsReport;
use agentnest_shell_api::dto::{
    CodexProbeDto, DaemonStatusDto, DeviceDto, FirewallResultDto, HistoryEntry, HooksStatusDto,
    PairingStartDto,
};
use agentnest_shell_api::IpcError;
use serde_json::Value;
use tauri::{AppHandle, State};
use tauri_plugin_opener::OpenerExt;

use crate::state::Shell;

#[tauri::command(rename_all = "snake_case")]
pub async fn daemon_status(shell: State<'_, Shell>) -> Result<DaemonStatusDto, IpcError> {
    shell.api.daemon_status().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn diagnostics_run(shell: State<'_, Shell>) -> Result<DiagnosticsReport, IpcError> {
    shell.api.diagnostics_run().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn firewall_rule_create(shell: State<'_, Shell>) -> Result<FirewallResultDto, IpcError> {
    shell.api.firewall_rule_create().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn firewall_rule_remove(shell: State<'_, Shell>) -> Result<FirewallResultDto, IpcError> {
    shell.api.firewall_rule_remove().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn link_set_enabled(shell: State<'_, Shell>, enabled: bool) -> Result<(), IpcError> {
    shell.api.link_set_enabled(enabled).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn risk_accept(shell: State<'_, Shell>, risk_id: String) -> Result<(), IpcError> {
    shell.api.risk_accept(&risk_id).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn pairing_start(shell: State<'_, Shell>) -> Result<PairingStartDto, IpcError> {
    shell.api.pairing_start().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn pairing_cancel(shell: State<'_, Shell>, pairing_id: String) -> Result<(), IpcError> {
    shell.api.pairing_cancel(&pairing_id).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn pairing_confirm(
    shell: State<'_, Shell>,
    pairing_id: String,
    approve: bool,
) -> Result<(), IpcError> {
    shell.api.pairing_confirm(&pairing_id, approve).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn devices_list(shell: State<'_, Shell>) -> Result<Vec<DeviceDto>, IpcError> {
    shell.api.devices_list().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn device_revoke(
    shell: State<'_, Shell>,
    device_id: String,
    name_typed: String,
) -> Result<(), IpcError> {
    shell.api.device_revoke(&device_id, &name_typed).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn sessions_list(shell: State<'_, Shell>) -> Result<Vec<SessionState>, IpcError> {
    shell.api.sessions_list().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn events_recent(
    shell: State<'_, Shell>,
    session_key: Option<String>,
    limit: u32,
) -> Result<Vec<Value>, IpcError> {
    shell.api.events_recent(session_key, limit).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn approvals_pending(shell: State<'_, Shell>) -> Result<Vec<Value>, IpcError> {
    shell.api.approvals_pending().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn approvals_history(
    shell: State<'_, Shell>,
    limit: u32,
) -> Result<Vec<HistoryEntry>, IpcError> {
    shell.api.approvals_history(limit).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn approval_handoff_local(
    shell: State<'_, Shell>,
    request_id: String,
) -> Result<(), IpcError> {
    shell.api.approval_handoff_local(&request_id).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn approval_decide_local(
    shell: State<'_, Shell>,
    request_id: String,
    decision: Decision,
    tool_input_sha256: String,
    confirm_ack: bool,
    reason: Option<String>,
) -> Result<(), IpcError> {
    shell
        .api
        .approval_decide_local(
            &request_id,
            decision,
            &tool_input_sha256,
            confirm_ack,
            reason,
        )
        .await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn remote_approval_pause(shell: State<'_, Shell>) -> Result<(), IpcError> {
    shell.api.remote_approval_pause(true).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn remote_approval_resume(shell: State<'_, Shell>) -> Result<(), IpcError> {
    shell.api.remote_approval_pause(false).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn hooks_install(
    shell: State<'_, Shell>,
    agent: HookAgent,
    mode: HooksMode,
) -> Result<HooksStatusDto, IpcError> {
    shell.api.hooks_install(agent, mode).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn hooks_uninstall(
    shell: State<'_, Shell>,
    agent: HookAgent,
    mode: HooksMode,
) -> Result<HooksStatusDto, IpcError> {
    // removal does not depend on the mode; the argument exists for the uniform `hooks_*` shape
    let _ = mode;
    shell.api.hooks_uninstall(agent).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn hooks_status(
    shell: State<'_, Shell>,
    agent: HookAgent,
    mode: HooksMode,
) -> Result<HooksStatusDto, IpcError> {
    let _ = mode;
    shell.api.hooks_status(agent).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn codex_probe(shell: State<'_, Shell>) -> Result<CodexProbeDto, IpcError> {
    shell.api.codex_probe().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn settings_get(shell: State<'_, Shell>) -> Result<Value, IpcError> {
    shell.api.settings_get().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn settings_set(
    shell: State<'_, Shell>,
    key: String,
    value: Value,
) -> Result<Value, IpcError> {
    shell.api.settings_set(&key, value).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn logs_open_dir(app: AppHandle, shell: State<'_, Shell>) -> Result<(), IpcError> {
    let dir = shell.api.logs_dir();
    std::fs::create_dir_all(&dir).map_err(|_| IpcError::internal())?;
    app.opener()
        .reveal_item_in_dir(&dir)
        .map_err(|_| IpcError::internal())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn logs_tail(shell: State<'_, Shell>, limit: u32) -> Result<Vec<String>, IpcError> {
    shell.api.logs_tail(limit).await
}
