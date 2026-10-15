//! [`ShellApi`]: one method per Tauri command, plus the event processing and tray measurements the glue needs.
//!
//! The glue crate keeps an `Arc<ShellApi>` in Tauri's managed state and every `#[tauri::command]` is a one line call
//! into a method here. Nothing in this file creates an allow reply: local approvals go through
//! `DaemonHandle::approval_decide_local`, the broker's single transition (security.md 6.2.1), and the broker, not this
//! code, decides whether a decision is applied.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentnest_core::audit::{Audit, ACTOR_DESKTOP_USER};
use agentnest_core::daemon::{CommandError, DaemonCommand, DaemonHandle, HookAgent, HooksMode};
use agentnest_core::events::DaemonEvent;
use agentnest_core::redact::{clip, sanitize_display_text};
use agentnest_core::state::timers::{format_ms, Clock};
use agentnest_protocol::{AgentState, Decision, SessionState};
use serde_json::{json, Value};
use tokio::sync::Mutex as AsyncMutex;

use crate::codex;
use crate::diagnostics::{build_report, DiagnosticsInput, DiagnosticsReport};
use crate::dto::{
    agent_event_value, pending_overview_value, CodexProbeDto, DaemonStatusDto, DeviceDto,
    FirewallResultDto, HistoryEntry, HooksStatusDto, LastEventAt, PairingStartDto,
};
use crate::error::{code, Ctx, IpcError};
use crate::events::{Envelope, EventMapper, Mapped, Notification, ShellAction};
use crate::history::{approvals_history, last_event_times};
use crate::logs::tail_log_lines;
use crate::net::{rule_name, ElevatedOutcome, NetworkOps, NetworkProfile, DEFAULT_LINK_PORT};
use crate::settings::{apply_setting, settings_value, SettingError, UiSettingsStore};
use crate::tray::{tray_gate, CodexLine, PendingBrief, TrayInput};

/// How long a daemon error keeps the tray red.
const DAEMON_ERROR_TRAY_MS: i64 = 60_000;
/// Longest deny reason handed to the daemon.
const REASON_MAX_CHARS: usize = 200;

/// Construction parameters.
#[derive(Clone, Debug)]
pub struct ShellApiOptions {
    /// The running executable (the firewall rule is scoped to it).
    pub exe_path: PathBuf,
    /// The Codex home directory (`$CODEX_HOME` or `~/.codex`), if known.
    pub codex_home: Option<PathBuf>,
    /// The platform has firewall / profile checks (Windows).
    pub platform_checks: bool,
    /// Timeout of the self-connect test.
    pub self_connect_timeout: Duration,
}

impl ShellApiOptions {
    /// Options for the running process: `exe_path` is supplied by the caller (`std::env::current_exe`), the Codex home
    /// comes from the environment.
    pub fn for_process(exe_path: PathBuf) -> Self {
        let home = directories::BaseDirs::new().map(|d| d.home_dir().to_path_buf());
        let env = std::env::var_os("CODEX_HOME").map(PathBuf::from);
        Self {
            exe_path,
            codex_home: codex::codex_home(env.as_deref(), home.as_deref()),
            platform_checks: cfg!(windows),
            self_connect_timeout: Duration::from_millis(1500),
        }
    }
}

/// The shell's command surface.
pub struct ShellApi {
    daemon: Arc<DaemonHandle>,
    ui: Arc<dyn UiSettingsStore>,
    net: Arc<dyn NetworkOps>,
    clock: Arc<dyn Clock>,
    audit: Audit,
    opts: ShellApiOptions,
    settings_lock: AsyncMutex<()>,
    paused: Arc<AtomicBool>,
    notifications: AtomicBool,
    last_preauth: Mutex<Option<(String, String)>>,
    daemon_error_until_ms: AtomicI64,
    mapper: Mutex<EventMapper>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl ShellApi {
    /// Creates the API around a running daemon.
    pub fn new(
        daemon: Arc<DaemonHandle>,
        ui: Arc<dyn UiSettingsStore>,
        net: Arc<dyn NetworkOps>,
        clock: Arc<dyn Clock>,
        opts: ShellApiOptions,
    ) -> Self {
        let audit = Audit::new(daemon.store().clone(), clock.clone());
        let paused = Arc::new(AtomicBool::new(false));
        let notifications = AtomicBool::new(ui.load().notifications);
        let mapper = Mutex::new(EventMapper::new(clock.clone(), paused.clone()));
        Self {
            daemon,
            ui,
            net,
            clock,
            audit,
            opts,
            settings_lock: AsyncMutex::new(()),
            paused,
            notifications,
            last_preauth: Mutex::new(None),
            daemon_error_until_ms: AtomicI64::new(0),
            mapper,
        }
    }

    /// The daemon (the glue calls `shutdown_blocking` on exit).
    pub fn daemon(&self) -> &Arc<DaemonHandle> {
        &self.daemon
    }

    /// Whether toasts are enabled (`app.notifications`).
    pub fn notifications_enabled(&self) -> bool {
        self.notifications.load(Ordering::Relaxed)
    }

    /// Whether the first-run checklist was completed.
    pub fn onboarding_completed(&self) -> bool {
        self.ui.load().onboarding_completed
    }

    fn core_err(e: &CommandError, ctx: Ctx) -> IpcError {
        IpcError::from_core(e, ctx)
    }

    async fn blocking<T: Send + 'static>(
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, IpcError> {
        tokio::task::spawn_blocking(f)
            .await
            .map_err(|_| IpcError::internal())
    }

    // -----------------------------------------------------------------------------------------------------------------
    // status and diagnostics
    // -----------------------------------------------------------------------------------------------------------------

    /// `daemon_status`.
    pub async fn daemon_status(&self) -> Result<DaemonStatusDto, IpcError> {
        let status = self
            .daemon
            .status()
            .await
            .map_err(|e| Self::core_err(&e, Ctx::Generic))?;
        self.paused
            .store(status.remote_approval_paused, Ordering::Relaxed);
        let store = self.daemon.store().clone();
        // a failing read must not hide the status: the field is "never seen" then
        let times = Self::blocking(move || last_event_times(&store))
            .await?
            .unwrap_or_default();
        let find = |kind: &str| {
            times
                .iter()
                .find(|(k, _)| k == kind)
                .map(|(_, ts)| ts.clone())
        };
        let last = LastEventAt {
            claude_code: find("claude_code"),
            codex: find("codex"),
        };
        Ok(DaemonStatusDto::from_core(status, last))
    }

    /// `diagnostics_run`.
    pub async fn diagnostics_run(&self) -> Result<DiagnosticsReport, IpcError> {
        let status = self
            .daemon
            .status()
            .await
            .map_err(|e| Self::core_err(&e, Ctx::Generic))?;
        let listener: Option<SocketAddr> = status
            .wss_addr
            .as_deref()
            .and_then(|a| a.parse::<SocketAddr>().ok());
        let port = listener.map_or(DEFAULT_LINK_PORT, |a| a.port());
        let profile_addr: Option<IpAddr> = listener
            .map(|a| a.ip())
            .or_else(|| status.hosts.first().and_then(|h| h.parse::<IpAddr>().ok()));
        let net = self.net.clone();
        let exe = self.opts.exe_path.clone();
        let (profile, firewall) = Self::blocking(move || {
            let profile = profile_addr.map_or(NetworkProfile::Unknown, |a| net.network_profile(a));
            let firewall = net.firewall_state(&exe, port);
            (profile, firewall)
        })
        .await?;
        let self_connect_ok = match listener {
            Some(addr) => {
                matches!(
                    tokio::time::timeout(
                        self.opts.self_connect_timeout,
                        tokio::net::TcpStream::connect(addr)
                    )
                    .await,
                    Ok(Ok(_))
                )
            }
            None => false,
        };
        let last_preauth = lock(&self.last_preauth).clone();
        Ok(build_report(&DiagnosticsInput {
            link_enabled: status.link_enabled,
            listener,
            profile,
            firewall,
            platform_checks: self.opts.platform_checks,
            last_preauth,
            self_connect_ok,
            hosts: status.hosts,
        }))
    }

    async fn link_port(&self) -> u16 {
        match self.daemon.status().await {
            Ok(s) => s
                .wss_addr
                .as_deref()
                .and_then(|a| a.parse::<SocketAddr>().ok())
                .map_or(DEFAULT_LINK_PORT, |a| a.port()),
            Err(_) => DEFAULT_LINK_PORT,
        }
    }

    /// `firewall_rule_create`: after the user's consent in the UI, one UAC prompt.
    pub async fn firewall_rule_create(&self) -> Result<FirewallResultDto, IpcError> {
        let port = self.link_port().await;
        let (net, exe) = (self.net.clone(), self.opts.exe_path.clone());
        let outcome = Self::blocking({
            let (net, exe) = (net.clone(), exe.clone());
            move || net.create_rule(&exe, port)
        })
        .await?;
        match outcome {
            ElevatedOutcome::Denied => Err(IpcError::new(code::ELEVATION_DENIED)),
            ElevatedOutcome::NotStarted => Ok(FirewallResultDto {
                ok: false,
                elevated: false,
                error: Some("not_available".to_owned()),
            }),
            ElevatedOutcome::Failed => Ok(FirewallResultDto {
                ok: false,
                elevated: true,
                error: Some("netsh_failed".to_owned()),
            }),
            ElevatedOutcome::Done => {
                // trust but verify: the rule must now exist with the documented scope
                let state = Self::blocking(move || net.firewall_state(&exe, port)).await?;
                let ok = state.check_failed || state.scoped_ok;
                if ok {
                    self.audit
                        .log(
                            ACTOR_DESKTOP_USER,
                            "firewall_rule_created",
                            Some(rule_name(port)),
                            Some(json!({"port": port, "profile": "private", "remoteip": "localsubnet"})),
                        )
                        .await;
                }
                Ok(FirewallResultDto {
                    ok,
                    elevated: true,
                    error: (!ok).then(|| "rule_not_verified".to_owned()),
                })
            }
        }
    }

    /// `firewall_rule_remove`: removes the allow rule and the block rules of this exe.
    pub async fn firewall_rule_remove(&self) -> Result<FirewallResultDto, IpcError> {
        let port = self.link_port().await;
        let (net, exe) = (self.net.clone(), self.opts.exe_path.clone());
        let outcome = Self::blocking({
            let (net, exe) = (net.clone(), exe.clone());
            move || net.remove_rules(&exe, port)
        })
        .await?;
        match outcome {
            ElevatedOutcome::Denied => Err(IpcError::new(code::ELEVATION_DENIED)),
            ElevatedOutcome::NotStarted => Ok(FirewallResultDto {
                ok: false,
                elevated: false,
                error: Some("not_available".to_owned()),
            }),
            ElevatedOutcome::Done | ElevatedOutcome::Failed => {
                let state = Self::blocking(move || net.firewall_state(&exe, port)).await?;
                // `netsh delete` exits non-zero when nothing matched: judge by the resulting state
                let clean = !state.check_failed && !state.rule_present && !state.block_rule_present;
                let ok = clean || (outcome == ElevatedOutcome::Done && state.check_failed);
                if ok {
                    self.audit
                        .log(
                            ACTOR_DESKTOP_USER,
                            "firewall_rule_removed",
                            Some(rule_name(port)),
                            None,
                        )
                        .await;
                }
                Ok(FirewallResultDto {
                    ok,
                    elevated: true,
                    error: (!ok).then(|| "rule_still_present".to_owned()),
                })
            }
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    // link, pairing, devices
    // -----------------------------------------------------------------------------------------------------------------

    /// `link_set_enabled`.
    pub async fn link_set_enabled(&self, enabled: bool) -> Result<(), IpcError> {
        self.daemon
            .link_set_enabled(enabled)
            .await
            .map_err(|e| Self::core_err(&e, Ctx::Generic))
    }

    /// `risk_accept`. Only `R1` exists.
    pub async fn risk_accept(&self, risk_id: &str) -> Result<(), IpcError> {
        if risk_id != "R1" {
            return Err(IpcError::invalid_setting());
        }
        self.daemon
            .risk_accept()
            .await
            .map_err(|e| Self::core_err(&e, Ctx::BadValue))
    }

    /// `pairing_start`: the QR (SVG only) of a new pairing.
    pub async fn pairing_start(&self) -> Result<PairingStartDto, IpcError> {
        // a disabled link has its own code; the daemon would answer with a generic "invalid"
        if let Ok(status) = self.daemon.status().await {
            if !status.link_enabled {
                return Err(IpcError::new(code::LINK_DISABLED));
            }
        }
        let started = self
            .daemon
            .pairing_start()
            .await
            .map_err(|e| Self::core_err(&e, Ctx::PairingStart))?;
        Ok(PairingStartDto::from_core(&started))
    }

    /// `pairing_cancel`.
    pub async fn pairing_cancel(&self, pairing_id: &str) -> Result<(), IpcError> {
        let pairing_id = pairing_id.to_owned();
        self.daemon
            .request(|reply| DaemonCommand::PairingCancel { pairing_id, reply })
            .await
            .map_err(|e| Self::core_err(&e, Ctx::PairingCancel))
    }

    /// `pairing_confirm`: the answer of the SAS modal.
    pub async fn pairing_confirm(&self, pairing_id: &str, approve: bool) -> Result<(), IpcError> {
        self.daemon
            .pairing_confirm(pairing_id, approve)
            .await
            .map_err(|e| Self::core_err(&e, Ctx::PairingConfirm))
    }

    /// `devices_list`.
    pub async fn devices_list(&self) -> Result<Vec<DeviceDto>, IpcError> {
        let list = self
            .daemon
            .devices_list()
            .await
            .map_err(|e| Self::core_err(&e, Ctx::Generic))?;
        Ok(list.into_iter().map(DeviceDto::from).collect())
    }

    /// `device_revoke`: needs the exact device name.
    pub async fn device_revoke(&self, device_id: &str, name_typed: &str) -> Result<(), IpcError> {
        self.daemon
            .device_revoke(device_id, name_typed)
            .await
            .map_err(|e| Self::core_err(&e, Ctx::Generic))
    }

    // -----------------------------------------------------------------------------------------------------------------
    // sessions and approvals
    // -----------------------------------------------------------------------------------------------------------------

    /// `sessions_list`.
    pub async fn sessions_list(&self) -> Result<Vec<SessionState>, IpcError> {
        self.daemon
            .request(|reply| DaemonCommand::SessionsList { reply })
            .await
            .map_err(|e| Self::core_err(&e, Ctx::Generic))
    }

    /// `events_recent`.
    pub async fn events_recent(
        &self,
        session_key: Option<String>,
        limit: u32,
    ) -> Result<Vec<Value>, IpcError> {
        let limit = limit.clamp(1, 200);
        let events = self
            .daemon
            .request(|reply| DaemonCommand::EventsRecent {
                session_key,
                limit,
                reply,
            })
            .await
            .map_err(|e| Self::core_err(&e, Ctx::Generic))?;
        Ok(events.iter().map(agent_event_value).collect())
    }

    /// `approvals_pending`: the cards (without their nonce) with delivery state.
    pub async fn approvals_pending(&self) -> Result<Vec<Value>, IpcError> {
        let pending = self
            .daemon
            .approvals_pending()
            .await
            .map_err(|e| Self::core_err(&e, Ctx::Generic))?;
        Ok(pending.iter().map(pending_overview_value).collect())
    }

    /// `approvals_history`.
    pub async fn approvals_history(&self, limit: u32) -> Result<Vec<HistoryEntry>, IpcError> {
        let store = self.daemon.store().clone();
        Self::blocking(move || approvals_history(&store, limit))
            .await?
            .map_err(|_| IpcError::internal())
    }

    /// `approval_handoff_local`: hands the request to the agent's own prompt. Allowed at every risk level because it
    /// makes no decision.
    pub async fn approval_handoff_local(&self, request_id: &str) -> Result<(), IpcError> {
        self.daemon
            .approval_handoff_local(request_id)
            .await
            .map_err(|e| Self::core_err(&e, Ctx::Generic))
    }

    /// `approval_decide_local`: the desktop allow / deny. The broker runs the same transition as for a phone decision
    /// (security.md 6.2.1); a refusal is always an error here, never a silent success.
    pub async fn approval_decide_local(
        &self,
        request_id: &str,
        decision: Decision,
        tool_input_sha256: &str,
        confirm_ack: bool,
        reason: Option<String>,
    ) -> Result<(), IpcError> {
        let reason = reason
            .map(|r| clip(&sanitize_display_text(&r), REASON_MAX_CHARS))
            .filter(|r| !r.is_empty());
        let outcome = self
            .daemon
            .approval_decide_local(request_id, decision, tool_input_sha256, confirm_ack, reason)
            .await
            .map_err(|e| Self::core_err(&e, Ctx::Generic))?;
        if outcome.accepted {
            Ok(())
        } else {
            Err(IpcError::from_decision_reason(&outcome.reason))
        }
    }

    /// `remote_approval_pause` / `remote_approval_resume`.
    pub async fn remote_approval_pause(&self, paused: bool) -> Result<(), IpcError> {
        self.daemon
            .remote_approval_pause(paused)
            .await
            .map_err(|e| Self::core_err(&e, Ctx::Generic))?;
        self.paused.store(paused, Ordering::Relaxed);
        Ok(())
    }

    /// The `link` envelope for the current state (the glue emits it after a tray toggle).
    pub async fn link_envelope(&self) -> Option<Envelope> {
        let status = self.daemon.status().await.ok()?;
        Some(Envelope::new(
            "link",
            json!({
                "enabled": status.link_enabled,
                "remote_approval_paused": status.remote_approval_paused,
            }),
        ))
    }

    // -----------------------------------------------------------------------------------------------------------------
    // hooks, codex
    // -----------------------------------------------------------------------------------------------------------------

    /// `hooks_install`.
    pub async fn hooks_install(
        &self,
        agent: HookAgent,
        mode: HooksMode,
    ) -> Result<HooksStatusDto, IpcError> {
        self.daemon
            .request(|reply| DaemonCommand::HooksInstall { agent, mode, reply })
            .await
            .map(HooksStatusDto::from)
            .map_err(|e| Self::core_err(&e, Ctx::Generic))
    }

    /// `hooks_uninstall` (the mode does not matter for removal).
    pub async fn hooks_uninstall(&self, agent: HookAgent) -> Result<HooksStatusDto, IpcError> {
        self.daemon
            .request(|reply| DaemonCommand::HooksUninstall { agent, reply })
            .await
            .map(HooksStatusDto::from)
            .map_err(|e| Self::core_err(&e, Ctx::Generic))
    }

    /// `hooks_status`.
    pub async fn hooks_status(&self, agent: HookAgent) -> Result<HooksStatusDto, IpcError> {
        self.daemon
            .request(|reply| DaemonCommand::HooksStatus { agent, reply })
            .await
            .map(HooksStatusDto::from)
            .map_err(|e| Self::core_err(&e, Ctx::Generic))
    }

    /// `codex_probe`.
    pub async fn codex_probe(&self) -> Result<CodexProbeDto, IpcError> {
        let home = self.opts.codex_home.clone();
        Self::blocking(move || codex::probe(home.as_deref(), |p| p.exists())).await
    }

    // -----------------------------------------------------------------------------------------------------------------
    // settings and logs
    // -----------------------------------------------------------------------------------------------------------------

    /// `settings_get`.
    pub async fn settings_get(&self) -> Result<Value, IpcError> {
        let cfg = self
            .daemon
            .settings_get()
            .await
            .map_err(|e| Self::core_err(&e, Ctx::Generic))?;
        let risk = self
            .daemon
            .status()
            .await
            .map(|s| s.risk_r1_accepted)
            .map_err(|e| Self::core_err(&e, Ctx::Generic))?;
        Ok(settings_value(&cfg, &self.ui.load(), risk))
    }

    /// `settings_set`: only whitelisted keys exist; the daemon validates and persists its part.
    pub async fn settings_set(&self, key: &str, value: Value) -> Result<Value, IpcError> {
        let _serial = self.settings_lock.lock().await;
        let old_cfg = self
            .daemon
            .settings_get()
            .await
            .map_err(|e| Self::core_err(&e, Ctx::Generic))?;
        let old_ui = self.ui.load();
        let (mut cfg, mut ui) = (old_cfg.clone(), old_ui.clone());
        apply_setting(key, &value, &mut cfg, &mut ui).map_err(|e| match e {
            SettingError::Unknown => IpcError::new(code::UNKNOWN_SETTING),
            SettingError::Invalid => IpcError::invalid_setting(),
        })?;
        if cfg != old_cfg {
            self.daemon
                .settings_set(cfg)
                .await
                .map_err(|e| Self::core_err(&e, Ctx::BadValue))?;
        }
        if ui != old_ui {
            self.ui.save(&ui).map_err(|_| IpcError::internal())?;
            self.notifications
                .store(ui.notifications, Ordering::Relaxed);
        }
        drop(_serial);
        self.settings_get().await
    }

    /// The log directory (`logs_open_dir`; the glue reveals it with the opener plugin).
    pub fn logs_dir(&self) -> PathBuf {
        self.daemon.paths().logs_dir.clone()
    }

    /// `logs_tail`.
    pub async fn logs_tail(&self, limit: u32) -> Result<Vec<String>, IpcError> {
        let dir = self.logs_dir();
        Self::blocking(move || tail_log_lines(&dir, limit as usize))
            .await?
            .map_err(|_| IpcError::internal())
    }

    // -----------------------------------------------------------------------------------------------------------------
    // events and the tray
    // -----------------------------------------------------------------------------------------------------------------

    /// Turns one daemon event into the actions the glue performs, in order.
    pub async fn process(&self, ev: DaemonEvent) -> Vec<ShellAction> {
        if let DaemonEvent::Error { message } = &ev {
            tracing::warn!(error = %clip(message, 200), "the daemon reported an error");
        }
        let mapped = lock(&self.mapper).map(&ev);
        let mut actions = Vec::with_capacity(mapped.len());
        for m in mapped {
            match m {
                Mapped::Emit(env) => actions.push(ShellAction::Emit(env)),
                Mapped::ShowWindow => actions.push(ShellAction::ShowWindow),
                Mapped::Notify(n) => actions.push(ShellAction::Notify(n)),
                Mapped::RefreshTray => actions.push(ShellAction::RefreshTray),
                Mapped::PreAuth { at, ip_masked } => {
                    *lock(&self.last_preauth) = Some((at, ip_masked));
                }
                Mapped::DaemonError => {
                    self.daemon_error_until_ms.store(
                        self.clock.now_ms() + DAEMON_ERROR_TRAY_MS,
                        Ordering::Relaxed,
                    );
                }
                Mapped::DeviceLookup {
                    op,
                    device_id,
                    toast,
                } => {
                    let device = self
                        .devices_list()
                        .await
                        .ok()
                        .and_then(|l| l.into_iter().find(|d| d.device_id == device_id));
                    if let Some(device) = device {
                        if let Some(title) = toast {
                            actions.push(ShellAction::Notify(Notification {
                                title: title.to_owned(),
                                body: clip(&sanitize_display_text(&device.name), 60),
                            }));
                        }
                        actions.push(ShellAction::Emit(Envelope::new(
                            "device",
                            json!({
                                "op": op,
                                "device": serde_json::to_value(&device).unwrap_or(Value::Null),
                            }),
                        )));
                    }
                }
            }
        }
        actions
    }

    /// Measures what the tray shows. `autostart` comes from the autostart plugin (the glue's business).
    pub async fn tray_input(&self, autostart: bool) -> TrayInput {
        let onboarding_pending = !self.ui.load().onboarding_completed;
        let Ok(status) = self.daemon.status().await else {
            return TrayInput {
                daemon_running: false,
                autostart,
                onboarding_pending,
                ..TrayInput::default()
            };
        };
        let pending = self
            .daemon
            .approvals_pending()
            .await
            .map(|list| {
                list.iter()
                    .map(|o| PendingBrief::from_card(&o.card))
                    .collect()
            })
            .unwrap_or_default();
        let session_states: Vec<AgentState> = self
            .sessions_list()
            .await
            .map(|s| {
                s.into_iter()
                    .filter(|x| !x.ended)
                    .map(|x| x.state)
                    .collect()
            })
            .unwrap_or_default();
        let store = self.daemon.store().clone();
        let adapters = Self::blocking(move || store.list_adapter_states())
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default();
        let connected = |kind: &str| {
            adapters
                .iter()
                .any(|a| a.agent_kind == kind && a.status == "connected")
        };
        let codex_mode = crate::dto::codex_mode_str(&status.codex_mode);
        let codex = if codex_mode == "off" {
            CodexLine::Off
        } else if connected("codex") {
            CodexLine::Connected
        } else {
            CodexLine::HooksWaiting
        };
        TrayInput {
            daemon_running: true,
            daemon_error: self.clock.now_ms() < self.daemon_error_until_ms.load(Ordering::Relaxed),
            link_enabled: status.link_enabled,
            remote_paused: status.remote_approval_paused,
            autostart,
            claude_connected: connected("claude_code"),
            codex,
            devices_online: status.devices_online,
            session_states,
            pending,
            onboarding_pending,
        }
    }

    /// A tray "허용" / "거부" click. The menu only offers these for `low` / `medium` requests; this re-checks the
    /// **live** card (a menu can be stale) and then sends the same `confirm_ack = false` local decision the window
    /// would, which the broker validates like any other (security.md 6.2.1).
    pub async fn tray_decide(&self, request_id: &str, decision: Decision) -> Result<(), IpcError> {
        let pending = self
            .daemon
            .approvals_pending()
            .await
            .map_err(|e| Self::core_err(&e, Ctx::Generic))?;
        let cards: Vec<_> = pending.into_iter().map(|o| o.card).collect();
        // high / critical (or a decision the card does not offer): only the window may decide
        let sha = tray_gate(&cards, request_id, decision)?
            .tool_input_sha256
            .clone();
        self.approval_decide_local(request_id, decision, &sha, false, None)
            .await
    }

    /// The `daemon-event` timestamp helper for synthetic envelopes (tests and the glue).
    pub fn now_rfc3339(&self) -> String {
        format_ms(self.clock.now_ms())
    }
}
