//! The daemon: wires every component and exposes the API the desktop shell uses (docs/architecture.md 3.2/3.3,
//! docs/desktop.md 2/3). `agentnest-core` does **not** depend on Tauri.
//!
//! ```text
//! let handle = Daemon::start(config)?;          // DaemonHandle { events, cmds, .. }
//! handle.events        // broadcast::Receiver<DaemonEvent>   (desktop `daemon-event`)
//! handle.cmds          // mpsc::Sender<DaemonCommand>        (desktop invoke commands; each carries a reply channel)
//! handle.pairing_start().await ...   // typed helpers over `cmds`
//! ```
//!
//! # Start-up order (each step before the next)
//!
//! 1. validate the configuration (forbidden / unknown keys were already rejected when it was loaded), install the rustls
//!    `ring` provider, create the data directories, open and migrate the database;
//! 2. load or create the TLS identity (same key forever; certificate re-issued on address change / near expiry);
//! 3. read or create the hook token (`daemon.json`, user-only file; the database keeps its SHA-256);
//! 4. **expire every approval a previous process left pending** (security.md 6.3);
//! 5. bind the loopback hook collector (47831, then 47833..=47840) and, if `link.enabled`, the WSS listener on one LAN
//!    interface address (47832); write `daemon.json`;
//! 6. start the timers: broker/session/pairing tick, address watcher (10 s), effective-TTL clamp (60 s), retention (hourly).
//!
//! `Daemon::start` owns a private multi-thread tokio runtime, so it can be called from a plain `main` (the Tauri shell) and
//! must **not** be called from inside another runtime's async context (use [`Daemon::start_async`] there).
//!
//! # Shutdown
//!
//! [`DaemonHandle::shutdown`]: pending approvals are handed to the local prompt (empty replies, no hook hangs), phones get
//! `bye{shutdown}` + 1012, the collector stops (at most 2 s), the database is checkpointed.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentnest_protocol::canonical::sha256;
use agentnest_protocol::qr::b64url_encode;
use agentnest_protocol::{
    AdapterMode, AdapterStatusKind, AgentEvent, AgentKind, ByeReason, Decision, SessionState,
};
use chrono::{DateTime, Utc};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::adapters::claude_code::install::{
    self as claude_install, effective_ttl_s, HookMode, InstallOptions,
};
use crate::approvals::broker::{
    default_classifier, Broker, BrokerDeps, BrokerSettings, DecisionOutcome, PendingOverview,
};
use crate::audit::{actions, Audit, ACTOR_DESKTOP_USER, ACTOR_SYSTEM};
use crate::auth::challenge::AdmissionControl;
use crate::auth::devices::{DeviceRecord, DeviceRegistry};
use crate::auth::pairing::{PairingError, PairingManager, PairingStartInfo, PairingStarted};
use crate::config::{AppConfig, CodexMode, ConfigError, CriticalRemote, Paths};
use crate::events::{DaemonEvent, DeviceUiEvent, EventBus, LinkUiEvent};
use crate::http::{
    self, DaemonInfo, GuardState, HookTokenVerifier, HttpContext, HttpServer, HttpSettings,
};
use crate::identity::{
    self, install_crypto_provider, IdentityChange, IdentityError, IdentityStore, ServerIdentity,
};
use crate::link::{self, LinkContext, LinkPolicy, LinkServer, PcInfo, Registry, Timing};
use crate::normalize::NormalizeEnv;
use crate::pipeline::Pipeline;
use crate::redact::HookToken;
use crate::state::timers::{format_ms, Clock, SystemClock};
use crate::store::{RetentionConfig, Store, StoreError};

/// Preferred loopback port of the hook collector.
pub const HOOK_PORT: u16 = agentnest_protocol::limits::HOOK_PORT;
/// Preferred WSS port.
pub const LINK_PORT: u16 = agentnest_protocol::limits::LINK_PORT;
/// Fallback ports of the hook collector when 47831 is taken (claude-code.md 2).
pub const HOOK_PORT_FALLBACKS: std::ops::RangeInclusive<u16> = 47833..=47840;
/// Fallback ports of the WSS listener when 47832 is taken.
pub const LINK_PORT_FALLBACKS: std::ops::RangeInclusive<u16> = 47841..=47848;

/// The collector could not get its preferred hook port (somebody else holds it) and listens on a fallback port. The HTTP
/// hooks in `settings.json` still point at the preferred one, where an HTTP hook cannot tell the daemon from the program
/// that holds it (docs/security.md 1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HookPortProblem {
    /// The port the hooks were installed for / the daemon asked for.
    pub wanted: u16,
    /// The port the collector actually listens on.
    pub bound: u16,
}

/// Errors of starting the daemon.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// Configuration problem.
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),
    /// Storage problem.
    #[error("storage error: {0}")]
    Store(#[from] StoreError),
    /// TLS identity problem.
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    /// Socket or file problem.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// No free port in the allowed range.
    #[error("no free port for {0}")]
    NoPort(&'static str),
    /// The system random number generator failed.
    #[error("random number generator failure")]
    Rng,
}

/// Everything that is not part of the configuration file: locations, ports and test knobs. The defaults of
/// [`DaemonOptions::production`] are the documented behaviour.
#[derive(Clone)]
pub struct DaemonOptions {
    /// Data directory layout.
    pub paths: Paths,
    /// Preferred collector port (`0` = any free port; tests).
    pub hook_port: u16,
    /// Preferred WSS port (`0` = any free port; tests).
    pub link_port: u16,
    /// Clock (security judgements use only this).
    pub clock: Arc<dyn Clock>,
    /// Link timing (tests shorten it).
    pub timing: Timing,
    /// Overrides the LAN address list (tests bind loopback).
    pub lan_addrs: Option<Vec<IpAddr>>,
    /// `~/.claude/settings.json`; the user's real one if `None`.
    pub claude_settings_path: Option<PathBuf>,
    /// Path of `agentnest-hook` for command hooks and the statusLine.
    pub hook_cli: String,
    /// PC display name; the host name if `None`.
    pub pc_name: Option<String>,
    /// Timer step in milliseconds (broker expiry, session timers).
    pub tick_ms: u64,
    /// Poll interval of the LAN address watcher.
    pub addr_poll_ms: u64,
    /// Effective-TTL clamp re-check interval.
    pub ttl_check_ms: u64,
    /// Overrides the effective approval TTL in milliseconds (tests; the configuration range stays 60..=180 s).
    pub ttl_override_ms: Option<i64>,
    /// Overrides the reconnect grace in milliseconds (tests).
    pub grace_override_ms: Option<i64>,
    /// Install the daily rolling, redacting file logger of [`crate::logging`] (production default). The Tauri shell
    /// installs its own subscriber and sets this to `false`; tests leave it off.
    pub init_logging: bool,
}

impl std::fmt::Debug for DaemonOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonOptions")
            .field("paths", &self.paths)
            .finish_non_exhaustive()
    }
}

impl DaemonOptions {
    /// The production options: per-user data directory, documented ports, system clock.
    pub fn production() -> Result<Self, ConfigError> {
        Ok(Self {
            paths: Paths::default_for_user()?,
            hook_port: HOOK_PORT,
            link_port: LINK_PORT,
            clock: Arc::new(SystemClock),
            timing: Timing::default(),
            lan_addrs: None,
            claude_settings_path: None,
            hook_cli: "agentnest-hook".to_owned(),
            pc_name: None,
            tick_ms: 100,
            addr_poll_ms: 10_000,
            ttl_check_ms: 60_000,
            ttl_override_ms: None,
            grace_override_ms: None,
            init_logging: true,
        })
    }

    /// Options for tests and tools: everything below `dir`, ephemeral ports, loopback only, no logger.
    pub fn for_dir(dir: impl Into<PathBuf>) -> Self {
        let dir: PathBuf = dir.into();
        Self {
            claude_settings_path: Some(dir.join("claude").join("settings.json")),
            paths: Paths::in_dir(dir),
            hook_port: 0,
            link_port: 0,
            clock: Arc::new(SystemClock),
            timing: Timing::default(),
            lan_addrs: Some(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
            hook_cli: "agentnest-hook".to_owned(),
            pc_name: Some("TEST-PC".to_owned()),
            tick_ms: 50,
            addr_poll_ms: 10_000,
            ttl_check_ms: 60_000,
            ttl_override_ms: None,
            grace_override_ms: None,
            init_logging: false,
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// commands and their results
// ---------------------------------------------------------------------------------------------------------------------

/// Errors a command can answer with. `code()` is the stable string for the UI (`RISK_NOT_ACCEPTED`, `PAIRING_BUSY`, ...).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum CommandError {
    /// The user has not accepted risk R1.
    #[error("risk R1 not accepted")]
    RiskNotAccepted,
    /// A pairing is already active.
    #[error("pairing busy")]
    PairingBusy,
    /// Nothing to act on (unknown id, wrong state).
    #[error("not found: {0}")]
    NotFound(&'static str),
    /// The typed device name does not match.
    #[error("device name does not match")]
    NameMismatch,
    /// The request is invalid.
    #[error("invalid: {0}")]
    Invalid(String),
    /// The daemon is shutting down or the reply channel closed.
    #[error("daemon unavailable")]
    Unavailable,
    /// An internal failure (details are logged, not returned).
    #[error("internal error")]
    Internal,
}

impl CommandError {
    /// Stable code for the UI.
    pub fn code(&self) -> &'static str {
        match self {
            CommandError::RiskNotAccepted => "RISK_NOT_ACCEPTED",
            CommandError::PairingBusy => "PAIRING_BUSY",
            CommandError::NotFound(_) => "NOT_FOUND",
            CommandError::NameMismatch => "NAME_MISMATCH",
            CommandError::Invalid(_) => "INVALID",
            CommandError::Unavailable => "UNAVAILABLE",
            CommandError::Internal => "INTERNAL",
        }
    }
}

impl From<PairingError> for CommandError {
    fn from(e: PairingError) -> Self {
        match e {
            PairingError::Busy => CommandError::PairingBusy,
            PairingError::RiskNotAccepted => CommandError::RiskNotAccepted,
            PairingError::NotPending => CommandError::NotFound("pairing"),
            PairingError::NoHosts => CommandError::Invalid("no LAN address".to_owned()),
            _ => CommandError::Internal,
        }
    }
}

/// Which agent a hooks command is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookAgent {
    /// Claude Code (`settings.json` merge).
    ClaudeCode,
    /// Codex (instructions only until Phase 0 C6).
    Codex,
}

/// How hooks reach the daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HooksMode {
    /// HTTP hooks.
    Http,
    /// Command hooks (`agentnest-hook`).
    Cli,
}

/// Result of a hooks command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HooksReport {
    /// Whether the hooks are installed now.
    pub installed: bool,
    /// The settings file (Claude) or hooks file (Codex).
    pub path: String,
    /// Korean warnings / instructions.
    pub warnings: Vec<String>,
    /// Installed `PermissionRequest` timeout (Claude).
    pub hook_timeout_s: Option<u32>,
}

/// Device row for the UI (no hashes, no keys).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeviceSummary {
    /// Device id.
    pub device_id: String,
    /// Name.
    pub name: String,
    /// Platform.
    pub platform: String,
    /// Model.
    pub model: Option<String>,
    /// Pairing time.
    pub paired_at: String,
    /// Last connection.
    pub last_seen_at: Option<String>,
    /// Currently connected.
    pub online: bool,
    /// Revocation time.
    pub revoked_at: Option<String>,
}

/// `daemon_status` (docs/desktop.md 3). No secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DaemonStatus {
    /// Always `true` while the daemon answers.
    pub running: bool,
    /// Collector port.
    pub hook_port: u16,
    /// WSS address (`ip:port`) if the listener runs.
    pub wss_addr: Option<String>,
    /// Advertised LAN addresses.
    pub hosts: Vec<String>,
    /// `link.enabled`.
    pub link_enabled: bool,
    /// Certificate end of validity.
    pub cert_expires_at: String,
    /// `sha256/<base64>` pin.
    pub spki_pin: String,
    /// All Claude Code hooks installed.
    pub hooks_installed: bool,
    /// Effective approval TTL (seconds).
    pub effective_ttl_s: u32,
    /// Installed `PermissionRequest` hook timeout.
    pub hook_timeout_s: Option<u32>,
    /// The installed hook URLs use another port than the running collector (reinstall needed).
    pub hook_port_mismatch: bool,
    /// Codex mode.
    pub codex_mode: String,
    /// Live sessions.
    pub sessions: usize,
    /// Online phones.
    pub devices_online: usize,
    /// Pending approvals.
    pub pending_approvals: usize,
    /// Risk R1 accepted.
    pub risk_r1_accepted: bool,
    /// Remote approval paused.
    pub remote_approval_paused: bool,
    /// A pairing is active.
    pub pairing_active: bool,
}

/// Which settings changed in a way that needs a restart.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SettingsApplied {
    /// Keys that only apply after a restart.
    pub restart_required: Vec<String>,
}

type Reply<T> = oneshot::Sender<Result<T, CommandError>>;

/// A command from the desktop shell. Every command carries its reply channel.
pub enum DaemonCommand {
    /// `daemon_status`.
    Status {
        /// Reply.
        reply: Reply<DaemonStatus>,
    },
    /// `risk_accept("R1")`.
    RiskAccept {
        /// Risk id (only `R1` exists).
        risk_id: String,
        /// Reply.
        reply: Reply<()>,
    },
    /// `pairing_start`: pairing mode on, QR returned.
    PairingStart {
        /// Reply.
        reply: Reply<PairingStarted>,
    },
    /// `pairing_cancel`.
    PairingCancel {
        /// Pairing id.
        pairing_id: String,
        /// Reply.
        reply: Reply<()>,
    },
    /// `pairing_confirm`: the SAS modal answer.
    PairingConfirm {
        /// Pairing id.
        pairing_id: String,
        /// Approve or reject.
        approve: bool,
        /// Reply.
        reply: Reply<()>,
    },
    /// `devices_list`.
    DevicesList {
        /// Reply.
        reply: Reply<Vec<DeviceSummary>>,
    },
    /// `device_revoke`: needs the device name typed by the user.
    DeviceRevoke {
        /// Device id.
        device_id: String,
        /// Name typed by the user (must equal the stored name).
        name_typed: String,
        /// Reply.
        reply: Reply<()>,
    },
    /// `sessions_list`.
    SessionsList {
        /// Reply.
        reply: Reply<Vec<SessionState>>,
    },
    /// `events_recent`.
    EventsRecent {
        /// Optional session filter.
        session_key: Option<String>,
        /// Number of events.
        limit: u32,
        /// Reply.
        reply: Reply<Vec<AgentEvent>>,
    },
    /// `approvals_pending`.
    ApprovalsPending {
        /// Reply.
        reply: Reply<Vec<PendingOverview>>,
    },
    /// `approval_handoff_local`.
    ApprovalHandoffLocal {
        /// Request id.
        request_id: String,
        /// Reply.
        reply: Reply<()>,
    },
    /// `approval_decide_local`: the same broker transition as a phone decision.
    ApprovalDecideLocal {
        /// Request id.
        request_id: String,
        /// `allow` / `deny` / `deny_and_stop`.
        decision: Decision,
        /// Hash of the card the user saw.
        tool_input_sha256: String,
        /// The UI completed its extra confirmation.
        confirm_ack: bool,
        /// Deny reason.
        reason: Option<String>,
        /// Reply (rejections are `accepted: false` outcomes, not errors).
        reply: Reply<DecisionOutcome>,
    },
    /// `remote_approval_pause` / `_resume`.
    RemoteApprovalPause {
        /// New state.
        paused: bool,
        /// Reply.
        reply: Reply<()>,
    },
    /// `link_set_enabled`.
    LinkSetEnabled {
        /// New state.
        enabled: bool,
        /// Reply.
        reply: Reply<()>,
    },
    /// `hooks_install`.
    HooksInstall {
        /// Agent.
        agent: HookAgent,
        /// Mode.
        mode: HooksMode,
        /// Reply.
        reply: Reply<HooksReport>,
    },
    /// `hooks_uninstall`.
    HooksUninstall {
        /// Agent.
        agent: HookAgent,
        /// Reply.
        reply: Reply<HooksReport>,
    },
    /// `hooks_status`.
    HooksStatus {
        /// Agent.
        agent: HookAgent,
        /// Reply.
        reply: Reply<HooksReport>,
    },
    /// `settings_get`.
    SettingsGet {
        /// Reply.
        reply: Reply<AppConfig>,
    },
    /// `settings_set`: validated, persisted and applied.
    SettingsSet {
        /// The new configuration (forbidden fields do not exist in the type).
        config: Box<AppConfig>,
        /// Reply.
        reply: Reply<SettingsApplied>,
    },
    /// "Regenerate PC identity": new key pair, new pin, every phone must pair again.
    IdentityRegenerate {
        /// Reply.
        reply: Reply<()>,
    },
    /// "Reissue hook token" (settings.json is re-merged by the next `HooksInstall`).
    HookTokenRotate {
        /// Reply.
        reply: Reply<()>,
    },
    /// Graceful shutdown.
    Shutdown {
        /// Reply.
        reply: Reply<()>,
    },
}

// ---------------------------------------------------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------------------------------------------------

struct RuntimeOwner(Mutex<Option<tokio::runtime::Runtime>>);

impl Drop for RuntimeOwner {
    fn drop(&mut self) {
        let rt = match self.0.lock() {
            Ok(mut g) => g.take(),
            Err(e) => e.into_inner().take(),
        };
        if let Some(rt) = rt {
            // never block in a destructor (it may run inside an async context)
            rt.shutdown_background();
        }
    }
}

struct Inner {
    options: DaemonOptions,
    config: Mutex<AppConfig>,
    store: Store,
    clock: Arc<dyn Clock>,
    registry: Arc<Registry>,
    pipeline: Arc<Pipeline>,
    broker: Arc<Broker>,
    devices: DeviceRegistry,
    pairing: PairingManager,
    audit: Audit,
    bus: EventBus,
    broker_settings: Arc<BrokerSettings>,
    http_settings: Arc<HttpSettings>,
    link_policy: Arc<LinkPolicy>,
    link_ctx: Arc<LinkContext>,
    guard: Arc<GuardState>,
    daemon_info: Arc<DaemonInfo>,
    hook_token: Mutex<HookToken>,
    identity: Mutex<ServerIdentity>,
    identity_store: IdentityStore,
    http_server: Mutex<Option<HttpServer>>,
    link_server: tokio::sync::Mutex<Option<LinkServer>>,
    hook_port: u16,
    hook_port_problem: Option<HookPortProblem>,
    wss_port: Mutex<u16>,
    shutdown_tx: watch::Sender<bool>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn generate_hook_token() -> Result<HookToken, DaemonError> {
    let mut raw = [0u8; 32];
    SystemRandom::new()
        .fill(&mut raw)
        .map_err(|_| DaemonError::Rng)?;
    Ok(HookToken::new(format!("an_hk_{}", b64url_encode(&raw))))
}

/// `daemon.json`, read by `agentnest-hook`. `approval_ttl_s` (the EFFECTIVE TTL) lets the CLI wait `ttl + 28 s` for a
/// held `PermissionRequest`; without it the CLI would assume 120 s and give up on a 180 s TTL while the daemon still waits.
#[derive(Serialize, Deserialize)]
struct DaemonJson {
    hook_port: u16,
    wss_port: u16,
    hook_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approval_ttl_s: Option<u32>,
}

fn read_daemon_json_token(path: &std::path::Path) -> Option<HookToken> {
    let text = std::fs::read_to_string(path).ok()?;
    let v: DaemonJson = serde_json::from_str(&text).ok()?;
    (v.hook_token.starts_with("an_hk_") && v.hook_token.len() >= 20)
        .then(|| HookToken::new(v.hook_token))
}

fn bind_with_fallback<T>(
    preferred: u16,
    fallbacks: std::ops::RangeInclusive<u16>,
    what: &'static str,
    mut bind: impl FnMut(u16) -> std::io::Result<T>,
) -> Result<T, DaemonError> {
    if preferred == 0 {
        return bind(0).map_err(DaemonError::Io);
    }
    let mut last = None;
    for port in std::iter::once(preferred).chain(fallbacks) {
        match bind(port) {
            Ok(v) => return Ok(v),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => last = Some(e),
            Err(e) => return Err(DaemonError::Io(e)),
        }
    }
    let _ = last;
    Err(DaemonError::NoPort(what))
}

fn pc_display_name(options: &DaemonOptions) -> String {
    let name = options
        .pc_name
        .clone()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "AgentNest PC".to_owned());
    name.chars().take(64).collect()
}

impl Inner {
    fn lan_addrs(&self) -> Vec<IpAddr> {
        self.options
            .lan_addrs
            .clone()
            .unwrap_or_else(identity::lan_addresses)
    }

    fn settings_path(&self) -> Option<PathBuf> {
        self.options
            .claude_settings_path
            .clone()
            .or_else(claude_install::default_settings_path)
    }

    fn config(&self) -> AppConfig {
        lock(&self.config).clone()
    }

    fn hosts(&self) -> Vec<String> {
        let mut v: Vec<String> = self.lan_addrs().iter().map(ToString::to_string).collect();
        v.truncate(8);
        v
    }

    fn effective_ttl_s(&self, cfg: &AppConfig) -> u32 {
        if let Some(ms) = self.options.ttl_override_ms {
            return u32::try_from((ms / 1000).max(1)).unwrap_or(1);
        }
        let installed = self
            .settings_path()
            .map(|p| claude_install::inspect(&p).permission_request_timeout_s)
            .unwrap_or(None);
        effective_ttl_s(cfg.approval.ttl_s, installed)
    }

    fn apply_ttl(&self, cfg: &AppConfig) {
        let ttl_s = self.effective_ttl_s(cfg);
        let ttl_ms = self
            .options
            .ttl_override_ms
            .unwrap_or(i64::from(ttl_s) * 1000);
        self.broker_settings.set_ttl_ms(ttl_ms);
        let previous = self
            .link_policy
            .effective_ttl_s
            .swap(ttl_s, Ordering::Relaxed);
        if previous != ttl_s {
            // the relay CLI reads the TTL from daemon.json
            if let Err(e) = self.write_daemon_json() {
                tracing::warn!(error = %e, "could not update daemon.json");
            }
        }
    }

    fn apply_policy(&self, cfg: &AppConfig) {
        self.broker_settings
            .set_critical_local_only(cfg.approval.critical_remote == CriticalRemote::LocalOnly);
        self.broker_settings
            .set_deny_requires_auth(cfg.approval.deny_requires_auth);
        let grace = self
            .options
            .grace_override_ms
            .unwrap_or(i64::from(cfg.approval.reconnect_grace_s) * 1000);
        self.broker_settings.set_grace_ms(grace);
        self.http_settings
            .force_ask_on_critical
            .store(cfg.risk.force_ask_on_critical, Ordering::Relaxed);
        self.http_settings.codex_hold.store(
            cfg!(feature = "codex-hooks-approval") && cfg.codex.mode == CodexMode::Hooks,
            Ordering::Relaxed,
        );
        self.link_policy.critical_local_only.store(
            cfg.approval.critical_remote == CriticalRemote::LocalOnly,
            Ordering::Relaxed,
        );
        self.link_policy
            .deny_requires_auth
            .store(cfg.approval.deny_requires_auth, Ordering::Relaxed);
        self.apply_ttl(cfg);
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

    fn write_daemon_json(&self) -> std::io::Result<()> {
        let token = lock(&self.hook_token).clone();
        let v = DaemonJson {
            hook_port: self.hook_port,
            wss_port: *lock(&self.wss_port),
            hook_token: token.expose().to_owned(),
            approval_ttl_s: Some(self.link_policy.effective_ttl_s.load(Ordering::Relaxed)),
        };
        let text = serde_json::to_vec_pretty(&v).map_err(std::io::Error::other)?;
        crate::identity::keywrap::write_user_only(
            &self.options.paths.daemon_json,
            &text,
            &crate::identity::keywrap::PlatformPermissions,
        )
    }

    async fn store_identity_row(&self, change: Option<IdentityChange>) {
        let id = lock(&self.identity).clone();
        let token = lock(&self.hook_token).clone();
        let now = format_ms(self.clock.now_ms());
        let rotated = matches!(
            change,
            Some(IdentityChange::CertReissued | IdentityChange::Regenerated)
        )
        .then(|| now.clone());
        let name = pc_display_name(&self.options);
        let (pc_id, cert_pem) = (id.pc_id(), id.cert_pem().to_owned());
        let pin = id.spki_pin();
        let spki_b64 = pin.strip_prefix("sha256/").unwrap_or(&pin).to_owned();
        let token_hash = sha256(token.expose().as_bytes()).to_vec();
        let r = self
            .db(move |s| {
                s.run(move |c| {
                    c.execute(
                        "INSERT INTO pc_identity(id, pc_id, pc_name, cert_pem, spki_sha256_b64, hook_token_hash, created_at, cert_rotated_at) \
                         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                         ON CONFLICT(id) DO UPDATE SET pc_id=excluded.pc_id, pc_name=excluded.pc_name, cert_pem=excluded.cert_pem, \
                         spki_sha256_b64=excluded.spki_sha256_b64, hook_token_hash=excluded.hook_token_hash, \
                         cert_rotated_at=COALESCE(excluded.cert_rotated_at, pc_identity.cert_rotated_at)",
                        rusqlite::params![pc_id, name, cert_pem, spki_b64, token_hash, now, rotated],
                    )?;
                    Ok(())
                })
            })
            .await;
        if let Err(e) = r {
            tracing::warn!(error = %e, "could not store the PC identity row");
        }
    }

    // -------------------------------------------------------------------------------------------------------------
    // link lifecycle
    // -------------------------------------------------------------------------------------------------------------

    fn link_bind_addr(&self, cfg: &AppConfig) -> IpAddr {
        cfg.link
            .bind_addr
            .or_else(|| self.lan_addrs().first().copied())
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }

    async fn start_link(&self, cfg: &AppConfig) -> Result<(), DaemonError> {
        let addr = self.link_bind_addr(cfg);
        let preferred = self.options.link_port;
        let listener = bind_with_fallback(preferred, LINK_PORT_FALLBACKS, "link", |p| {
            link::bind_link(addr, p)
        })?;
        let port = listener.local_addr()?.port();
        *lock(&self.wss_port) = port;
        self.daemon_info.wss_port.store(port, Ordering::Relaxed);
        {
            let mut pc = self.link_ctx.pc.write().unwrap_or_else(|e| e.into_inner());
            pc.port = port;
            pc.hosts = self.hosts();
        }
        let id = lock(&self.identity).clone();
        let server = LinkServer::start(self.link_ctx.clone(), &id, listener)?;
        self.bus.emit(DaemonEvent::Link(LinkUiEvent::Listening {
            addr: server.addr.to_string(),
        }));
        *self.link_server.lock().await = Some(server);
        if let Err(e) = self.write_daemon_json() {
            tracing::warn!(error = %e, "could not write daemon.json");
        }
        Ok(())
    }

    async fn stop_link(
        &self,
        reason: ByeReason,
        reconnect: bool,
        message_ko: &str,
        close_code: u16,
    ) {
        let server = self.link_server.lock().await.take();
        if let Some(server) = server {
            server.stop(reason, reconnect, message_ko, close_code).await;
        }
    }

    async fn set_link_enabled(&self, enabled: bool) -> Result<(), CommandError> {
        let mut cfg = self.config();
        if cfg.link.enabled == enabled {
            return Ok(());
        }
        cfg.link.enabled = enabled;
        cfg.save(&self.options.paths.config)
            .map_err(|_| CommandError::Internal)?;
        *lock(&self.config) = cfg.clone();
        if enabled {
            self.start_link(&cfg).await.map_err(|e| {
                tracing::error!(error = %e, "could not start the link listener");
                CommandError::Internal
            })?;
            self.audit
                .log(ACTOR_DESKTOP_USER, actions::LINK_ENABLED, None, None)
                .await;
        } else {
            // pending approvals end as handed_off_local (resolved by the desktop), the pairing mode ends, the phones are told
            self.broker.link_disabled().await;
            if let Some((id, _)) = self.pairing.active() {
                self.pairing.cancel(&id);
            }
            self.stop_link(
                ByeReason::Shutdown,
                false,
                "PC에서 휴대폰 연결을 껐어요",
                1000,
            )
            .await;
            self.audit
                .log(ACTOR_DESKTOP_USER, actions::LINK_DISABLED, None, None)
                .await;
        }
        self.bus
            .emit(DaemonEvent::Link(LinkUiEvent::Enabled { enabled }));
        Ok(())
    }

    // -------------------------------------------------------------------------------------------------------------
    // timers
    // -------------------------------------------------------------------------------------------------------------

    async fn check_addresses(&self) {
        let lan = self.lan_addrs();
        let current = lock(&self.identity).clone();
        let changed = match self.identity_store.refresh(
            &current,
            &lan,
            DateTime::<Utc>::from_timestamp_millis(self.clock.now_ms()).unwrap_or_else(Utc::now),
        ) {
            Ok(Some(fresh)) => Some(fresh),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(error = %e, "certificate refresh failed");
                None
            }
        };
        let hosts = self.hosts();
        let hosts_changed = self
            .link_ctx
            .pc
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .hosts
            != hosts;
        if let Some(fresh) = changed {
            // same key: the pin is unchanged, phones need no re-pairing
            *lock(&self.identity) = fresh.clone();
            if let Some(server) = self.link_server.lock().await.as_ref() {
                if let Err(e) = server.reload_identity(&fresh) {
                    tracing::warn!(error = %e, "could not load the new certificate");
                }
            }
            self.store_identity_row(Some(IdentityChange::CertReissued))
                .await;
            self.audit
                .log(ACTOR_SYSTEM, actions::CERT_ROTATED, None, None)
                .await;
        }
        if hosts_changed {
            self.link_ctx.set_hosts(hosts.clone());
            self.bus.emit(DaemonEvent::Link(LinkUiEvent::HostsChanged {
                addresses: hosts,
            }));
            // the primary interface changed and the listener follows it (no fixed bind address configured)
            let cfg = self.config();
            if cfg.link.enabled && cfg.link.bind_addr.is_none() {
                let want = self.link_bind_addr(&cfg);
                let have = self.link_server.lock().await.as_ref().map(|s| s.addr.ip());
                if have.is_some() && have != Some(want) {
                    self.stop_link(
                        ByeReason::Restart,
                        true,
                        "PC 주소가 바뀌어 다시 연결해요",
                        1012,
                    )
                    .await;
                    if let Err(e) = self.start_link(&cfg).await {
                        tracing::error!(error = %e, "could not rebind the link listener");
                    }
                }
            }
        }
    }

    async fn run_retention(&self) {
        let now = self.clock.now_ms();
        let r = self
            .db(move |s| s.run_retention(now, &RetentionConfig::default()))
            .await;
        if let Err(e) = r {
            tracing::warn!(error = %e, "retention failed");
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// the public handle
// ---------------------------------------------------------------------------------------------------------------------

/// The running daemon as seen by the desktop shell.
pub struct DaemonHandle {
    /// Events for the UI. Subscribe more receivers with [`DaemonHandle::subscribe`].
    pub events: broadcast::Receiver<DaemonEvent>,
    /// Commands from the UI.
    pub cmds: mpsc::Sender<DaemonCommand>,
    inner: Arc<Inner>,
    handle: tokio::runtime::Handle,
    _runtime: Arc<RuntimeOwner>,
    /// Keeps the file logger's background writer alive (`DaemonOptions::init_logging`).
    _log_guard: Option<crate::logging::LogGuard>,
}

impl std::fmt::Debug for DaemonHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonHandle")
            .field("hook_port", &self.inner.hook_port)
            .finish_non_exhaustive()
    }
}

/// Namespace of the start functions.
pub struct Daemon;

impl Daemon {
    /// Starts the daemon with the production options (see the module docs). Blocks briefly; call it from a plain `main`
    /// or a blocking context, not from async code.
    pub fn start(config: AppConfig) -> Result<DaemonHandle, DaemonError> {
        Self::start_with(config, DaemonOptions::production()?)
    }

    /// Starts the daemon with explicit options.
    pub fn start_with(
        config: AppConfig,
        options: DaemonOptions,
    ) -> Result<DaemonHandle, DaemonError> {
        config.validate()?;
        install_crypto_provider();
        options.paths.ensure_dirs()?;
        // The file logger (security.md 8.2). Another global subscriber (the desktop shell's) is not an error.
        let log_guard = if options.init_logging {
            crate::logging::init_file_logging(&options.paths.logs_dir, config.log_level).ok()
        } else {
            None
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("agentnest-core")
            .enable_all()
            .build()?;
        let runtime_handle = runtime.handle().clone();
        let owner = Arc::new(RuntimeOwner(Mutex::new(Some(runtime))));
        // Everything below needs a runtime context; `block_on` on the owned runtime provides it.
        let (inner, events, cmd_tx, cmd_rx) = {
            let guard = lock(&owner.0);
            let Some(rt) = guard.as_ref() else {
                return Err(DaemonError::Io(std::io::Error::other("runtime missing")));
            };
            rt.block_on(Self::build(config, options))?
        };
        runtime_handle.spawn(Self::command_loop(inner.clone(), cmd_rx));
        Ok(DaemonHandle {
            events,
            cmds: cmd_tx,
            inner,
            handle: runtime_handle,
            _runtime: owner,
            _log_guard: log_guard,
        })
    }

    /// [`Daemon::start_with`] for callers inside an async context (runs it on the blocking pool).
    pub async fn start_async(
        config: AppConfig,
        options: DaemonOptions,
    ) -> Result<DaemonHandle, DaemonError> {
        tokio::task::spawn_blocking(move || Self::start_with(config, options))
            .await
            .map_err(|e| DaemonError::Io(std::io::Error::other(e.to_string())))?
    }

    #[allow(clippy::type_complexity)]
    async fn build(
        config: AppConfig,
        options: DaemonOptions,
    ) -> Result<
        (
            Arc<Inner>,
            broadcast::Receiver<DaemonEvent>,
            mpsc::Sender<DaemonCommand>,
            mpsc::Receiver<DaemonCommand>,
        ),
        DaemonError,
    > {
        let clock = options.clock.clone();
        let store = Store::open(&options.paths.db)?;
        let bus = EventBus::new(1024);
        let events = bus.subscribe();

        // identity and hook token
        let lan = options
            .lan_addrs
            .clone()
            .unwrap_or_else(identity::lan_addresses);
        let identity_store = IdentityStore::new(options.paths.identity_dir.clone());
        let now_dt =
            DateTime::<Utc>::from_timestamp_millis(clock.now_ms()).unwrap_or_else(Utc::now);
        let (identity, change) = identity_store.load_or_create(&lan, now_dt)?;
        let hook_token = match read_daemon_json_token(&options.paths.daemon_json) {
            Some(t) => t,
            None => generate_hook_token()?,
        };

        // components
        let registry = Arc::new(Registry::new());
        let env = NormalizeEnv::new(
            clock.clone(),
            Arc::new(crate::normalize::UuidV7Gen),
            Arc::new(crate::normalize::ProjectResolver::new()),
        );
        let pipeline = Arc::new(Pipeline::new(
            store.clone(),
            clock.clone(),
            registry.clone(),
            bus.clone(),
        ));
        let audit = Audit::new(store.clone(), clock.clone());
        let devices = DeviceRegistry::new(store.clone(), clock.clone());
        let pairing = PairingManager::new(store.clone(), clock.clone(), audit.clone(), bus.clone());
        let broker_settings = Arc::new(BrokerSettings::new(120, 10, false, false));
        let broker = Broker::new(BrokerDeps {
            store: store.clone(),
            clock: clock.clone(),
            pipeline: pipeline.clone(),
            registry: registry.clone(),
            bus: bus.clone(),
            audit: audit.clone(),
            devices: devices.clone(),
            env: env.clone(),
            settings: broker_settings.clone(),
            classifier: default_classifier(),
        });
        // security.md 6.3: a restarted daemon cannot answer the old hook connections
        let expired = broker.recover_on_startup().await;
        if expired > 0 {
            tracing::info!(
                expired,
                "expired approvals left pending by the previous process"
            );
        }

        let http_settings = Arc::new(HttpSettings::new(config.risk.force_ask_on_critical, false));
        let link_policy = Arc::new(LinkPolicy::new(false, false, 120));
        let daemon_info = Arc::new(DaemonInfo::new(0, 0));
        let guard = Arc::new(GuardState {
            tokens: HookTokenVerifier::new(&hook_token),
        });
        let http_ctx = HttpContext::new(
            pipeline.clone(),
            broker.clone(),
            clock.clone(),
            env.clone(),
            http_settings.clone(),
            daemon_info.clone(),
        );
        let admission = AdmissionControl::new(clock.clone());
        let link_ctx = Arc::new(LinkContext {
            store: store.clone(),
            clock: clock.clone(),
            registry: registry.clone(),
            pipeline: pipeline.clone(),
            broker: broker.clone(),
            devices: devices.clone(),
            pairing: pairing.clone(),
            admission,
            audit: audit.clone(),
            bus: bus.clone(),
            pc: std::sync::RwLock::new(PcInfo {
                pc_id: identity.pc_id(),
                name: pc_display_name(&options),
                hosts: lan.iter().map(ToString::to_string).collect(),
                port: 0,
            }),
            policy: link_policy.clone(),
            timing: options.timing.clone(),
            private_sources_only: config.link.private_sources_only,
        });

        // the loopback collector
        let (v4, v6) = bind_with_fallback(
            options.hook_port,
            HOOK_PORT_FALLBACKS,
            "hook",
            http::bind_loopback,
        )?;
        let hook_port = v4.local_addr()?.port();
        daemon_info.hook_port.store(hook_port, Ordering::Relaxed);
        let router = http::router(http_ctx, guard.clone());
        let http_server = http::serve(router, v4, v6)?;

        let (shutdown_tx, _) = watch::channel(false);
        let inner = Arc::new(Inner {
            options: options.clone(),
            config: Mutex::new(config.clone()),
            store,
            clock,
            registry,
            pipeline,
            broker,
            devices,
            pairing,
            audit,
            bus,
            broker_settings,
            http_settings,
            link_policy,
            link_ctx,
            guard,
            daemon_info,
            hook_token: Mutex::new(hook_token),
            identity: Mutex::new(identity),
            identity_store,
            http_server: Mutex::new(Some(http_server)),
            link_server: tokio::sync::Mutex::new(None),
            hook_port,
            hook_port_problem: (options.hook_port != 0 && hook_port != options.hook_port)
                .then_some(HookPortProblem {
                    wanted: options.hook_port,
                    bound: hook_port,
                }),
            wss_port: Mutex::new(0),
            shutdown_tx,
            tasks: Mutex::new(Vec::new()),
        });
        inner.apply_policy(&config);
        inner.store_identity_row(Some(change)).await;
        if config.link.enabled {
            inner.start_link(&config).await?;
        }
        if let Err(e) = inner.write_daemon_json() {
            tracing::warn!(error = %e, "could not write daemon.json");
        }
        inner
            .audit
            .log(ACTOR_SYSTEM, actions::DAEMON_STARTED, None, None)
            .await;
        tracing::info!(hook_port, "agentnest daemon started");
        inner.handle_hook_port_problem(&config).await;
        inner.refresh_http_approval_gate();
        inner.init_adapter_status(&config).await;
        inner.spawn_timers();
        inner.run_retention().await;
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        Ok((inner, events, cmd_tx, cmd_rx))
    }

    async fn command_loop(inner: Arc<Inner>, mut rx: mpsc::Receiver<DaemonCommand>) {
        while let Some(cmd) = rx.recv().await {
            let inner = inner.clone();
            // each command runs on its own task so that a slow one (a pairing modal) never blocks the others
            tokio::spawn(async move { inner.handle(cmd).await });
        }
    }
}

impl Inner {
    /// The port of the installed HTTP hooks, if HTTP hooks are installed.
    fn installed_http_port(&self) -> Option<u16> {
        self.settings_path()
            .and_then(|p| claude_install::inspect(&p).port)
    }

    /// `PermissionRequest`s over HTTP hooks are answered only while the installed HTTP hooks point at the port the
    /// collector listens on (see [`HttpSettings::http_approvals_enabled`]). No HTTP hooks installed: nothing to protect.
    fn refresh_http_approval_gate(&self) {
        let ok = self
            .installed_http_port()
            .is_none_or(|p| p == self.hook_port);
        let was = self
            .http_settings
            .http_approvals_enabled
            .swap(ok, Ordering::Relaxed);
        if was && !ok {
            tracing::error!(
                installed = ?self.installed_http_port(),
                listening = self.hook_port,
                "hook_port_unavailable: approvals over HTTP hooks are disabled until the hooks point at the collector port"
            );
            self.bus.emit(DaemonEvent::Error {
                message: format!(
                    "hook_port_unavailable: the installed HTTP hooks point at another port than {}; approvals over HTTP hooks are off (reinstall the hooks, or use command hooks)",
                    self.hook_port
                ),
            });
        }
    }

    /// Start-up policy for a collector that had to take a fallback port.
    async fn handle_hook_port_problem(&self, cfg: &AppConfig) {
        let Some(problem) = self.hook_port_problem else {
            return;
        };
        tracing::error!(
            wanted = problem.wanted,
            bound = problem.bound,
            "hook_port_unavailable: another process holds the preferred hook port"
        );
        self.bus.emit(DaemonEvent::Error {
            message: format!(
                "hook_port_unavailable: port {} is held by another process; the collector listens on {}. HTTP hooks cannot authenticate the daemon, so use command hooks (agentnest-hook) or reinstall the hooks",
                problem.wanted, problem.bound
            ),
        });
        self.audit
            .log(
                ACTOR_SYSTEM,
                actions::HOOK_PORT_UNAVAILABLE,
                None,
                Some(serde_json::json!({"wanted": problem.wanted, "bound": problem.bound})),
            )
            .await;
        // opt-in only: rewrite the HTTP hooks to the port the collector really has
        if cfg.hooks.auto_reinstall_on_port_change && self.installed_http_port().is_some() {
            match self
                .hooks_install(HookAgent::ClaudeCode, HooksMode::Http)
                .await
            {
                Ok(_) => {
                    self.audit
                        .log(ACTOR_SYSTEM, actions::HOOKS_REPOINTED, None, None)
                        .await;
                }
                Err(e) => tracing::warn!(error = %e, "could not repoint the HTTP hooks"),
            }
        }
    }

    async fn init_adapter_status(&self, cfg: &AppConfig) {
        let installed = self
            .settings_path()
            .map(|p| claude_install::inspect(&p))
            .unwrap_or_default();
        if installed.fully_installed() {
            self.pipeline
                .set_adapter_status(
                    AgentKind::ClaudeCode,
                    AdapterStatusKind::Disconnected,
                    AdapterMode::HooksHttp,
                    Some("hooks installed, waiting for the first event".to_owned()),
                )
                .await;
        } else {
            self.pipeline
                .set_adapter_status(
                    AgentKind::ClaudeCode,
                    AdapterStatusKind::NotConfigured,
                    AdapterMode::None,
                    Some("hooks not installed".to_owned()),
                )
                .await;
        }
        match cfg.codex.mode {
            CodexMode::Off => {
                self.pipeline
                    .set_adapter_status(
                        AgentKind::Codex,
                        AdapterStatusKind::NotConfigured,
                        AdapterMode::None,
                        Some("codex disabled".to_owned()),
                    )
                    .await;
            }
            _ => {
                self.pipeline
                    .set_adapter_status(
                        AgentKind::Codex,
                        AdapterStatusKind::Degraded,
                        AdapterMode::HooksCli,
                        Some("observation only · review: not available (hooks mode)".to_owned()),
                    )
                    .await;
            }
        }
    }

    fn spawn_timers(self: &Arc<Self>) {
        let mut tasks = lock(&self.tasks);
        // broker expiry, session timers, pairing expiry
        let me = self.clone();
        let mut stop = self.shutdown_tx.subscribe();
        tasks.push(tokio::spawn(async move {
            let mut step = tokio::time::interval(Duration::from_millis(me.options.tick_ms.max(10)));
            step.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut n: u64 = 0;
            loop {
                tokio::select! {
                    _ = step.tick() => {
                        me.broker.tick().await;
                        n += 1;
                        // session timers and pairing housekeeping about once a second
                        if n.is_multiple_of((1000 / me.options.tick_ms.max(10)).max(1)) {
                            me.pipeline.tick().await;
                            me.pairing.tick();
                        }
                    }
                    _ = stop.changed() => return,
                }
            }
        }));
        // LAN address watcher
        let me = self.clone();
        let mut stop = self.shutdown_tx.subscribe();
        tasks.push(tokio::spawn(async move {
            let mut iv =
                tokio::time::interval(Duration::from_millis(me.options.addr_poll_ms.max(50)));
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            iv.tick().await;
            loop {
                tokio::select! {
                    _ = iv.tick() => me.check_addresses().await,
                    _ = stop.changed() => return,
                }
            }
        }));
        // effective TTL clamp (reads the installed hook timeout; read only)
        let me = self.clone();
        let mut stop = self.shutdown_tx.subscribe();
        tasks.push(tokio::spawn(async move {
            let mut iv =
                tokio::time::interval(Duration::from_millis(me.options.ttl_check_ms.max(50)));
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            iv.tick().await;
            loop {
                tokio::select! {
                    _ = iv.tick() => {
                        let cfg = me.config();
                        me.apply_ttl(&cfg);
                        me.refresh_http_approval_gate();
                    }
                    _ = stop.changed() => return,
                }
            }
        }));
        // retention, hourly
        let me = self.clone();
        let mut stop = self.shutdown_tx.subscribe();
        tasks.push(tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(3600));
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            iv.tick().await;
            loop {
                tokio::select! {
                    _ = iv.tick() => me.run_retention().await,
                    _ = stop.changed() => return,
                }
            }
        }));
    }

    async fn status(&self) -> DaemonStatus {
        let cfg = self.config();
        let id = lock(&self.identity).clone();
        let inspection = self
            .settings_path()
            .map(|p| claude_install::inspect(&p))
            .unwrap_or_default();
        let wss_addr = self
            .link_server
            .lock()
            .await
            .as_ref()
            .map(|s| s.addr.to_string());
        let risk = self.pairing.risk_accepted();
        DaemonStatus {
            running: true,
            hook_port: self.hook_port,
            wss_addr,
            hosts: self.hosts(),
            link_enabled: cfg.link.enabled,
            cert_expires_at: id.not_after().to_rfc3339(),
            spki_pin: id.spki_pin(),
            hooks_installed: inspection.fully_installed(),
            effective_ttl_s: self.link_policy.effective_ttl_s.load(Ordering::Relaxed),
            hook_timeout_s: inspection.permission_request_timeout_s,
            hook_port_mismatch: inspection.port.is_some_and(|p| p != self.hook_port),
            codex_mode: format!("{:?}", cfg.codex.mode).to_lowercase(),
            sessions: self.pipeline.snapshot_sessions(64).await.len(),
            devices_online: self.registry.online_count(),
            pending_approvals: self.broker.pending_count().await,
            risk_r1_accepted: risk,
            remote_approval_paused: self.broker_settings.paused(),
            pairing_active: self.pairing.active().is_some(),
        }
    }

    fn device_summary(&self, d: DeviceRecord) -> DeviceSummary {
        DeviceSummary {
            online: self.registry.is_online(&d.device_id),
            device_id: d.device_id,
            name: d.name,
            platform: d.platform,
            model: d.model,
            paired_at: d.paired_at,
            last_seen_at: d.last_seen_at,
            revoked_at: d.revoked_at,
        }
    }

    fn hooks_report(
        &self,
        installed: bool,
        path: String,
        warnings: Vec<String>,
        timeout: Option<u32>,
    ) -> HooksReport {
        HooksReport {
            installed,
            path,
            warnings,
            hook_timeout_s: timeout,
        }
    }

    async fn hooks_install(
        &self,
        agent: HookAgent,
        mode: HooksMode,
    ) -> Result<HooksReport, CommandError> {
        match agent {
            HookAgent::Codex => {
                let steps = crate::adapters::codex::install::manual_steps_ko()
                    .into_iter()
                    .map(str::to_owned)
                    .collect();
                Ok(self.hooks_report(false, "~/.codex/hooks.json".to_owned(), steps, None))
            }
            HookAgent::ClaudeCode => {
                let path = self
                    .settings_path()
                    .ok_or(CommandError::Invalid("no home directory".to_owned()))?;
                let cfg = self.config();
                let token = lock(&self.hook_token).clone();
                let hook_cli = self.options.hook_cli.clone();
                let port = self.hook_port;
                let path2 = path.clone();
                let report = tokio::task::spawn_blocking(move || {
                    claude_install::install(
                        &path2,
                        &InstallOptions {
                            mode: match mode {
                                HooksMode::Http => HookMode::Http,
                                HooksMode::Cli => HookMode::Cli,
                            },
                            hook_port: port,
                            hook_token: token.expose(),
                            approval_ttl_s: cfg.approval.ttl_s,
                            daemon_down_deny: cfg.approval.daemon_down_deny,
                            install_statusline: true,
                            hook_cli: &hook_cli,
                            backup_stamp: None,
                        },
                    )
                })
                .await
                .map_err(|_| CommandError::Internal)?
                .map_err(|e| {
                    tracing::warn!(error = %e, "hooks installation failed");
                    CommandError::Invalid(e.to_string())
                })?;
                self.audit
                    .log(
                        ACTOR_DESKTOP_USER,
                        actions::HOOKS_INSTALLED,
                        Some("claude_code".to_owned()),
                        None,
                    )
                    .await;
                self.apply_ttl(&cfg);
                self.refresh_http_approval_gate();
                let mut warnings: Vec<String> =
                    report.warnings.iter().map(|w| w.message_ko(port)).collect();
                if let Some(p) = self.hook_port_problem {
                    warnings.push(format!(
                        "기본 포트 {}를 다른 프로그램이 쓰고 있어 훅이 포트 {}를 가리켜요. HTTP 훅은 응답을 검증할 수 없으니, 그 프로그램이 의심되면 명령(CLI) 훅으로 전환하세요.",
                        p.wanted, p.bound
                    ));
                }
                Ok(self.hooks_report(
                    true,
                    report.path.display().to_string(),
                    warnings,
                    Some(report.permission_request_timeout_s),
                ))
            }
        }
    }

    async fn hooks_uninstall(&self, agent: HookAgent) -> Result<HooksReport, CommandError> {
        match agent {
            HookAgent::Codex => {
                Ok(self.hooks_report(false, "~/.codex/hooks.json".to_owned(), vec![], None))
            }
            HookAgent::ClaudeCode => {
                let path = self
                    .settings_path()
                    .ok_or(CommandError::Invalid("no home directory".to_owned()))?;
                let p2 = path.clone();
                let report = tokio::task::spawn_blocking(move || claude_install::uninstall(&p2))
                    .await
                    .map_err(|_| CommandError::Internal)?
                    .map_err(|e| CommandError::Invalid(e.to_string()))?;
                self.audit
                    .log(
                        ACTOR_DESKTOP_USER,
                        actions::HOOKS_REMOVED,
                        Some("claude_code".to_owned()),
                        None,
                    )
                    .await;
                self.apply_ttl(&self.config());
                self.refresh_http_approval_gate();
                Ok(self.hooks_report(false, report.path.display().to_string(), vec![], None))
            }
        }
    }

    fn hooks_status(&self, agent: HookAgent) -> Result<HooksReport, CommandError> {
        match agent {
            HookAgent::Codex => Ok(self.hooks_report(
                false,
                "~/.codex/hooks.json".to_owned(),
                crate::adapters::codex::install::manual_steps_ko()
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                None,
            )),
            HookAgent::ClaudeCode => {
                let path = self
                    .settings_path()
                    .ok_or(CommandError::Invalid("no home directory".to_owned()))?;
                let i = claude_install::inspect(&path);
                let mut warnings = Vec::new();
                let cfg = self.config();
                if let Some(t) = i.permission_request_timeout_s {
                    let eff = effective_ttl_s(cfg.approval.ttl_s, Some(t));
                    if eff < cfg.approval.ttl_s {
                        warnings.push(format!(
                            "훅 timeout 이 {t}초라 TTL 이 {eff}초로 제한돼요 · 훅 다시 설치"
                        ));
                    }
                }
                if let (Some(p), Some(port)) = (self.hook_port_problem, i.port) {
                    if port != self.hook_port {
                        warnings.push(format!(
                            "훅이 포트 {port}를 가리키는데 수집기는 {}에서 듣고 있어요(기본 포트 {}를 다른 프로그램이 점유). HTTP 훅 승인은 꺼져 있어요 · 훅 다시 설치 또는 명령(CLI) 훅 사용",
                            self.hook_port, p.wanted
                        ));
                    }
                }
                Ok(self.hooks_report(
                    i.fully_installed(),
                    path.display().to_string(),
                    warnings,
                    i.permission_request_timeout_s,
                ))
            }
        }
    }

    async fn settings_set(&self, new: AppConfig) -> Result<SettingsApplied, CommandError> {
        new.validate()
            .map_err(|e| CommandError::Invalid(e.to_string()))?;
        let old = self.config();
        new.save(&self.options.paths.config)
            .map_err(|e| CommandError::Invalid(e.to_string()))?;
        *lock(&self.config) = new.clone();
        self.apply_policy(&new);
        let mut applied = SettingsApplied::default();
        if new.link.bind_addr != old.link.bind_addr {
            applied.restart_required.push("link.bind_addr".to_owned());
        }
        if new.codex.mode != old.codex.mode {
            applied.restart_required.push("codex.mode".to_owned());
        }
        if new.link.enabled != old.link.enabled {
            // the stored value is already new; make the listener follow it
            let mut tmp = new.clone();
            tmp.link.enabled = old.link.enabled;
            *lock(&self.config) = tmp;
            self.set_link_enabled(new.link.enabled).await?;
        }
        Ok(applied)
    }

    async fn revoke_device(
        &self,
        device_id: String,
        name_typed: String,
    ) -> Result<(), CommandError> {
        let devices = self.devices.clone();
        let id = device_id.clone();
        let rec = tokio::task::spawn_blocking(move || devices.get(&id))
            .await
            .map_err(|_| CommandError::Internal)?
            .map_err(|_| CommandError::Internal)?
            .ok_or(CommandError::NotFound("device"))?;
        // the name has to be typed exactly (protects against a mis-click)
        if rec.name != name_typed {
            return Err(CommandError::NameMismatch);
        }
        let devices = self.devices.clone();
        let id = device_id.clone();
        let revoked = tokio::task::spawn_blocking(move || devices.revoke(&id, "user_desktop"))
            .await
            .map_err(|_| CommandError::Internal)?
            .map_err(|_| CommandError::Internal)?;
        if !revoked {
            return Err(CommandError::NotFound("device"));
        }
        // I6: effective at once: the connection gets bye{device_revoked} + 4003, its pending decisions are void
        self.registry.kick_revoked(&device_id);
        self.broker.device_revoked().await;
        self.audit
            .log(
                ACTOR_DESKTOP_USER,
                actions::DEVICE_REVOKED,
                Some(device_id.clone()),
                Some(serde_json::json!({"reason": "user_desktop"})),
            )
            .await;
        self.bus
            .emit(DaemonEvent::Device(DeviceUiEvent::Revoked { device_id }));
        Ok(())
    }

    async fn regenerate_identity(&self) -> Result<(), CommandError> {
        let lan = self.lan_addrs();
        let now =
            DateTime::<Utc>::from_timestamp_millis(self.clock.now_ms()).unwrap_or_else(Utc::now);
        let fresh = self.identity_store.regenerate(&lan, now).map_err(|e| {
            tracing::error!(error = %e, "could not regenerate the identity");
            CommandError::Internal
        })?;
        *lock(&self.identity) = fresh.clone();
        self.link_ctx
            .pc
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .pc_id = fresh.pc_id();
        // every phone must pair again: revoke them all
        let list = self.devices.list().map_err(|_| CommandError::Internal)?;
        for d in list.into_iter().filter(|d| d.revoked_at.is_none()) {
            let _ = self.devices.revoke(&d.device_id, "user_desktop");
            self.registry.kick_revoked(&d.device_id);
        }
        self.broker.device_revoked().await;
        if let Some(server) = self.link_server.lock().await.as_ref() {
            let _ = server.reload_identity(&fresh);
        }
        self.store_identity_row(Some(IdentityChange::Regenerated))
            .await;
        self.audit
            .log(
                ACTOR_DESKTOP_USER,
                actions::IDENTITY_REGENERATED,
                None,
                None,
            )
            .await;
        Ok(())
    }

    async fn rotate_hook_token(&self) -> Result<(), CommandError> {
        let fresh = generate_hook_token().map_err(|_| CommandError::Internal)?;
        // Installed HTTP hooks carry the token as a literal header: they are re-merged FIRST with the new token (an
        // installed hook with a dead token would be a 401 on every event - a total deny with `onFailure: block`). If
        // the merge fails nothing has changed yet and the old token stays valid.
        let http_installed = self.installed_http_port().is_some();
        let old = std::mem::replace(&mut *lock(&self.hook_token), fresh.clone());
        if http_installed {
            if let Err(e) = self
                .hooks_install(HookAgent::ClaudeCode, HooksMode::Http)
                .await
            {
                *lock(&self.hook_token) = old;
                tracing::warn!(error = %e, "hook token not rotated: settings.json could not be updated");
                return Err(e);
            }
        }
        self.guard.tokens.rotate(&fresh);
        self.write_daemon_json()
            .map_err(|_| CommandError::Internal)?;
        self.store_identity_row(None).await;
        self.audit
            .log(ACTOR_DESKTOP_USER, actions::HOOK_TOKEN_ROTATED, None, None)
            .await;
        Ok(())
    }

    async fn graceful_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        // no hook may hang: pending approvals go to the local prompt (empty replies)
        self.broker.shutdown().await;
        self.stop_link(ByeReason::Shutdown, true, "PC 앱이 종료돼요", 1012)
            .await;
        let server = lock(&self.http_server).take();
        if let Some(server) = server {
            server.shutdown(Duration::from_secs(2)).await;
        }
        let tasks: Vec<JoinHandle<()>> = std::mem::take(&mut *lock(&self.tasks));
        for t in tasks {
            t.abort();
        }
        let store = self.store.clone();
        let _ = tokio::task::spawn_blocking(move || store.wal_checkpoint()).await;
    }

    async fn handle(self: Arc<Self>, cmd: DaemonCommand) {
        match cmd {
            DaemonCommand::Status { reply } => {
                let _ = reply.send(Ok(self.status().await));
            }
            DaemonCommand::RiskAccept { risk_id, reply } => {
                let r = if risk_id == "R1" {
                    self.pairing.accept_risk().await.map_err(CommandError::from)
                } else {
                    Err(CommandError::Invalid("unknown risk id".to_owned()))
                };
                let _ = reply.send(r);
            }
            DaemonCommand::PairingStart { reply } => {
                let cfg = self.config();
                let r = if !cfg.link.enabled {
                    Err(CommandError::Invalid("the link is disabled".to_owned()))
                } else {
                    let (pc_id, pin) = {
                        let id = lock(&self.identity);
                        (id.pc_id(), id.spki_pin())
                    };
                    let info = PairingStartInfo {
                        pc_id,
                        pc_name: pc_display_name(&self.options),
                        hosts: self.hosts(),
                        port: *lock(&self.wss_port),
                        spki_pin: pin,
                    };
                    let started = self.pairing.start(&info).map_err(CommandError::from);
                    if started.is_ok() {
                        self.audit
                            .log(ACTOR_DESKTOP_USER, actions::PAIRING_STARTED, None, None)
                            .await;
                    }
                    started
                };
                let _ = reply.send(r);
            }
            DaemonCommand::PairingCancel { pairing_id, reply } => {
                let _ = reply.send(if self.pairing.cancel(&pairing_id) {
                    Ok(())
                } else {
                    Err(CommandError::NotFound("pairing"))
                });
            }
            DaemonCommand::PairingConfirm {
                pairing_id,
                approve,
                reply,
            } => {
                let _ = reply.send(
                    self.pairing
                        .confirm(&pairing_id, approve)
                        .map_err(CommandError::from),
                );
            }
            DaemonCommand::DevicesList { reply } => {
                let devices = self.devices.clone();
                let r = tokio::task::spawn_blocking(move || devices.list())
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .map(|v| v.into_iter().map(|d| self.device_summary(d)).collect())
                    .ok_or(CommandError::Internal);
                let _ = reply.send(r);
            }
            DaemonCommand::DeviceRevoke {
                device_id,
                name_typed,
                reply,
            } => {
                let _ = reply.send(self.revoke_device(device_id, name_typed).await);
            }
            DaemonCommand::SessionsList { reply } => {
                let _ = reply.send(Ok(self.pipeline.snapshot_sessions(64).await));
            }
            DaemonCommand::EventsRecent {
                session_key,
                limit,
                reply,
            } => {
                let r = self
                    .db(move |s| {
                        s.events_page(&crate::store::EventsQuery {
                            session_key,
                            before_seq: i64::MAX,
                            limit,
                            kinds: Vec::new(),
                            max_bytes: 1024 * 1024,
                        })
                    })
                    .await
                    .map(|p| p.events)
                    .map_err(|_| CommandError::Internal);
                let _ = reply.send(r);
            }
            DaemonCommand::ApprovalsPending { reply } => {
                let _ = reply.send(Ok(self.broker.pending_overview().await));
            }
            DaemonCommand::ApprovalHandoffLocal { request_id, reply } => {
                let _ = reply.send(if self.broker.handoff_local(&request_id).await {
                    Ok(())
                } else {
                    Err(CommandError::NotFound("approval"))
                });
            }
            DaemonCommand::ApprovalDecideLocal {
                request_id,
                decision,
                tool_input_sha256,
                confirm_ack,
                reason,
                reply,
            } => {
                let out = self
                    .broker
                    .decide_local(
                        &request_id,
                        decision,
                        &tool_input_sha256,
                        confirm_ack,
                        reason,
                    )
                    .await;
                let _ = reply.send(Ok(out));
            }
            DaemonCommand::RemoteApprovalPause { paused, reply } => {
                self.broker.set_paused(paused).await;
                self.audit
                    .log(
                        ACTOR_DESKTOP_USER,
                        if paused {
                            actions::REMOTE_APPROVAL_PAUSED
                        } else {
                            actions::REMOTE_APPROVAL_RESUMED
                        },
                        None,
                        None,
                    )
                    .await;
                let _ = reply.send(Ok(()));
            }
            DaemonCommand::LinkSetEnabled { enabled, reply } => {
                let _ = reply.send(self.set_link_enabled(enabled).await);
            }
            DaemonCommand::HooksInstall { agent, mode, reply } => {
                let _ = reply.send(self.hooks_install(agent, mode).await);
            }
            DaemonCommand::HooksUninstall { agent, reply } => {
                let _ = reply.send(self.hooks_uninstall(agent).await);
            }
            DaemonCommand::HooksStatus { agent, reply } => {
                let _ = reply.send(self.hooks_status(agent));
            }
            DaemonCommand::SettingsGet { reply } => {
                let _ = reply.send(Ok(self.config()));
            }
            DaemonCommand::SettingsSet { config, reply } => {
                let _ = reply.send(self.settings_set(*config).await);
            }
            DaemonCommand::IdentityRegenerate { reply } => {
                let _ = reply.send(self.regenerate_identity().await);
            }
            DaemonCommand::HookTokenRotate { reply } => {
                let _ = reply.send(self.rotate_hook_token().await);
            }
            DaemonCommand::Shutdown { reply } => {
                self.graceful_shutdown().await;
                let _ = reply.send(Ok(()));
            }
        }
    }
}

impl DaemonHandle {
    /// A new receiver of the event stream.
    pub fn subscribe(&self) -> broadcast::Receiver<DaemonEvent> {
        self.inner.bus.subscribe()
    }

    /// The loopback collector port.
    pub fn hook_port(&self) -> u16 {
        self.inner.hook_port
    }

    /// `Some` if the collector had to take a fallback port because the preferred one is held by another process
    /// (`hook_port_unavailable`).
    pub fn hook_port_problem(&self) -> Option<HookPortProblem> {
        self.inner.hook_port_problem
    }

    /// The WSS listener address, if it runs.
    pub fn link_addr(&self) -> Option<SocketAddr> {
        let port = *lock(&self.inner.wss_port);
        if port == 0 {
            return None;
        }
        let g = self.inner.link_server.try_lock().ok()?;
        g.as_ref().map(|s| s.addr)
    }

    /// The data directory layout.
    pub fn paths(&self) -> &Paths {
        &self.inner.options.paths
    }

    /// The current hook token (the desktop never displays it; tests use it to call the collector).
    pub fn hook_token(&self) -> HookToken {
        lock(&self.inner.hook_token).clone()
    }

    /// `sha256/<base64>` pin of the TLS identity.
    pub fn spki_pin(&self) -> String {
        lock(&self.inner.identity).spki_pin()
    }

    /// The runtime the daemon runs on (tests spawn their clients on it or a runtime of their own).
    pub fn runtime(&self) -> &tokio::runtime::Handle {
        &self.handle
    }

    /// The database handle (tests and tools; read access for assertions).
    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    /// Sends a command and waits for its reply.
    pub async fn request<T>(
        &self,
        make: impl FnOnce(Reply<T>) -> DaemonCommand,
    ) -> Result<T, CommandError> {
        let (tx, rx) = oneshot::channel();
        self.cmds
            .send(make(tx))
            .await
            .map_err(|_| CommandError::Unavailable)?;
        rx.await.map_err(|_| CommandError::Unavailable)?
    }

    /// `daemon_status`.
    pub async fn status(&self) -> Result<DaemonStatus, CommandError> {
        self.request(|reply| DaemonCommand::Status { reply }).await
    }

    /// `risk_accept("R1")`.
    pub async fn risk_accept(&self) -> Result<(), CommandError> {
        self.request(|reply| DaemonCommand::RiskAccept {
            risk_id: "R1".to_owned(),
            reply,
        })
        .await
    }

    /// `pairing_start`.
    pub async fn pairing_start(&self) -> Result<PairingStarted, CommandError> {
        self.request(|reply| DaemonCommand::PairingStart { reply })
            .await
    }

    /// `pairing_confirm`.
    pub async fn pairing_confirm(
        &self,
        pairing_id: &str,
        approve: bool,
    ) -> Result<(), CommandError> {
        let pairing_id = pairing_id.to_owned();
        self.request(|reply| DaemonCommand::PairingConfirm {
            pairing_id,
            approve,
            reply,
        })
        .await
    }

    /// `devices_list`.
    pub async fn devices_list(&self) -> Result<Vec<DeviceSummary>, CommandError> {
        self.request(|reply| DaemonCommand::DevicesList { reply })
            .await
    }

    /// `device_revoke`.
    pub async fn device_revoke(
        &self,
        device_id: &str,
        name_typed: &str,
    ) -> Result<(), CommandError> {
        let (device_id, name_typed) = (device_id.to_owned(), name_typed.to_owned());
        self.request(|reply| DaemonCommand::DeviceRevoke {
            device_id,
            name_typed,
            reply,
        })
        .await
    }

    /// `approvals_pending`.
    pub async fn approvals_pending(&self) -> Result<Vec<PendingOverview>, CommandError> {
        self.request(|reply| DaemonCommand::ApprovalsPending { reply })
            .await
    }

    /// `approval_handoff_local`.
    pub async fn approval_handoff_local(&self, request_id: &str) -> Result<(), CommandError> {
        let request_id = request_id.to_owned();
        self.request(|reply| DaemonCommand::ApprovalHandoffLocal { request_id, reply })
            .await
    }

    /// `approval_decide_local`.
    pub async fn approval_decide_local(
        &self,
        request_id: &str,
        decision: Decision,
        tool_input_sha256: &str,
        confirm_ack: bool,
        reason: Option<String>,
    ) -> Result<DecisionOutcome, CommandError> {
        let (request_id, tool_input_sha256) = (request_id.to_owned(), tool_input_sha256.to_owned());
        self.request(|reply| DaemonCommand::ApprovalDecideLocal {
            request_id,
            decision,
            tool_input_sha256,
            confirm_ack,
            reason,
            reply,
        })
        .await
    }

    /// `remote_approval_pause` / `_resume`.
    pub async fn remote_approval_pause(&self, paused: bool) -> Result<(), CommandError> {
        self.request(|reply| DaemonCommand::RemoteApprovalPause { paused, reply })
            .await
    }

    /// `link_set_enabled`.
    pub async fn link_set_enabled(&self, enabled: bool) -> Result<(), CommandError> {
        self.request(|reply| DaemonCommand::LinkSetEnabled { enabled, reply })
            .await
    }

    /// `hooks_install` for Claude Code.
    pub async fn hooks_install(&self, mode: HooksMode) -> Result<HooksReport, CommandError> {
        self.request(|reply| DaemonCommand::HooksInstall {
            agent: HookAgent::ClaudeCode,
            mode,
            reply,
        })
        .await
    }

    /// `hooks_uninstall` for Claude Code.
    pub async fn hooks_uninstall(&self) -> Result<HooksReport, CommandError> {
        self.request(|reply| DaemonCommand::HooksUninstall {
            agent: HookAgent::ClaudeCode,
            reply,
        })
        .await
    }

    /// `settings_get`.
    pub async fn settings_get(&self) -> Result<AppConfig, CommandError> {
        self.request(|reply| DaemonCommand::SettingsGet { reply })
            .await
    }

    /// `settings_set`.
    pub async fn settings_set(&self, config: AppConfig) -> Result<SettingsApplied, CommandError> {
        self.request(|reply| DaemonCommand::SettingsSet {
            config: Box::new(config),
            reply,
        })
        .await
    }

    /// Graceful shutdown (async).
    pub async fn shutdown(&self) -> Result<(), CommandError> {
        self.request(|reply| DaemonCommand::Shutdown { reply })
            .await
    }

    /// Graceful shutdown for synchronous callers (the Tauri `ExitRequested` handler): waits for it to finish.
    pub fn shutdown_blocking(&self) {
        let (tx, rx) = oneshot::channel();
        if self
            .cmds
            .blocking_send(DaemonCommand::Shutdown { reply: tx })
            .is_ok()
        {
            let _ = rx.blocking_recv();
        }
    }

    /// The distinct set of tasks left (tests).
    #[doc(hidden)]
    pub fn debug_online_devices(&self) -> BTreeSet<String> {
        self.inner.registry.online_devices().into_iter().collect()
    }
}
