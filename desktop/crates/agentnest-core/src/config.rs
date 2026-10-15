//! `AppConfig`: the daemon configuration file (docs/security.md 9) and the on-disk locations.
//!
//! # Security shape (I10)
//!
//! * **Forbidden fields do not exist.** `AppConfig` and every nested struct use `#[serde(deny_unknown_fields)]`, so a
//!   configuration file that contains `auto_allow_*`, `allow_for_session`, `trust_all_certs`,
//!   `bind_hooks_all_interfaces`, `hook_bind_addr`, `disable_biometric`, `skip_auth_for_*`, `approval_ttl_s`,
//!   `risk_overrides`, `risk_rules_path` (or anything else unknown) is **rejected and the daemon does not start**.
//!   There is no struct field with such a name (a test walks the serialised default to prove it).
//! * **Every security setting can only be tightened** and has a validated range ([`AppConfig::validate`]): the approval
//!   TTL is 60..=180 s, the reconnect grace 0..=10 s, `link.private_sources_only` cannot be switched off before
//!   Phase 3, `link.bind_addr` rejects the unspecified address (`0.0.0.0`, `::`).
//! * The hook collector address is **not** a setting: it is `127.0.0.1` / `[::1]` in code (`http` module).
//!
//! The file is JSON (`config.json`); a missing file means defaults. Locations: [`Paths`].

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use agentnest_protocol::limits::{APPROVAL_TTL_DEFAULT_S, APPROVAL_TTL_MAX_S, APPROVAL_TTL_MIN_S};

/// File name of the configuration file inside the data directory.
pub const CONFIG_FILE_NAME: &str = "config.json";
/// File name of `daemon.json` (hook port, WSS port, hook token; docs/integrations/claude-code.md 2).
pub const DAEMON_JSON_NAME: &str = "daemon.json";
/// File name of the SQLite database.
pub const DB_FILE_NAME: &str = "agentnest.db";
/// Largest allowed reconnect grace in seconds (security.md 9).
pub const RECONNECT_GRACE_MAX_S: u32 = 10;

/// Configuration errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Reading or writing the file failed.
    #[error("config io error: {0}")]
    Io(#[from] std::io::Error),
    /// The file is not valid JSON or contains an unknown (possibly forbidden) key.
    #[error("config parse error: {0}")]
    Parse(String),
    /// A value is outside its allowed range.
    #[error("invalid config value for {key}: {reason}")]
    Invalid {
        /// Dotted key.
        key: &'static str,
        /// Why.
        reason: &'static str,
    },
    /// The per-user data directory could not be determined.
    #[error("no user data directory available")]
    NoDataDir,
}

/// What the daemon does with a `critical` request (security.md 9). Only the stricter value `local_only` removes remote
/// approval; neither value allows anything the risk rules forbid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CriticalRemote {
    /// Remote approval with long press, re-confirmation sheet and biometrics (default).
    ExtraConfirmation,
    /// Critical requests are never sent to the phone: they go straight to the local prompt.
    LocalOnly,
}

impl CriticalRemote {
    /// The wire / config spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            CriticalRemote::ExtraConfirmation => "extra_confirmation",
            CriticalRemote::LocalOnly => "local_only",
        }
    }
}

/// `approval.*`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ApprovalConfig {
    /// Requested TTL in seconds, 60..=180. The effective TTL is also bounded by the installed hook `timeout - 30`
    /// (claude-code.md 2).
    pub ttl_s: u32,
    /// Handling of `critical` requests.
    pub critical_remote: CriticalRemote,
    /// A deny also needs biometrics. Owned by the PC and sent to the phone in `welcome.policy`. Can only be turned on.
    pub deny_requires_auth: bool,
    /// Install the hook with `"onFailure":"block"` (deny when the daemon is down). Opt-in, tightening only.
    pub daemon_down_deny: bool,
    /// Grace period in seconds after the last phone disconnected before pending requests are handed to the local
    /// prompt, 0..=10.
    pub reconnect_grace_s: u32,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            ttl_s: APPROVAL_TTL_DEFAULT_S,
            critical_remote: CriticalRemote::ExtraConfirmation,
            deny_requires_auth: false,
            daemon_down_deny: false,
            reconnect_grace_s: RECONNECT_GRACE_MAX_S,
        }
    }
}

/// How the phone confirms the pairing SAS (security.md 4.3). `retype_sas` only tightens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmMode {
    /// The phone shows the SAS it computed and the PC user compares (default).
    SasDisplay,
    /// The user types the SAS on the phone (stricter).
    RetypeSas,
}

/// `pairing.*`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PairingConfig {
    /// SAS confirmation mode.
    pub confirm_mode: ConfirmMode,
}

impl Default for PairingConfig {
    fn default() -> Self {
        Self {
            confirm_mode: ConfirmMode::SasDisplay,
        }
    }
}

/// `risk.*`. There is no way to lower a risk level from configuration (I10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RiskConfig {
    /// Answer a critical `PreToolUse` with `ask` (forces the local prompt). Turning it off removes only that forcing.
    pub force_ask_on_critical: bool,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            force_ask_on_critical: true,
        }
    }
}

/// `link.*`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LinkConfig {
    /// LAN interface address to bind the WSS listener to. `None` = the primary interface at start. Never
    /// `0.0.0.0` / `::`.
    pub bind_addr: Option<IpAddr>,
    /// Accept only private-range (and loopback) source addresses. Cannot be switched off before Phase 3.
    pub private_sources_only: bool,
    /// `false` closes the listener ("disconnect phones", security.md 3.3).
    pub enabled: bool,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            bind_addr: None,
            private_sources_only: true,
            enabled: true,
        }
    }
}

/// `codex.mode` (security.md 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexMode {
    /// Command hooks (`agentnest-hook codex`), observation only by default.
    Hooks,
    /// Shared app-server socket subscription. UNVERIFIED (Phase 0); only in builds with `codex-daemon-observer`.
    DaemonObserver,
    /// No Codex adapter.
    Off,
}

/// `codex.*`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CodexConfig {
    /// Collection mode.
    pub mode: CodexMode,
}

impl Default for CodexConfig {
    fn default() -> Self {
        Self {
            mode: CodexMode::Hooks,
        }
    }
}

/// Log verbosity of the daemon (`tracing` filter level). Request bodies are never logged at any level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    /// Errors only.
    Error,
    /// Warnings and errors.
    Warn,
    /// Default.
    Info,
    /// Debug.
    Debug,
}

impl LogLevel {
    /// The `tracing` directive.
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
        }
    }
}

/// The whole configuration file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AppConfig {
    /// `approval.*`.
    pub approval: ApprovalConfig,
    /// `pairing.*`.
    pub pairing: PairingConfig,
    /// `risk.*`.
    pub risk: RiskConfig,
    /// `link.*`.
    pub link: LinkConfig,
    /// `codex.*`.
    pub codex: CodexConfig,
    /// Log level.
    pub log_level: LogLevel,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            approval: ApprovalConfig::default(),
            pairing: PairingConfig::default(),
            risk: RiskConfig::default(),
            link: LinkConfig::default(),
            codex: CodexConfig::default(),
            log_level: LogLevel::Info,
        }
    }
}

impl AppConfig {
    /// Checks every range of security.md 9.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let a = &self.approval;
        if !(APPROVAL_TTL_MIN_S..=APPROVAL_TTL_MAX_S).contains(&a.ttl_s) {
            return Err(ConfigError::Invalid {
                key: "approval.ttl_s",
                reason: "must be between 60 and 180 seconds",
            });
        }
        if a.reconnect_grace_s > RECONNECT_GRACE_MAX_S {
            return Err(ConfigError::Invalid {
                key: "approval.reconnect_grace_s",
                reason: "must be between 0 and 10 seconds",
            });
        }
        if !self.link.private_sources_only {
            return Err(ConfigError::Invalid {
                key: "link.private_sources_only",
                reason: "cannot be disabled before Phase 3",
            });
        }
        if let Some(ip) = self.link.bind_addr {
            if ip.is_unspecified() {
                return Err(ConfigError::Invalid {
                    key: "link.bind_addr",
                    reason: "0.0.0.0 and :: are rejected; choose a LAN interface address",
                });
            }
            if ip.is_multicast() {
                return Err(ConfigError::Invalid {
                    key: "link.bind_addr",
                    reason: "multicast addresses are not valid",
                });
            }
        }
        if self.codex.mode == CodexMode::DaemonObserver && !cfg!(feature = "codex-daemon-observer")
        {
            return Err(ConfigError::Invalid {
                key: "codex.mode",
                reason: "daemon_observer needs a build with the codex-daemon-observer feature",
            });
        }
        Ok(())
    }

    /// Parses and validates a configuration. Unknown keys (forbidden or not) are an error.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        let cfg: AppConfig =
            serde_json::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Loads `path`; a missing file yields the defaults.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_json(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(ConfigError::Io(e)),
        }
    }

    /// Validates and writes the configuration atomically (temporary file, then rename).
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        self.validate()?;
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| ConfigError::Parse(e.to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// On-disk locations of the daemon (docs/storage.md, security.md 3 and 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    /// Data directory (`%LOCALAPPDATA%\AgentNest`).
    pub root: PathBuf,
    /// SQLite database.
    pub db: PathBuf,
    /// Configuration file.
    pub config: PathBuf,
    /// `daemon.json` (ports and hook token; user-only permissions).
    pub daemon_json: PathBuf,
    /// Directory of the server key and certificate.
    pub identity_dir: PathBuf,
    /// Rolling log files.
    pub logs_dir: PathBuf,
}

impl Paths {
    /// All locations below `root` (tests inject a temporary directory here).
    pub fn in_dir(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            db: root.join(DB_FILE_NAME),
            config: root.join(CONFIG_FILE_NAME),
            daemon_json: root.join(DAEMON_JSON_NAME),
            identity_dir: root.join("identity"),
            logs_dir: root.join("logs"),
            root,
        }
    }

    /// The per-user location: `%LOCALAPPDATA%\AgentNest\` on Windows (`directories` resolves the Known Folder), the
    /// XDG data directory elsewhere.
    pub fn default_for_user() -> Result<Self, ConfigError> {
        let base = directories::BaseDirs::new().ok_or(ConfigError::NoDataDir)?;
        Ok(Self::in_dir(base.data_local_dir().join("AgentNest")))
    }

    /// Creates the directories.
    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.root)?;
        std::fs::create_dir_all(&self.identity_dir)?;
        std::fs::create_dir_all(&self.logs_dir)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn defaults_are_valid_and_match_the_documented_values() {
        let c = AppConfig::default();
        c.validate().unwrap();
        assert_eq!(c.approval.ttl_s, 120);
        assert_eq!(c.approval.critical_remote, CriticalRemote::ExtraConfirmation);
        assert!(!c.approval.deny_requires_auth);
        assert!(!c.approval.daemon_down_deny);
        assert_eq!(c.approval.reconnect_grace_s, 10);
        assert_eq!(c.pairing.confirm_mode, ConfirmMode::SasDisplay);
        assert!(c.risk.force_ask_on_critical);
        assert!(c.link.private_sources_only);
        assert!(c.link.enabled);
        assert_eq!(c.link.bind_addr, None);
        assert_eq!(c.codex.mode, CodexMode::Hooks);
    }

    #[test]
    fn empty_object_and_partial_files_fill_in_defaults() {
        assert_eq!(AppConfig::from_json("{}").unwrap(), AppConfig::default());
        let c = AppConfig::from_json(r#"{"approval":{"ttl_s":90}}"#).unwrap();
        assert_eq!(c.approval.ttl_s, 90);
        assert_eq!(c.approval.reconnect_grace_s, 10);
    }

    fn keys(v: &Value, out: &mut Vec<String>) {
        if let Value::Object(m) = v {
            for (k, x) in m {
                out.push(k.clone());
                keys(x, out);
            }
        }
    }

    #[test]
    fn the_serialised_config_contains_none_of_the_forbidden_fields() {
        let mut all = Vec::new();
        keys(&serde_json::to_value(AppConfig::default()).unwrap(), &mut all);
        assert!(all.len() >= 10, "{all:?}");
        for k in &all {
            for bad in [
                "auto_allow",
                "allow_for_session",
                "trust_all_certs",
                "bind_hooks_all_interfaces",
                "hook_bind_addr",
                "disable_biometric",
                "skip_auth_for",
                "approval_ttl_s",
                "risk_overrides",
                "risk_rules_path",
            ] {
                assert!(!k.starts_with(bad), "forbidden field {k}");
            }
        }
    }

    #[test]
    fn forbidden_and_unknown_keys_are_rejected_at_every_level() {
        let forbidden = [
            "auto_allow_low",
            "auto_allow_tests",
            "allow_for_session",
            "trust_all_certs",
            "bind_hooks_all_interfaces",
            "hook_bind_addr",
            "disable_biometric",
            "skip_auth_for_deny",
            "approval_ttl_s",
            "risk_overrides",
            "risk_rules_path",
            "some_future_key",
        ];
        for key in forbidden {
            // top level and inside every section
            for section in [None, Some("approval"), Some("pairing"), Some("risk"), Some("link"), Some("codex")]
            {
                let doc = match section {
                    None => json!({ key: true }),
                    Some(s) => json!({ s: { key: true } }),
                };
                let r = AppConfig::from_json(&doc.to_string());
                assert!(
                    matches!(r, Err(ConfigError::Parse(_))),
                    "{key} in {section:?} must be rejected, got {r:?}"
                );
            }
        }
    }

    #[test]
    fn ranges_are_enforced() {
        for ttl in [0, 59, 181, 600, u32::MAX] {
            let r = AppConfig::from_json(&json!({"approval": {"ttl_s": ttl}}).to_string());
            assert!(matches!(r, Err(ConfigError::Invalid { key: "approval.ttl_s", .. })), "{ttl}");
        }
        for ttl in [60, 120, 180] {
            AppConfig::from_json(&json!({"approval": {"ttl_s": ttl}}).to_string()).unwrap();
        }
        assert!(AppConfig::from_json(r#"{"approval":{"reconnect_grace_s":11}}"#).is_err());
        AppConfig::from_json(r#"{"approval":{"reconnect_grace_s":0}}"#).unwrap();
        assert!(AppConfig::from_json(r#"{"link":{"private_sources_only":false}}"#).is_err());
        assert!(AppConfig::from_json(r#"{"link":{"bind_addr":"0.0.0.0"}}"#).is_err());
        assert!(AppConfig::from_json(r#"{"link":{"bind_addr":"::"}}"#).is_err());
        AppConfig::from_json(r#"{"link":{"bind_addr":"192.168.0.10"}}"#).unwrap();
        // wrong types and unknown enum spellings are parse errors, not silent defaults
        assert!(AppConfig::from_json(r#"{"approval":{"critical_remote":"allow_all"}}"#).is_err());
        assert!(AppConfig::from_json(r#"{"approval":{"ttl_s":"120"}}"#).is_err());
        assert!(AppConfig::from_json("not json").is_err());
    }

    #[cfg(not(feature = "codex-daemon-observer"))]
    #[test]
    fn daemon_observer_needs_the_feature() {
        assert!(AppConfig::from_json(r#"{"codex":{"mode":"daemon_observer"}}"#).is_err());
        AppConfig::from_json(r#"{"codex":{"mode":"off"}}"#).unwrap();
    }

    #[test]
    fn save_and_load_round_trip_in_a_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::in_dir(dir.path());
        assert_eq!(AppConfig::load(&paths.config).unwrap(), AppConfig::default());
        let mut c = AppConfig::default();
        c.approval.ttl_s = 150;
        c.approval.deny_requires_auth = true;
        c.link.enabled = false;
        c.save(&paths.config).unwrap();
        assert_eq!(AppConfig::load(&paths.config).unwrap(), c);
        // an invalid config is refused on save
        c.approval.ttl_s = 500;
        assert!(c.save(&paths.config).is_err());
        // a file with a forbidden key refuses to load
        std::fs::write(&paths.config, r#"{"hook_bind_addr":"0.0.0.0"}"#).unwrap();
        assert!(matches!(AppConfig::load(&paths.config), Err(ConfigError::Parse(_))));
    }

    #[test]
    fn paths_live_below_the_root() {
        let p = Paths::in_dir("/tmp/x");
        assert!(p.db.starts_with("/tmp/x"));
        assert!(p.identity_dir.ends_with("identity"));
        assert!(p.daemon_json.ends_with("daemon.json"));
        // the per-user default exists on CI machines too
        if let Ok(p) = Paths::default_for_user() {
            assert!(p.root.ends_with("AgentNest"));
        }
    }
}
