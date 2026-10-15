//! `settings_get` / `settings_set`: the whitelisted, flat, dot-notation settings of the front end (docs/desktop.md 3.1).
//!
//! Two stores back the keys: the daemon's [`AppConfig`] (security relevant settings, validated and persisted by the
//! daemon) and [`UiSettings`] (purely cosmetic: notifications, onboarding). Security.md 9: a forbidden field cannot be
//! set because **only the keys in [`WRITABLE_KEYS`] exist**; every other key, including `link.enabled`
//! (`link_set_enabled` owns it), `app.autostart` (the autostart plugin owns it) and anything that looks like
//! `auto_allow_*` / `allow_for_session` / `risk_overrides`, answers `UNKNOWN_SETTING` and touches nothing.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use agentnest_core::config::{AppConfig, CriticalRemote, LogLevel};
use agentnest_protocol::limits::{APPROVAL_TTL_MAX_S, APPROVAL_TTL_MIN_S};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// File name of the UI settings inside the data directory.
pub const UI_SETTINGS_FILE: &str = "ui-settings.json";

/// The keys `settings_set` accepts.
pub const WRITABLE_KEYS: &[&str] = &[
    "approval.ttl_s",
    "approval.deny_requires_auth",
    "approval.critical_remote",
    "approval.daemon_down_deny",
    "app.notifications",
    "app.log_level",
    "onboarding.completed",
    "onboarding.codex_steps_done",
];

/// Keys that `settings_get` returns but `settings_set` refuses (`risk.accepted` is written by `risk_accept` only).
pub const READ_ONLY_KEYS: &[&str] = &["risk.accepted"];

/// The Codex hooks onboarding steps (docs/desktop.md 6.1).
pub const CODEX_STEPS: &[&str] = &["hooks_json", "trust", "doctor"];

/// Why a `settings_set` was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingError {
    /// The key is not on the whitelist (`UNKNOWN_SETTING`).
    Unknown,
    /// Known key, value out of range or of the wrong type (`INVALID_SETTING`).
    Invalid,
}

/// Cosmetic settings the daemon does not know about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UiSettings {
    /// Desktop toasts.
    pub notifications: bool,
    /// The first-run checklist was completed.
    pub onboarding_completed: bool,
    /// Finished Codex onboarding steps (subset of [`CODEX_STEPS`]).
    pub codex_steps_done: Vec<String>,
}

impl Default for UiSettings {
    fn default() -> Self {
        Self {
            notifications: true,
            onboarding_completed: false,
            codex_steps_done: Vec::new(),
        }
    }
}

/// Where [`UiSettings`] live.
pub trait UiSettingsStore: Send + Sync + 'static {
    /// Reads the settings; a missing or unreadable store yields the defaults.
    fn load(&self) -> UiSettings;
    /// Persists the settings.
    fn save(&self, settings: &UiSettings) -> std::io::Result<()>;
}

/// A JSON file written atomically (temporary file, then rename).
#[derive(Clone, Debug)]
pub struct FileUiSettings {
    path: PathBuf,
}

impl FileUiSettings {
    /// The store at `<data dir>/ui-settings.json`.
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            path: dir.join(UI_SETTINGS_FILE),
        }
    }
}

impl UiSettingsStore for FileUiSettings {
    fn load(&self) -> UiSettings {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return UiSettings::default();
        };
        let mut s: UiSettings = serde_json::from_str(&text).unwrap_or_else(|_| {
            tracing::warn!("ui-settings.json is unreadable; using defaults");
            UiSettings::default()
        });
        // a hand-edited file may carry anything: keep only known, deduplicated steps
        s.codex_steps_done = normalise_steps(&s.codex_steps_done);
        s
    }

    fn save(&self, settings: &UiSettings) -> std::io::Result<()> {
        let text = serde_json::to_string_pretty(settings).map_err(std::io::Error::other)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.path)
    }
}

/// An in-memory store (tests, and the fallback when the data directory cannot be written).
#[derive(Debug, Default)]
pub struct MemoryUiSettings(Mutex<UiSettings>);

impl UiSettingsStore for MemoryUiSettings {
    fn load(&self) -> UiSettings {
        self.0.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn save(&self, settings: &UiSettings) -> std::io::Result<()> {
        if let Ok(mut g) = self.0.lock() {
            *g = settings.clone();
        }
        Ok(())
    }
}

fn normalise_steps(steps: &[String]) -> Vec<String> {
    CODEX_STEPS
        .iter()
        .filter(|known| steps.iter().any(|s| s == *known))
        .map(|s| (*s).to_owned())
        .collect()
}

fn as_ttl(value: &Value) -> Option<u32> {
    let n = if let Some(i) = value.as_i64() {
        i
    } else {
        let f = value.as_f64()?;
        if !f.is_finite() || f.fract() != 0.0 || f.abs() > 1e9 {
            return None;
        }
        f as i64
    };
    let range = i64::from(APPROVAL_TTL_MIN_S)..=i64::from(APPROVAL_TTL_MAX_S);
    range.contains(&n).then_some(n as u32)
}

/// Applies one `settings_set(key, value)` to `cfg` / `ui` in memory. Nothing is persisted here; the caller validates
/// and saves. On error neither argument has changed.
pub fn apply_setting(
    key: &str,
    value: &Value,
    cfg: &mut AppConfig,
    ui: &mut UiSettings,
) -> Result<(), SettingError> {
    if READ_ONLY_KEYS.contains(&key) {
        return Err(SettingError::Invalid);
    }
    if !WRITABLE_KEYS.contains(&key) {
        return Err(SettingError::Unknown);
    }
    match key {
        "approval.ttl_s" => cfg.approval.ttl_s = as_ttl(value).ok_or(SettingError::Invalid)?,
        "approval.deny_requires_auth" => {
            cfg.approval.deny_requires_auth = value.as_bool().ok_or(SettingError::Invalid)?;
        }
        "approval.daemon_down_deny" => {
            cfg.approval.daemon_down_deny = value.as_bool().ok_or(SettingError::Invalid)?;
        }
        "approval.critical_remote" => {
            cfg.approval.critical_remote = serde_json::from_value::<CriticalRemote>(value.clone())
                .map_err(|_| SettingError::Invalid)?;
        }
        "app.log_level" => {
            cfg.log_level = serde_json::from_value::<LogLevel>(value.clone())
                .map_err(|_| SettingError::Invalid)?;
        }
        "app.notifications" => ui.notifications = value.as_bool().ok_or(SettingError::Invalid)?,
        "onboarding.completed" => {
            ui.onboarding_completed = value.as_bool().ok_or(SettingError::Invalid)?;
        }
        "onboarding.codex_steps_done" => {
            let items = value.as_array().ok_or(SettingError::Invalid)?;
            let mut steps = Vec::with_capacity(items.len());
            for item in items {
                let s = item.as_str().ok_or(SettingError::Invalid)?;
                if !CODEX_STEPS.contains(&s) {
                    return Err(SettingError::Invalid);
                }
                steps.push(s.to_owned());
            }
            ui.codex_steps_done = normalise_steps(&steps);
        }
        _ => return Err(SettingError::Unknown),
    }
    Ok(())
}

/// The flat settings object `settings_get` / `settings_set` return. `app.autostart` is deliberately absent (the
/// front end owns it through the autostart plugin).
pub fn settings_value(cfg: &AppConfig, ui: &UiSettings, risk_r1_accepted: bool) -> Value {
    json!({
        "approval.ttl_s": cfg.approval.ttl_s,
        "approval.deny_requires_auth": cfg.approval.deny_requires_auth,
        "approval.critical_remote": cfg.approval.critical_remote.as_str(),
        "approval.daemon_down_deny": cfg.approval.daemon_down_deny,
        "app.notifications": ui.notifications,
        "app.log_level": cfg.log_level.as_str(),
        "onboarding.completed": ui.onboarding_completed,
        "onboarding.codex_steps_done": ui.codex_steps_done,
        "risk.accepted": if risk_r1_accepted { json!(["R1"]) } else { json!([]) },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> (AppConfig, UiSettings) {
        (AppConfig::default(), UiSettings::default())
    }

    #[test]
    fn every_writable_key_accepts_a_valid_value_and_changes_only_itself() {
        let cases: Vec<(&str, Value)> = vec![
            ("approval.ttl_s", json!(90)),
            ("approval.deny_requires_auth", json!(true)),
            ("approval.critical_remote", json!("local_only")),
            ("approval.daemon_down_deny", json!(true)),
            ("app.notifications", json!(false)),
            ("app.log_level", json!("debug")),
            ("onboarding.completed", json!(true)),
            ("onboarding.codex_steps_done", json!(["trust", "hooks_json"])),
        ];
        assert_eq!(cases.len(), WRITABLE_KEYS.len());
        for (key, value) in cases {
            let (mut cfg, mut ui) = fresh();
            apply_setting(key, &value, &mut cfg, &mut ui).unwrap();
            let after = settings_value(&cfg, &ui, false);
            let before = settings_value(&AppConfig::default(), &UiSettings::default(), false);
            let changed: Vec<&str> = after
                .as_object()
                .unwrap()
                .iter()
                .filter(|(k, v)| before[k.as_str()] != **v)
                .map(|(k, _)| k.as_str())
                .collect();
            assert_eq!(changed, vec![key], "{key} must change exactly itself");
            // security.md 9 fields that have no UI key stay untouched
            let d = AppConfig::default();
            assert_eq!(cfg.link, d.link);
            assert_eq!(cfg.pairing, d.pairing);
            assert_eq!(cfg.risk, d.risk);
            assert_eq!(cfg.codex, d.codex);
            assert_eq!(cfg.approval.reconnect_grace_s, d.approval.reconnect_grace_s);
            cfg.validate().unwrap();
        }
    }

    #[test]
    fn forbidden_and_unlisted_keys_are_unknown() {
        let forbidden = [
            "auto_allow_low",
            "auto_allow_all",
            "approval.auto_allow",
            "allow_for_session",
            "approval.allow_for_session",
            "trust_all_certs",
            "bind_hooks_all_interfaces",
            "hook_bind_addr",
            "disable_biometric",
            "skip_auth_for_low",
            "skip_auth_for_phone",
            "approval_ttl_s",
            "risk_overrides",
            "risk.overrides",
            "risk_rules_path",
            "risk.rules_path",
            // real settings that this API must not write
            "link.enabled",
            "link.bind_addr",
            "link.private_sources_only",
            "app.autostart",
            "approval.reconnect_grace_s",
            "pairing.confirm_mode",
            "risk.force_ask_on_critical",
            "codex.mode",
            "",
            "APPROVAL.TTL_S",
        ];
        for key in forbidden {
            let (mut cfg, mut ui) = fresh();
            let r = apply_setting(key, &json!(true), &mut cfg, &mut ui);
            assert_eq!(r, Err(SettingError::Unknown), "{key:?}");
            assert_eq!((cfg, ui), fresh(), "{key:?} must not change anything");
        }
    }

    #[test]
    fn risk_accepted_is_read_only() {
        let (mut cfg, mut ui) = fresh();
        assert_eq!(
            apply_setting("risk.accepted", &json!(["R1"]), &mut cfg, &mut ui),
            Err(SettingError::Invalid)
        );
        assert!(READ_ONLY_KEYS.contains(&"risk.accepted"));
    }

    #[test]
    fn ttl_is_60_to_180_integers_only() {
        for bad in [
            json!(59),
            json!(181),
            json!(0),
            json!(-120),
            json!(120.5),
            json!("120"),
            json!(true),
            json!(null),
            json!(1e12),
            json!([120]),
        ] {
            let (mut cfg, mut ui) = fresh();
            assert_eq!(
                apply_setting("approval.ttl_s", &bad, &mut cfg, &mut ui),
                Err(SettingError::Invalid),
                "{bad}"
            );
            assert_eq!(cfg.approval.ttl_s, 120);
        }
        for ok in [60, 61, 120, 179, 180] {
            let (mut cfg, mut ui) = fresh();
            apply_setting("approval.ttl_s", &json!(ok), &mut cfg, &mut ui).unwrap();
            assert_eq!(cfg.approval.ttl_s, ok as u32);
        }
        // an integer-valued float is what a JS number may serialise to
        let (mut cfg, mut ui) = fresh();
        apply_setting("approval.ttl_s", &json!(90.0), &mut cfg, &mut ui).unwrap();
        assert_eq!(cfg.approval.ttl_s, 90);
    }

    #[test]
    fn enums_and_booleans_are_strict() {
        let (mut cfg, mut ui) = fresh();
        for (key, bad) in [
            ("approval.critical_remote", json!("none")),
            ("approval.critical_remote", json!("LOCAL_ONLY")),
            ("approval.critical_remote", json!(1)),
            ("app.log_level", json!("trace")),
            ("app.log_level", json!(null)),
            ("approval.deny_requires_auth", json!("true")),
            ("approval.daemon_down_deny", json!(1)),
            ("app.notifications", json!("yes")),
            ("onboarding.completed", json!(null)),
            ("onboarding.codex_steps_done", json!("trust")),
            ("onboarding.codex_steps_done", json!(["trust", "bogus"])),
            ("onboarding.codex_steps_done", json!([1])),
        ] {
            assert_eq!(
                apply_setting(key, &bad, &mut cfg, &mut ui),
                Err(SettingError::Invalid),
                "{key} {bad}"
            );
        }
        assert_eq!((cfg, ui), fresh());
    }

    #[test]
    fn codex_steps_are_deduplicated_and_ordered() {
        let (mut cfg, mut ui) = fresh();
        apply_setting(
            "onboarding.codex_steps_done",
            &json!(["doctor", "hooks_json", "doctor"]),
            &mut cfg,
            &mut ui,
        )
        .unwrap();
        assert_eq!(ui.codex_steps_done, vec!["hooks_json", "doctor"]);
    }

    #[test]
    fn settings_value_has_the_contract_keys_and_no_autostart() {
        let (cfg, ui) = fresh();
        let v = settings_value(&cfg, &ui, true);
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut want: Vec<&str> = WRITABLE_KEYS.iter().chain(READ_ONLY_KEYS).copied().collect();
        want.sort_unstable();
        assert_eq!(keys, want);
        assert!(v.get("app.autostart").is_none());
        assert_eq!(v["risk.accepted"], json!(["R1"]));
        assert_eq!(settings_value(&cfg, &ui, false)["risk.accepted"], json!([]));
        assert_eq!(v["approval.ttl_s"], 120);
        assert_eq!(v["approval.critical_remote"], "extra_confirmation");
        assert_eq!(v["app.log_level"], "info");
        assert_eq!(v["app.notifications"], true);
    }

    #[test]
    fn file_store_round_trips_and_survives_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileUiSettings::in_dir(dir.path());
        assert_eq!(store.load(), UiSettings::default());
        let s = UiSettings {
            notifications: false,
            onboarding_completed: true,
            codex_steps_done: vec!["trust".into()],
        };
        store.save(&s).unwrap();
        assert_eq!(store.load(), s);
        std::fs::write(dir.path().join(UI_SETTINGS_FILE), "{not json").unwrap();
        assert_eq!(store.load(), UiSettings::default());
        // unknown keys in a hand-edited file are ignored and unknown steps dropped
        std::fs::write(
            dir.path().join(UI_SETTINGS_FILE),
            r#"{"notifications":false,"auto_allow_low":true,"codex_steps_done":["trust","x"]}"#,
        )
        .unwrap();
        let loaded = store.load();
        assert!(!loaded.notifications);
        assert_eq!(loaded.codex_steps_done, vec!["trust"]);
    }

    #[test]
    fn the_ui_settings_file_has_no_security_fields() {
        let text = serde_json::to_string(&UiSettings::default()).unwrap();
        for forbidden in ["auto_allow", "allow_for_session", "trust_all", "risk_overrides", "ttl"] {
            assert!(!text.contains(forbidden), "{forbidden} in {text}");
        }
    }
}
