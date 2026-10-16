//! Result payloads of the Tauri commands, shaped exactly as `desktop/apps/desktop/src/api/guards.ts` reads them.
//!
//! Rules (docs/desktop.md 3.1, security.md 8.1): no secret value ever leaves through these types. The pairing QR is an
//! SVG only (never the `agentnest://` URI), an approval card loses its `nonce_b64`, an event loses its `detail` object,
//! devices carry no keys or hashes.

use agentnest_core::approvals::broker::PendingOverview;
use agentnest_core::auth::pairing::PairingStarted;
use agentnest_core::daemon::{DaemonStatus as CoreStatus, DeviceSummary, HooksReport};
use agentnest_protocol::{AgentEvent, ApprovalRequest};
use serde::Serialize;
use serde_json::{json, Map, Value};

/// `daemon_status.last_event_at`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct LastEventAt {
    /// Last Claude Code event (RFC 3339) or `null`.
    pub claude_code: Option<String>,
    /// Last Codex event or `null`.
    pub codex: Option<String>,
}

/// `daemon_status` (docs/desktop.md 3 + 3.1). No secrets: `spki_pin` is a public key fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DaemonStatusDto {
    /// The daemon answers.
    pub running: bool,
    /// Loopback collector port.
    pub hook_port: u16,
    /// `ip:port` of the WSS listener, empty if it is not listening.
    pub wss_addr: String,
    /// Advertised LAN addresses.
    pub hosts: Vec<String>,
    /// `link.enabled`.
    pub link_enabled: bool,
    /// End of the certificate validity.
    pub cert_expires_at: Option<String>,
    /// `sha256/<base64>` pin.
    pub spki_pin: String,
    /// All Claude Code hooks are installed.
    pub hooks_installed: bool,
    /// Effective approval TTL in seconds.
    pub effective_ttl_s: u32,
    /// Installed `PermissionRequest` timeout, `0` if the hooks are not installed.
    pub hook_timeout_s: u32,
    /// `hooks` | `daemon_observer` | `off`.
    pub codex_mode: &'static str,
    /// Live sessions.
    pub sessions: usize,
    /// Online phones.
    pub devices_online: usize,
    /// Remote approval paused.
    pub remote_approval_paused: bool,
    /// Last event per agent.
    pub last_event_at: LastEventAt,
}

/// The core spells the Codex mode with `format!("{:?}")` lowercased (`daemonobserver`); the contract spells it
/// `daemon_observer`. Unknown values become `off` (nothing is collected).
pub fn codex_mode_str(core: &str) -> &'static str {
    match core {
        "hooks" => "hooks",
        "daemonobserver" | "daemon_observer" => "daemon_observer",
        _ => "off",
    }
}

impl DaemonStatusDto {
    /// Builds the contract shape from the daemon's status.
    pub fn from_core(s: CoreStatus, last_event_at: LastEventAt) -> Self {
        Self {
            running: s.running,
            hook_port: s.hook_port,
            wss_addr: s.wss_addr.unwrap_or_default(),
            hosts: s.hosts,
            link_enabled: s.link_enabled,
            cert_expires_at: Some(s.cert_expires_at),
            spki_pin: s.spki_pin,
            hooks_installed: s.hooks_installed,
            effective_ttl_s: s.effective_ttl_s,
            hook_timeout_s: s.hook_timeout_s.unwrap_or(0),
            codex_mode: codex_mode_str(&s.codex_mode),
            sessions: s.sessions,
            devices_online: s.devices_online,
            remote_approval_paused: s.remote_approval_paused,
            last_event_at,
        }
    }
}

/// `pairing_start` result. The QR content (which holds the pairing secret) is only ever rendered into the SVG.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PairingStartDto {
    /// `p_...`.
    pub pairing_id: String,
    /// SVG markup.
    pub qr_svg: String,
    /// Expiry (RFC 3339).
    pub expires_at: String,
}

impl PairingStartDto {
    /// Copies the three public fields and drops the payload / URI.
    pub fn from_core(p: &PairingStarted) -> Self {
        Self {
            pairing_id: p.pairing_id.clone(),
            qr_svg: p.qr_svg.clone(),
            expires_at: p.expires_at.clone(),
        }
    }
}

/// A device row (`devices_list`, `daemon-event` `device`). No public key, no hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeviceDto {
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

impl From<DeviceSummary> for DeviceDto {
    fn from(d: DeviceSummary) -> Self {
        Self {
            device_id: d.device_id,
            name: d.name,
            platform: d.platform,
            model: d.model,
            paired_at: d.paired_at,
            last_seen_at: d.last_seen_at,
            online: d.online,
            revoked_at: d.revoked_at,
        }
    }
}

/// `hooks_install` / `hooks_uninstall` / `hooks_status` result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HooksStatusDto {
    /// Installed now.
    pub installed: bool,
    /// Settings file (Claude) or hooks file (Codex).
    pub path: Option<String>,
    /// Korean warnings / instructions.
    pub warnings: Vec<String>,
    /// Codex: the `hooks.json` draft built by the daemon from the real hook program path and the current TTL.
    pub codex_draft: Option<String>,
    /// Codex: the `doctor` command line with the real hook program path.
    pub doctor_command: Option<String>,
}

impl From<HooksReport> for HooksStatusDto {
    fn from(r: HooksReport) -> Self {
        Self {
            installed: r.installed,
            path: (!r.path.is_empty()).then_some(r.path),
            warnings: r.warnings,
            codex_draft: r.codex_draft,
            doctor_command: r.doctor_command,
        }
    }
}

/// `codex_probe` result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CodexProbeDto {
    /// The Codex control socket path, if known.
    pub socket_path: Option<String>,
    /// The socket exists.
    pub reachable: bool,
    /// `userAgent` from the app-server handshake (not collected: UNVERIFIED, Phase 0 C1).
    pub user_agent: Option<String>,
    /// Threads seen (not collected, see above).
    pub threads: u32,
}

/// `firewall_rule_create` / `_remove` result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FirewallResultDto {
    /// The change was made.
    pub ok: bool,
    /// An elevated process ran.
    pub elevated: bool,
    /// Short English reason on failure (never daemon text, never a path).
    pub error: Option<String>,
}

/// One `approvals_history` row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HistoryEntry {
    /// Request id.
    pub request_id: String,
    /// Card title.
    pub title: String,
    /// Tool name.
    pub tool_name: String,
    /// Risk level.
    pub risk_level: String,
    /// Outcome.
    pub outcome: String,
    /// Who resolved it.
    pub resolved_by: String,
    /// The deciding phone's name.
    pub resolved_device_name: Option<String>,
    /// Resolution time (expiry time for requests that expired without a decision).
    pub resolved_at: String,
}

/// An `ApprovalRequest` as the UI reads it: the card without `nonce_b64` plus `delivery`.
pub fn approval_pending_value(
    card: &ApprovalRequest,
    sent_to: &[String],
    acked: bool,
    seen: bool,
) -> Value {
    let mut v = serde_json::to_value(card).unwrap_or(Value::Null);
    if let Value::Object(m) = &mut v {
        // the nonce is a secret type (security.md 8.1): the UI never receives it
        m.remove("nonce_b64");
        m.insert(
            "delivery".to_owned(),
            json!({"sent_to": sent_to, "acked": acked, "seen": seen}),
        );
    }
    v
}

/// [`approval_pending_value`] for a broker overview row.
pub fn pending_overview_value(o: &PendingOverview) -> Value {
    approval_pending_value(&o.card, &o.sent_to, o.acked, o.seen)
}

/// An `AgentEvent` as the UI reads it. The bounded `detail` object is dropped (the UI never needs it).
pub fn agent_event_value(e: &AgentEvent) -> Value {
    let mut v = serde_json::to_value(e).unwrap_or(Value::Null);
    if let Value::Object(m) = &mut v {
        m.remove("detail");
        // the guard needs a number; the pipeline always assigns one before the event is published
        m.entry("seq").or_insert_with(|| json!(0));
    }
    v
}

/// Removes every key named `nonce_b64` anywhere in `v` (defence in depth for payloads built from wire types).
pub fn strip_nonce(v: &mut Value) {
    match v {
        Value::Object(m) => {
            m.remove("nonce_b64");
            for x in m.values_mut() {
                strip_nonce(x);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(strip_nonce),
        _ => {}
    }
}

/// A JSON object builder for the small payloads below.
pub fn object(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(k.to_owned(), v);
    }
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core_status() -> CoreStatus {
        CoreStatus {
            running: true,
            hook_port: 47831,
            wss_addr: Some("192.168.0.10:47832".into()),
            hosts: vec!["192.168.0.10".into()],
            link_enabled: true,
            cert_expires_at: "2028-10-15T00:00:00+00:00".into(),
            spki_pin: "sha256/AAAA".into(),
            hooks_installed: true,
            effective_ttl_s: 120,
            hook_timeout_s: Some(150),
            hook_port_mismatch: false,
            codex_mode: "hooks".into(),
            sessions: 2,
            devices_online: 1,
            pending_approvals: 3,
            risk_r1_accepted: true,
            remote_approval_paused: false,
            pairing_active: false,
        }
    }

    #[test]
    fn daemon_status_has_exactly_the_contract_fields() {
        let dto = DaemonStatusDto::from_core(core_status(), LastEventAt::default());
        let v = serde_json::to_value(&dto).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut want = vec![
            "running",
            "hook_port",
            "wss_addr",
            "hosts",
            "link_enabled",
            "cert_expires_at",
            "spki_pin",
            "hooks_installed",
            "effective_ttl_s",
            "hook_timeout_s",
            "codex_mode",
            "sessions",
            "devices_online",
            "remote_approval_paused",
            "last_event_at",
        ];
        want.sort_unstable();
        assert_eq!(keys, want);
        assert_eq!(
            v["last_event_at"],
            json!({"claude_code": null, "codex": null})
        );
    }

    #[test]
    fn missing_listener_and_hooks_become_empty_values_the_guard_accepts() {
        let mut s = core_status();
        s.wss_addr = None;
        s.hook_timeout_s = None;
        let v =
            serde_json::to_value(DaemonStatusDto::from_core(s, LastEventAt::default())).unwrap();
        assert_eq!(v["wss_addr"], "");
        assert_eq!(v["hook_timeout_s"], 0);
    }

    #[test]
    fn codex_mode_spellings_are_normalised() {
        assert_eq!(codex_mode_str("hooks"), "hooks");
        assert_eq!(codex_mode_str("daemonobserver"), "daemon_observer");
        assert_eq!(codex_mode_str("daemon_observer"), "daemon_observer");
        assert_eq!(codex_mode_str("off"), "off");
        assert_eq!(codex_mode_str("???"), "off");
    }

    #[test]
    fn hooks_status_path_is_null_when_empty() {
        let r = HooksReport {
            installed: false,
            path: String::new(),
            warnings: vec!["w".into()],
            hook_timeout_s: None,
            codex_draft: Some("{}".into()),
            doctor_command: Some("\"C:\\a b\\agentnest-hook.exe\" doctor".into()),
        };
        let v = serde_json::to_value(HooksStatusDto::from(r)).unwrap();
        assert_eq!(
            v,
            json!({
                "installed": false,
                "path": null,
                "warnings": ["w"],
                "codex_draft": "{}",
                "doctor_command": "\"C:\\a b\\agentnest-hook.exe\" doctor"
            })
        );
    }

    #[test]
    fn strip_nonce_removes_nested_keys() {
        let mut v = json!({"a": {"nonce_b64": "x", "b": [{"nonce_b64": "y", "c": 1}]}});
        strip_nonce(&mut v);
        assert_eq!(v, json!({"a": {"b": [{"c": 1}]}}));
    }
}
