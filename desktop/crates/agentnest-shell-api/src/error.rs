//! The error shape of every Tauri command: `{ "code": "UPPER_SNAKE", "message"?: string }` (docs/desktop.md 3.1).
//!
//! The UI turns the `code` into Korean text and never shows `message`, so `message` is a short fixed English phrase for
//! logs and never contains daemon-provided text (paths, device names, tokens).

use agentnest_core::daemon::CommandError;
use agentnest_protocol::DecisionResultReason;
use serde::Serialize;

/// Stable error codes of the front-end contract (`src/api/errors.ts`).
pub mod code {
    /// The request id does not exist.
    pub const UNKNOWN_REQUEST: &str = "UNKNOWN_REQUEST";
    /// The request is already resolved.
    pub const ALREADY_RESOLVED: &str = "ALREADY_RESOLVED";
    /// The echoed `tool_input_sha256` differs from the stored one.
    pub const INPUT_HASH_MISMATCH: &str = "INPUT_HASH_MISMATCH";
    /// The request expired.
    pub const EXPIRED: &str = "EXPIRED";
    /// The decision is not offered by the request.
    pub const NOT_ALLOWED: &str = "NOT_ALLOWED";
    /// `high` / `critical` allow without `confirm_ack`.
    pub const EXTRA_CONFIRMATION_REQUIRED: &str = "EXTRA_CONFIRMATION_REQUIRED";
    /// Risk R1 has not been accepted.
    pub const RISK_NOT_ACCEPTED: &str = "RISK_NOT_ACCEPTED";
    /// A pairing is already active.
    pub const PAIRING_BUSY: &str = "PAIRING_BUSY";
    /// No such pairing.
    pub const PAIRING_NOT_FOUND: &str = "PAIRING_NOT_FOUND";
    /// The pairing is not waiting for the PC user.
    pub const PAIRING_NOT_PENDING: &str = "PAIRING_NOT_PENDING";
    /// `link.enabled` is false.
    pub const LINK_DISABLED: &str = "LINK_DISABLED";
    /// The typed device name differs.
    pub const NAME_MISMATCH: &str = "NAME_MISMATCH";
    /// No such device.
    pub const DEVICE_NOT_FOUND: &str = "DEVICE_NOT_FOUND";
    /// A settings value is out of range.
    pub const INVALID_SETTING: &str = "INVALID_SETTING";
    /// A settings key is not on the whitelist.
    pub const UNKNOWN_SETTING: &str = "UNKNOWN_SETTING";
    /// The UAC prompt was declined.
    pub const ELEVATION_DENIED: &str = "ELEVATION_DENIED";
    /// The daemon does not answer.
    pub const DAEMON_NOT_RUNNING: &str = "DAEMON_NOT_RUNNING";
    /// Anything else.
    pub const INTERNAL: &str = "INTERNAL";

    /// Every code this crate can produce.
    pub const ALL: &[&str] = &[
        UNKNOWN_REQUEST,
        ALREADY_RESOLVED,
        INPUT_HASH_MISMATCH,
        EXPIRED,
        NOT_ALLOWED,
        EXTRA_CONFIRMATION_REQUIRED,
        RISK_NOT_ACCEPTED,
        PAIRING_BUSY,
        PAIRING_NOT_FOUND,
        PAIRING_NOT_PENDING,
        LINK_DISABLED,
        NAME_MISMATCH,
        DEVICE_NOT_FOUND,
        INVALID_SETTING,
        UNKNOWN_SETTING,
        ELEVATION_DENIED,
        DAEMON_NOT_RUNNING,
        INTERNAL,
    ];
}

/// The error a command returns. Serialises as `{"code": "...", "message": "..."}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IpcError {
    /// `UPPER_SNAKE` code (see [`code`]).
    pub code: &'static str,
    /// Short fixed English phrase for logs; never shown by the UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<&'static str>,
}

impl IpcError {
    /// An error with a code and no message.
    pub const fn new(code: &'static str) -> Self {
        Self {
            code,
            message: None,
        }
    }

    /// An error with a code and a fixed phrase.
    pub const fn with_message(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message: Some(message),
        }
    }

    /// `INTERNAL`.
    pub const fn internal() -> Self {
        Self::new(code::INTERNAL)
    }

    /// `INVALID_SETTING`.
    pub const fn invalid_setting() -> Self {
        Self::new(code::INVALID_SETTING)
    }
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}

impl std::error::Error for IpcError {}

/// Which command an error comes from; `NotFound("pairing")` means different things for cancel and confirm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ctx {
    /// Anything without special handling.
    Generic,
    /// `pairing_start`.
    PairingStart,
    /// `pairing_cancel`.
    PairingCancel,
    /// `pairing_confirm`.
    PairingConfirm,
    /// `risk_accept`, `settings_set`: the daemon's `Invalid` means a bad value.
    BadValue,
}

impl IpcError {
    /// Maps a daemon [`CommandError`] (never forwards its text).
    pub fn from_core(e: &CommandError, ctx: Ctx) -> Self {
        match e {
            CommandError::RiskNotAccepted => Self::new(code::RISK_NOT_ACCEPTED),
            CommandError::PairingBusy => Self::new(code::PAIRING_BUSY),
            CommandError::NotFound("pairing") => match ctx {
                Ctx::PairingConfirm => Self::new(code::PAIRING_NOT_PENDING),
                _ => Self::new(code::PAIRING_NOT_FOUND),
            },
            CommandError::NotFound("device") => Self::new(code::DEVICE_NOT_FOUND),
            CommandError::NotFound("approval") => Self::new(code::UNKNOWN_REQUEST),
            CommandError::NotFound(_) => Self::internal(),
            CommandError::NameMismatch => Self::new(code::NAME_MISMATCH),
            CommandError::Invalid(text) => match ctx {
                Ctx::PairingStart if text.contains("link is disabled") => {
                    Self::new(code::LINK_DISABLED)
                }
                Ctx::BadValue => Self::invalid_setting(),
                _ => Self::with_message(code::INTERNAL, "the daemon rejected the request"),
            },
            CommandError::Unavailable => Self::new(code::DAEMON_NOT_RUNNING),
            CommandError::Internal => Self::internal(),
        }
    }

    /// Maps the reason of a refused local decision to a code. A refusal is **always** an error: nothing that is not
    /// `APPLIED` may look like success to the UI (fail-closed). Reasons the desktop path cannot produce map to
    /// `INTERNAL`.
    pub fn from_decision_reason(reason: &DecisionResultReason) -> Self {
        match reason {
            DecisionResultReason::UnknownRequest => Self::new(code::UNKNOWN_REQUEST),
            DecisionResultReason::AlreadyResolved => Self::new(code::ALREADY_RESOLVED),
            DecisionResultReason::InputHashMismatch => Self::new(code::INPUT_HASH_MISMATCH),
            DecisionResultReason::Expired => Self::new(code::EXPIRED),
            DecisionResultReason::NotAllowed => Self::new(code::NOT_ALLOWED),
            DecisionResultReason::ExtraConfirmationRequired => {
                Self::new(code::EXTRA_CONFIRMATION_REQUIRED)
            }
            _ => Self::internal(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialises_as_code_and_optional_message() {
        let v = serde_json::to_value(IpcError::new(code::EXPIRED)).unwrap();
        assert_eq!(v, serde_json::json!({"code": "EXPIRED"}));
        let v = serde_json::to_value(IpcError::with_message(code::INTERNAL, "x")).unwrap();
        assert_eq!(v, serde_json::json!({"code": "INTERNAL", "message": "x"}));
    }

    #[test]
    fn every_code_is_upper_snake() {
        for c in code::ALL {
            assert!(c
                .chars()
                .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_'));
        }
    }

    #[test]
    fn core_errors_map_per_context() {
        let nf = CommandError::NotFound("pairing");
        assert_eq!(
            IpcError::from_core(&nf, Ctx::PairingConfirm).code,
            code::PAIRING_NOT_PENDING
        );
        assert_eq!(
            IpcError::from_core(&nf, Ctx::PairingCancel).code,
            code::PAIRING_NOT_FOUND
        );
        assert_eq!(
            IpcError::from_core(&CommandError::NotFound("device"), Ctx::Generic).code,
            code::DEVICE_NOT_FOUND
        );
        assert_eq!(
            IpcError::from_core(&CommandError::NotFound("approval"), Ctx::Generic).code,
            code::UNKNOWN_REQUEST
        );
        assert_eq!(
            IpcError::from_core(&CommandError::RiskNotAccepted, Ctx::PairingStart).code,
            code::RISK_NOT_ACCEPTED
        );
        assert_eq!(
            IpcError::from_core(&CommandError::PairingBusy, Ctx::PairingStart).code,
            code::PAIRING_BUSY
        );
        assert_eq!(
            IpcError::from_core(&CommandError::NameMismatch, Ctx::Generic).code,
            code::NAME_MISMATCH
        );
        assert_eq!(
            IpcError::from_core(&CommandError::Unavailable, Ctx::Generic).code,
            code::DAEMON_NOT_RUNNING
        );
        assert_eq!(
            IpcError::from_core(&CommandError::Internal, Ctx::Generic).code,
            code::INTERNAL
        );
    }

    #[test]
    fn invalid_depends_on_the_command_and_never_forwards_text() {
        let disabled = CommandError::Invalid("the link is disabled".to_owned());
        assert_eq!(
            IpcError::from_core(&disabled, Ctx::PairingStart).code,
            code::LINK_DISABLED
        );
        let secret = CommandError::Invalid("C:\\Users\\kim\\secret.txt".to_owned());
        let e = IpcError::from_core(&secret, Ctx::Generic);
        assert_eq!(e.code, code::INTERNAL);
        assert!(!format!("{e:?}").contains("secret"));
        assert_eq!(
            IpcError::from_core(&secret, Ctx::BadValue).code,
            code::INVALID_SETTING
        );
    }

    #[test]
    fn refused_decisions_are_always_errors() {
        use DecisionResultReason as R;
        assert_eq!(
            IpcError::from_decision_reason(&R::UnknownRequest).code,
            code::UNKNOWN_REQUEST
        );
        assert_eq!(
            IpcError::from_decision_reason(&R::AlreadyResolved).code,
            code::ALREADY_RESOLVED
        );
        assert_eq!(
            IpcError::from_decision_reason(&R::InputHashMismatch).code,
            code::INPUT_HASH_MISMATCH
        );
        assert_eq!(
            IpcError::from_decision_reason(&R::Expired).code,
            code::EXPIRED
        );
        assert_eq!(
            IpcError::from_decision_reason(&R::NotAllowed).code,
            code::NOT_ALLOWED
        );
        assert_eq!(
            IpcError::from_decision_reason(&R::ExtraConfirmationRequired).code,
            code::EXTRA_CONFIRMATION_REQUIRED
        );
        // even a reason that means "applied" must not turn a refusal into success
        assert_eq!(
            IpcError::from_decision_reason(&R::Applied).code,
            code::INTERNAL
        );
        assert_eq!(
            IpcError::from_decision_reason(&R::AuthRequired).code,
            code::INTERNAL
        );
        assert_eq!(
            IpcError::from_decision_reason(&R::Unknown("X".into())).code,
            code::INTERNAL
        );
    }
}
