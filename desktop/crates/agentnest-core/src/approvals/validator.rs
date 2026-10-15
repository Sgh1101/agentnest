//! The decision validator: the nine ordered checks of docs/security.md 6.2 and the desktop table of 6.2.1.
//!
//! [`validate`] is a **pure function**: it looks at the stored request, the current time and the decision, and it
//! changes nothing. The broker calls it *before* any state change; one failing step means "nothing happens"
//! (the request stays pending, the attempt is only recorded). The checks run in this fixed order and the first failure
//! decides the reason:
//!
//! | # | check | reason |
//! | --- | --- | --- |
//! | 1 | the decision came from an authenticated, not revoked device connection (phone only) | `DEVICE_REVOKED` |
//! | 2 | the `request_id` exists | `UNKNOWN_REQUEST` |
//! | 3 | the request is still `pending` | `ALREADY_RESOLVED` |
//! | 4 | `session_key` and `nonce` match (phone only; constant time) | `BINDING_MISMATCH` |
//! | 5 | `tool_input_sha256` matches (the desktop echoes the hash of the card it showed) | `INPUT_HASH_MISMATCH` |
//! | 6 | server clock `now < expires_at` (plus, for the phone, the `decided_at` window) | `EXPIRED` / `CLOCK_SKEW` |
//! | 7 | `decision ∈ allowed_decisions` | `NOT_ALLOWED` |
//! | 8 | authentication and freshness (phone) / `confirm_ack` (desktop); extra confirmation for allow-type decisions | `AUTH_REQUIRED` / `CLOCK_SKEW` / `EXTRA_CONFIRMATION_REQUIRED` |
//! | 9 | remote approval is not paused (phone only) | `PAUSED` |
//!
//! Step 8 follows the lead decision: `risk.extra_confirmation` (hold / hold_and_reconfirm) is required **only for
//! decisions in `auth_required_for`** that are not a plain `deny`. A plain `deny` never needs an extra confirmation,
//! whatever the risk; the `deny_requires_auth` policy only adds the authentication (and its freshness) to it. The
//! authentication claims remain claims of the phone until Phase 3 signatures (security.md 6.4).

use agentnest_protocol::canonical::ct_eq;
use agentnest_protocol::qr::b64_decode;
use agentnest_protocol::{
    Decision, DecisionAuth, DecisionResultReason, ExtraConfirmation, ExtraConfirmationProof, Secret,
};

use crate::state::timers::parse_ms;

/// Where a decision came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecisionSource {
    /// A phone, through its authenticated connection.
    Phone {
        /// The authenticated device.
        device_id: String,
    },
    /// The desktop UI of the PC user (Tauri command `approval_decide_local`).
    Desktop,
}

impl DecisionSource {
    /// `device:<id>` / `desktop` (the `decisions.actor` spelling).
    pub fn actor(&self) -> String {
        match self {
            DecisionSource::Phone { device_id } => format!("device:{device_id}"),
            DecisionSource::Desktop => "desktop".to_owned(),
        }
    }

    /// `phone:<id>` / `desktop` (the `approval_audit.actor` spelling).
    pub fn audit_actor(&self) -> String {
        match self {
            DecisionSource::Phone { device_id } => format!("phone:{device_id}"),
            DecisionSource::Desktop => "desktop".to_owned(),
        }
    }

    /// `phone` / `desktop` (`approvals.resolved_by`).
    pub fn resolved_by(&self) -> &'static str {
        match self {
            DecisionSource::Phone { .. } => "phone",
            DecisionSource::Desktop => "desktop",
        }
    }
}

/// A decision as the broker receives it. Phone-only fields are `None` for desktop decisions and vice versa.
#[derive(Clone)]
pub struct DecisionInput {
    /// Who decided.
    pub source: DecisionSource,
    /// The `decision` envelope id (phone) or a generated id (desktop); the idempotency key.
    pub decision_id: String,
    /// The request.
    pub request_id: String,
    /// Phone binding: session key echo.
    pub session_key: Option<String>,
    /// Phone binding: nonce echo (base64).
    pub nonce_b64: Option<Secret>,
    /// Binding: input hash echo (phone) / hash of the card the user saw (desktop).
    pub tool_input_sha256: String,
    /// The decision.
    pub decision: Decision,
    /// Deny reason typed by the user (sanitised by the broker).
    pub reason: Option<String>,
    /// Phone time of the decision (RFC 3339), phone only.
    pub decided_at: Option<String>,
    /// Authentication claim, phone only.
    pub auth: Option<DecisionAuth>,
    /// Extra confirmation claim, phone only.
    pub extra_confirmation: Option<ExtraConfirmationProof>,
    /// The desktop UI completed its extra confirmation (hold / re-display + checkbox), desktop only.
    pub confirm_ack: bool,
}

impl std::fmt::Debug for DecisionInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecisionInput")
            .field("source", &self.source)
            .field("request_id", &self.request_id)
            .field("decision", &self.decision)
            .finish_non_exhaustive()
    }
}

/// What the validator needs to know about a stored request.
#[derive(Clone, Debug)]
pub struct CardView<'a> {
    /// Bound session.
    pub session_key: &'a str,
    /// Raw 16-byte nonce.
    pub nonce: &'a [u8],
    /// Lower-case hex SHA-256 of the canonical tool input.
    pub tool_input_sha256_hex: &'a str,
    /// Creation time (server clock, Unix ms).
    pub created_ms: i64,
    /// Expiry (server clock, Unix ms).
    pub expires_ms: i64,
    /// Decisions the phone may send.
    pub allowed: &'a [Decision],
    /// Decisions that need strong authentication.
    pub auth_required_for: &'a [Decision],
    /// Required extra confirmation for allow-type decisions.
    pub extra_confirmation: ExtraConfirmation,
}

/// What the store says about the request id.
#[derive(Clone, Debug)]
pub enum RequestStatus<'a> {
    /// No such request (step 2).
    Unknown,
    /// Exists but is no longer pending (step 3).
    NotPending,
    /// Pending, with its card.
    Pending(CardView<'a>),
}

/// The situation around the decision.
#[derive(Clone, Copy, Debug)]
pub struct ValidationEnv {
    /// Server time, Unix ms. The only clock used for security judgements.
    pub now_ms: i64,
    /// The deciding device is registered and not revoked (checked by the broker against the database).
    pub device_active: bool,
    /// Remote approval is paused on the PC.
    pub paused: bool,
}

/// A refused decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    /// Reason code (`decision_result.reason`).
    pub reason: DecisionResultReason,
    /// The request has to be moved to `expired` as part of the rejection (step 6 expiry).
    pub expire_request: bool,
    /// Worth a security warning in the log (binding mismatch).
    pub warn: bool,
}

impl Rejection {
    fn of(reason: DecisionResultReason) -> Self {
        Self {
            reason,
            expire_request: false,
            warn: false,
        }
    }
}

/// Window of `decided_at` around the server clock (security.md 6.2 step 6): `created_at - 60 s .. now + 60 s`.
pub const DECIDED_AT_SLACK_MS: i64 = 60_000;
/// Tolerance of `authenticated_at` before `created_at` / after `decided_at` (step 8).
pub const AUTH_CLOCK_TOLERANCE_MS: i64 = 5_000;
/// Maximum age of the authentication at decision time (step 8).
pub const AUTH_MAX_AGE_MS: i64 = 60_000;

/// `true` if `decision` needs strong authentication on this card. Allow-type decisions always do (fail closed even if
/// a card claims otherwise); a plain deny only if the card says so (`deny_requires_auth`).
fn requires_auth(card: &CardView<'_>, decision: Decision) -> bool {
    decision != Decision::Deny || card.auth_required_for.contains(&decision)
}

/// Runs the ordered checks. `Ok(())` means every applicable step passed; nothing has been changed.
pub fn validate(
    env: &ValidationEnv,
    status: &RequestStatus<'_>,
    input: &DecisionInput,
) -> Result<(), Rejection> {
    let phone = matches!(input.source, DecisionSource::Phone { .. });

    // 1. an authenticated, not revoked device (the desktop has no device: IPC is limited to the main window)
    if phone && !env.device_active {
        return Err(Rejection::of(DecisionResultReason::DeviceRevoked));
    }
    // 2. the request exists
    let card = match status {
        RequestStatus::Unknown => return Err(Rejection::of(DecisionResultReason::UnknownRequest)),
        // 3. still pending
        RequestStatus::NotPending => {
            return Err(Rejection::of(DecisionResultReason::AlreadyResolved))
        }
        RequestStatus::Pending(card) => card,
    };
    // 4. session_key and nonce (remote replay protection; the desktop looks the request up by id itself)
    if phone {
        let session_ok = input
            .session_key
            .as_deref()
            .is_some_and(|k| ct_eq(k.as_bytes(), card.session_key.as_bytes()));
        let nonce_ok = input
            .nonce_b64
            .as_ref()
            .and_then(|n| b64_decode(n.expose()).ok())
            .is_some_and(|n| ct_eq(&n, card.nonce));
        // both are always evaluated: no short circuit on the secret comparison
        if !(session_ok & nonce_ok) {
            let mut r = Rejection::of(DecisionResultReason::BindingMismatch);
            r.warn = true;
            return Err(r);
        }
    }
    // 5. the input hash (for the desktop: the hash of the card the user saw)
    if !ct_eq(
        input.tool_input_sha256.as_bytes(),
        card.tool_input_sha256_hex.as_bytes(),
    ) {
        return Err(Rejection::of(DecisionResultReason::InputHashMismatch));
    }
    // 6. expiry on the server clock, then the phone's decided_at window
    if env.now_ms >= card.expires_ms {
        return Err(Rejection {
            reason: DecisionResultReason::Expired,
            expire_request: true,
            warn: false,
        });
    }
    let decided_ms = if phone {
        let decided = input.decided_at.as_deref().and_then(parse_ms);
        match decided {
            Some(d)
                if d >= card.created_ms - DECIDED_AT_SLACK_MS
                    && d <= env.now_ms + DECIDED_AT_SLACK_MS =>
            {
                Some(d)
            }
            _ => return Err(Rejection::of(DecisionResultReason::ClockSkew)),
        }
    } else {
        None
    };
    // 7. the decision is offered by this request
    if !card.allowed.contains(&input.decision) {
        return Err(Rejection::of(DecisionResultReason::NotAllowed));
    }
    // 8. authentication + freshness (phone) / confirm_ack (desktop), extra confirmation for allow-type decisions
    if phone {
        if requires_auth(card, input.decision) {
            let Some(auth) = input.auth.as_ref().filter(|a| a.method.is_strong()) else {
                return Err(Rejection::of(DecisionResultReason::AuthRequired));
            };
            let Some(authenticated_ms) = auth.authenticated_at.as_deref().and_then(parse_ms) else {
                return Err(Rejection::of(DecisionResultReason::AuthRequired));
            };
            let decided = decided_ms.unwrap_or(env.now_ms);
            if authenticated_ms < card.created_ms - AUTH_CLOCK_TOLERANCE_MS
                || authenticated_ms > decided + AUTH_CLOCK_TOLERANCE_MS
            {
                return Err(Rejection::of(DecisionResultReason::ClockSkew));
            }
            if decided - authenticated_ms > AUTH_MAX_AGE_MS {
                return Err(Rejection::of(DecisionResultReason::AuthRequired));
            }
            if input.decision != Decision::Deny
                && card.extra_confirmation != ExtraConfirmation::None
            {
                let required = card.extra_confirmation.strength();
                let done = input
                    .extra_confirmation
                    .as_ref()
                    .is_some_and(|e| e.completed && e.method.strength() >= required);
                if !done {
                    return Err(Rejection::of(
                        DecisionResultReason::ExtraConfirmationRequired,
                    ));
                }
            }
        }
    } else if input.decision != Decision::Deny
        && card.extra_confirmation != ExtraConfirmation::None
        && !input.confirm_ack
    {
        return Err(Rejection::of(
            DecisionResultReason::ExtraConfirmationRequired,
        ));
    }
    // 9. remote approval paused: blocks the remote channel only; the desktop is unaffected
    if phone && env.paused {
        return Err(Rejection::of(DecisionResultReason::Paused));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentnest_protocol::qr::b64_encode;
    use agentnest_protocol::{AuthMethod, ExtraConfirmationMethod};

    const CREATED: i64 = 1_792_055_553_000;
    const NOW: i64 = CREATED + 20_000;
    const EXPIRES: i64 = CREATED + 120_000;
    const NONCE: [u8; 16] = [7; 16];
    const HASH: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    fn ts(ms: i64) -> String {
        crate::state::timers::format_ms(ms)
    }

    fn card<'a>(
        allowed: &'a [Decision],
        auth_required: &'a [Decision],
        extra: ExtraConfirmation,
    ) -> CardView<'a> {
        CardView {
            session_key: "claude_code:s1",
            nonce: &NONCE,
            tool_input_sha256_hex: HASH,
            created_ms: CREATED,
            expires_ms: EXPIRES,
            allowed,
            auth_required_for: auth_required,
            extra_confirmation: extra,
        }
    }

    const ALL: [Decision; 3] = [Decision::Allow, Decision::Deny, Decision::DenyAndStop];
    const AUTH_DEFAULT: [Decision; 2] = [Decision::Allow, Decision::DenyAndStop];

    fn env() -> ValidationEnv {
        ValidationEnv {
            now_ms: NOW,
            device_active: true,
            paused: false,
        }
    }

    fn phone(decision: Decision) -> DecisionInput {
        DecisionInput {
            source: DecisionSource::Phone {
                device_id: "dev_a".into(),
            },
            decision_id: "d1".into(),
            request_id: "ar_1".into(),
            session_key: Some("claude_code:s1".into()),
            nonce_b64: Some(Secret::new(b64_encode(&NONCE))),
            tool_input_sha256: HASH.into(),
            decision,
            reason: None,
            decided_at: Some(ts(NOW - 500)),
            auth: Some(DecisionAuth {
                method: AuthMethod::Biometric,
                authenticated_at: Some(ts(NOW - 1_000)),
            }),
            extra_confirmation: None,
            confirm_ack: false,
        }
    }

    fn desktop(decision: Decision, ack: bool) -> DecisionInput {
        DecisionInput {
            source: DecisionSource::Desktop,
            decision_id: "desktop-1".into(),
            request_id: "ar_1".into(),
            session_key: None,
            nonce_b64: None,
            tool_input_sha256: HASH.into(),
            decision,
            reason: None,
            decided_at: None,
            auth: None,
            extra_confirmation: None,
            confirm_ack: ack,
        }
    }

    fn reason(r: Result<(), Rejection>) -> DecisionResultReason {
        r.unwrap_err().reason
    }

    #[test]
    fn all_nine_steps_pass_for_a_valid_allow() {
        let c = card(&ALL, &AUTH_DEFAULT, ExtraConfirmation::None);
        validate(&env(), &RequestStatus::Pending(c), &phone(Decision::Allow)).unwrap();
        let c = card(&ALL, &AUTH_DEFAULT, ExtraConfirmation::None);
        validate(&env(), &RequestStatus::Pending(c), &phone(Decision::Deny)).unwrap();
    }

    // one test per step: it fails *only* that step

    #[test]
    fn step1_revoked_or_unauthenticated_device() {
        let c = card(&ALL, &AUTH_DEFAULT, ExtraConfirmation::None);
        let mut e = env();
        e.device_active = false;
        assert_eq!(
            reason(validate(
                &e,
                &RequestStatus::Pending(c),
                &phone(Decision::Allow)
            )),
            DecisionResultReason::DeviceRevoked
        );
    }

    #[test]
    fn step2_unknown_request() {
        assert_eq!(
            reason(validate(
                &env(),
                &RequestStatus::Unknown,
                &phone(Decision::Allow)
            )),
            DecisionResultReason::UnknownRequest
        );
    }

    #[test]
    fn step3_not_pending() {
        assert_eq!(
            reason(validate(
                &env(),
                &RequestStatus::NotPending,
                &phone(Decision::Allow)
            )),
            DecisionResultReason::AlreadyResolved
        );
    }

    #[test]
    fn step4_session_key_or_nonce_mismatch() {
        let c = card(&ALL, &AUTH_DEFAULT, ExtraConfirmation::None);
        let mut d = phone(Decision::Allow);
        d.session_key = Some("claude_code:other".into());
        let r = validate(&env(), &RequestStatus::Pending(c.clone()), &d).unwrap_err();
        assert_eq!(r.reason, DecisionResultReason::BindingMismatch);
        assert!(r.warn, "a binding mismatch is logged as a security warning");
        let mut d = phone(Decision::Allow);
        d.nonce_b64 = Some(Secret::new(b64_encode(&[8u8; 16])));
        assert_eq!(
            reason(validate(&env(), &RequestStatus::Pending(c.clone()), &d)),
            DecisionResultReason::BindingMismatch
        );
        for bad in [None, Some(Secret::new("%%%")), Some(Secret::new(""))] {
            let mut d = phone(Decision::Allow);
            d.nonce_b64 = bad;
            assert_eq!(
                reason(validate(&env(), &RequestStatus::Pending(c.clone()), &d)),
                DecisionResultReason::BindingMismatch
            );
        }
        let mut d = phone(Decision::Allow);
        d.session_key = None;
        assert_eq!(
            reason(validate(&env(), &RequestStatus::Pending(c), &d)),
            DecisionResultReason::BindingMismatch
        );
    }

    #[test]
    fn step5_input_hash_mismatch() {
        let c = card(&ALL, &AUTH_DEFAULT, ExtraConfirmation::None);
        let mut d = phone(Decision::Allow);
        d.tool_input_sha256 = HASH.replace('9', "8");
        assert_eq!(
            reason(validate(&env(), &RequestStatus::Pending(c.clone()), &d)),
            DecisionResultReason::InputHashMismatch
        );
        let mut d = phone(Decision::Allow);
        d.tool_input_sha256 = HASH.to_uppercase();
        assert_eq!(
            reason(validate(&env(), &RequestStatus::Pending(c), &d)),
            DecisionResultReason::InputHashMismatch,
            "the hash must match exactly (lower-case hex)"
        );
    }

    #[test]
    fn step6_expiry_boundary_and_decided_at_window() {
        let c = card(&ALL, &AUTH_DEFAULT, ExtraConfirmation::None);
        // exactly at expires_at is expired (now < expires_at is required)
        let mut e = env();
        e.now_ms = EXPIRES;
        let r = validate(
            &e,
            &RequestStatus::Pending(c.clone()),
            &phone(Decision::Allow),
        )
        .unwrap_err();
        assert_eq!(r.reason, DecisionResultReason::Expired);
        assert!(r.expire_request);
        e.now_ms = EXPIRES - 1;
        let mut d = phone(Decision::Allow);
        d.decided_at = Some(ts(EXPIRES - 2));
        d.auth = Some(DecisionAuth {
            method: AuthMethod::Biometric,
            authenticated_at: Some(ts(EXPIRES - 5)),
        });
        validate(&e, &RequestStatus::Pending(c.clone()), &d).unwrap();
        // decided_at too early / too late / missing / garbage
        for bad in [
            Some(ts(CREATED - 60_001)),
            Some(ts(NOW + 60_001)),
            None,
            Some("yesterday".to_owned()),
        ] {
            let mut d = phone(Decision::Allow);
            d.decided_at = bad;
            assert_eq!(
                reason(validate(&env(), &RequestStatus::Pending(c.clone()), &d)),
                DecisionResultReason::ClockSkew
            );
        }
        // the window edges are inclusive
        for ok in [CREATED - 60_000, NOW + 60_000] {
            let mut d = phone(Decision::Deny);
            d.decided_at = Some(ts(ok));
            validate(&env(), &RequestStatus::Pending(c.clone()), &d).unwrap();
        }
        // the desktop has no decided_at window: only the expiry applies
        validate(
            &env(),
            &RequestStatus::Pending(c),
            &desktop(Decision::Allow, true),
        )
        .unwrap();
    }

    #[test]
    fn step7_decision_must_be_allowed() {
        let allowed = [Decision::Allow, Decision::Deny];
        let c = card(&allowed, &AUTH_DEFAULT, ExtraConfirmation::None);
        assert_eq!(
            reason(validate(
                &env(),
                &RequestStatus::Pending(c),
                &phone(Decision::DenyAndStop)
            )),
            DecisionResultReason::NotAllowed
        );
        let only_deny = [Decision::Deny];
        let c = card(&only_deny, &AUTH_DEFAULT, ExtraConfirmation::None);
        assert_eq!(
            reason(validate(
                &env(),
                &RequestStatus::Pending(c),
                &phone(Decision::Allow)
            )),
            DecisionResultReason::NotAllowed
        );
    }

    #[test]
    fn step8_authentication_and_freshness() {
        let c = card(&ALL, &AUTH_DEFAULT, ExtraConfirmation::None);
        let run = |mutate: &dyn Fn(&mut DecisionInput)| {
            let mut d = phone(Decision::Allow);
            mutate(&mut d);
            reason(validate(&env(), &RequestStatus::Pending(c.clone()), &d))
        };
        assert_eq!(run(&|d| d.auth = None), DecisionResultReason::AuthRequired);
        assert_eq!(
            run(&|d| d.auth = Some(DecisionAuth {
                method: AuthMethod::None,
                authenticated_at: Some(ts(NOW))
            })),
            DecisionResultReason::AuthRequired
        );
        assert_eq!(
            run(&|d| d.auth = Some(DecisionAuth {
                method: AuthMethod::Biometric,
                authenticated_at: None
            })),
            DecisionResultReason::AuthRequired
        );
        assert_eq!(
            run(&|d| d.auth = Some(DecisionAuth {
                method: AuthMethod::Biometric,
                authenticated_at: Some("x".into())
            })),
            DecisionResultReason::AuthRequired
        );
        // device credential is as good as biometrics
        assert!(run_ok(&c, |d| d.auth = Some(DecisionAuth {
            method: AuthMethod::DeviceCredential,
            authenticated_at: Some(ts(NOW - 100))
        })));
        // authentication from before the request existed (reuse): CLOCK_SKEW
        assert_eq!(
            run(&|d| d.auth = Some(DecisionAuth {
                method: AuthMethod::Biometric,
                authenticated_at: Some(ts(CREATED - 5_001))
            })),
            DecisionResultReason::ClockSkew
        );
        // 5 s before the request is tolerated
        assert!(run_ok(&c, |d| d.auth = Some(DecisionAuth {
            method: AuthMethod::Biometric,
            authenticated_at: Some(ts(CREATED - 5_000))
        })));
        // authentication in the future relative to decided_at
        assert_eq!(
            run(&|d| d.auth = Some(DecisionAuth {
                method: AuthMethod::Biometric,
                authenticated_at: Some(ts(NOW - 500 + 5_001))
            })),
            DecisionResultReason::ClockSkew
        );
        // older than 60 s at decision time: re-authenticate. (decided_at = NOW-500; created = NOW-20s so a 61 s old
        // authentication is also before created-5s -> use a longer-lived request)
        let long = CardView {
            created_ms: NOW - 200_000,
            expires_ms: NOW + 100_000,
            ..c.clone()
        };
        let mut d = phone(Decision::Allow);
        d.decided_at = Some(ts(NOW - 500));
        d.auth = Some(DecisionAuth {
            method: AuthMethod::Biometric,
            authenticated_at: Some(ts(NOW - 500 - 60_001)),
        });
        assert_eq!(
            reason(validate(&env(), &RequestStatus::Pending(long.clone()), &d)),
            DecisionResultReason::AuthRequired
        );
        d.auth = Some(DecisionAuth {
            method: AuthMethod::Biometric,
            authenticated_at: Some(ts(NOW - 500 - 60_000)),
        });
        validate(&env(), &RequestStatus::Pending(long), &d).unwrap();
        // deny_and_stop needs authentication too
        let mut d = phone(Decision::DenyAndStop);
        d.auth = None;
        assert_eq!(
            reason(validate(&env(), &RequestStatus::Pending(c.clone()), &d)),
            DecisionResultReason::AuthRequired
        );
        // a plain deny does not (default policy)
        let mut d = phone(Decision::Deny);
        d.auth = None;
        validate(&env(), &RequestStatus::Pending(c), &d).unwrap();
    }

    fn run_ok(c: &CardView<'_>, mutate: impl Fn(&mut DecisionInput)) -> bool {
        let mut d = phone(Decision::Allow);
        mutate(&mut d);
        validate(&env(), &RequestStatus::Pending(c.clone()), &d).is_ok()
    }

    #[test]
    fn step8_deny_requires_auth_policy_adds_authentication_but_never_extra_confirmation() {
        let auth_all = [Decision::Allow, Decision::Deny, Decision::DenyAndStop];
        let c = card(&ALL, &auth_all, ExtraConfirmation::HoldAndReconfirm);
        let mut d = phone(Decision::Deny);
        d.auth = None;
        assert_eq!(
            reason(validate(&env(), &RequestStatus::Pending(c.clone()), &d)),
            DecisionResultReason::AuthRequired
        );
        // with authentication a deny passes on a critical card without any hold
        let d = phone(Decision::Deny);
        assert!(d.extra_confirmation.is_none());
        validate(&env(), &RequestStatus::Pending(c.clone()), &d).unwrap();
        // stale authentication fails a deny under the policy too
        let long = CardView {
            created_ms: NOW - 200_000,
            expires_ms: NOW + 100_000,
            ..c
        };
        let mut d = phone(Decision::Deny);
        d.auth = Some(DecisionAuth {
            method: AuthMethod::Biometric,
            authenticated_at: Some(ts(NOW - 500 - 61_000)),
        });
        assert_eq!(
            reason(validate(&env(), &RequestStatus::Pending(long), &d)),
            DecisionResultReason::AuthRequired
        );
    }

    #[test]
    fn step8_extra_confirmation_is_required_for_allow_type_decisions_only() {
        for (extra, ok_method, weak_method) in [
            (ExtraConfirmation::Hold, ExtraConfirmationMethod::Hold, None),
            (
                ExtraConfirmation::HoldAndReconfirm,
                ExtraConfirmationMethod::HoldAndReconfirm,
                Some(ExtraConfirmationMethod::Hold),
            ),
        ] {
            let c = card(&ALL, &AUTH_DEFAULT, extra.clone());
            for decision in [Decision::Allow, Decision::DenyAndStop] {
                // missing
                let d = phone(decision);
                assert_eq!(
                    reason(validate(&env(), &RequestStatus::Pending(c.clone()), &d)),
                    DecisionResultReason::ExtraConfirmationRequired,
                    "{decision:?}"
                );
                // not completed
                let mut d = phone(decision);
                d.extra_confirmation = Some(ExtraConfirmationProof {
                    method: ok_method,
                    completed: false,
                });
                assert_eq!(
                    reason(validate(&env(), &RequestStatus::Pending(c.clone()), &d)),
                    DecisionResultReason::ExtraConfirmationRequired
                );
                // weaker than required
                if let Some(weak) = weak_method {
                    let mut d = phone(decision);
                    d.extra_confirmation = Some(ExtraConfirmationProof {
                        method: weak,
                        completed: true,
                    });
                    assert_eq!(
                        reason(validate(&env(), &RequestStatus::Pending(c.clone()), &d)),
                        DecisionResultReason::ExtraConfirmationRequired
                    );
                }
                // sufficient (also stronger than required)
                let mut d = phone(decision);
                d.extra_confirmation = Some(ExtraConfirmationProof {
                    method: ok_method,
                    completed: true,
                });
                validate(&env(), &RequestStatus::Pending(c.clone()), &d).unwrap();
                let mut d = phone(decision);
                d.extra_confirmation = Some(ExtraConfirmationProof {
                    method: ExtraConfirmationMethod::HoldAndReconfirm,
                    completed: true,
                });
                validate(&env(), &RequestStatus::Pending(c.clone()), &d).unwrap();
            }
            // a plain deny never needs it, whatever the risk
            let d = phone(Decision::Deny);
            validate(&env(), &RequestStatus::Pending(c), &d).unwrap();
        }
        // an unknown (future) extra-confirmation requirement counts as the strongest
        let c = card(
            &ALL,
            &AUTH_DEFAULT,
            ExtraConfirmation::Unknown("quadruple".into()),
        );
        let mut d = phone(Decision::Allow);
        d.extra_confirmation = Some(ExtraConfirmationProof {
            method: ExtraConfirmationMethod::Hold,
            completed: true,
        });
        assert_eq!(
            reason(validate(&env(), &RequestStatus::Pending(c), &d)),
            DecisionResultReason::ExtraConfirmationRequired
        );
    }

    #[test]
    fn a_card_that_forgets_auth_required_for_still_protects_allow() {
        // fail closed: allow-type decisions need authentication whatever the card says
        let c = card(&ALL, &[], ExtraConfirmation::None);
        let mut d = phone(Decision::Allow);
        d.auth = None;
        assert_eq!(
            reason(validate(&env(), &RequestStatus::Pending(c.clone()), &d)),
            DecisionResultReason::AuthRequired
        );
        let mut d = phone(Decision::DenyAndStop);
        d.auth = None;
        assert_eq!(
            reason(validate(&env(), &RequestStatus::Pending(c), &d)),
            DecisionResultReason::AuthRequired
        );
    }

    #[test]
    fn step9_paused_blocks_the_phone_only() {
        let c = card(&ALL, &AUTH_DEFAULT, ExtraConfirmation::None);
        let mut e = env();
        e.paused = true;
        assert_eq!(
            reason(validate(
                &e,
                &RequestStatus::Pending(c.clone()),
                &phone(Decision::Allow)
            )),
            DecisionResultReason::Paused
        );
        assert_eq!(
            reason(validate(
                &e,
                &RequestStatus::Pending(c.clone()),
                &phone(Decision::Deny)
            )),
            DecisionResultReason::Paused
        );
        // desktop decisions still apply while remote approval is paused (6.2.1 step 9 not applicable)
        validate(
            &e,
            &RequestStatus::Pending(c),
            &desktop(Decision::Allow, true),
        )
        .unwrap();
    }

    #[test]
    fn steps_run_in_the_documented_order() {
        // a decision that violates every step reports step 1; peel the failures off from the top
        let allowed = [Decision::Deny];
        let c = card(&allowed, &AUTH_DEFAULT, ExtraConfirmation::HoldAndReconfirm);
        let mut e = ValidationEnv {
            now_ms: EXPIRES + 1,
            device_active: false,
            paused: true,
        };
        let mut d = phone(Decision::Allow);
        d.session_key = Some("x".into());
        d.tool_input_sha256 = "0".repeat(64);
        d.decided_at = None;
        d.auth = None;
        assert_eq!(
            reason(validate(&e, &RequestStatus::Unknown, &d)),
            DecisionResultReason::DeviceRevoked
        );
        e.device_active = true;
        assert_eq!(
            reason(validate(&e, &RequestStatus::Unknown, &d)),
            DecisionResultReason::UnknownRequest
        );
        assert_eq!(
            reason(validate(&e, &RequestStatus::NotPending, &d)),
            DecisionResultReason::AlreadyResolved
        );
        assert_eq!(
            reason(validate(&e, &RequestStatus::Pending(c.clone()), &d)),
            DecisionResultReason::BindingMismatch
        );
        d.session_key = Some("claude_code:s1".into());
        assert_eq!(
            reason(validate(&e, &RequestStatus::Pending(c.clone()), &d)),
            DecisionResultReason::InputHashMismatch
        );
        d.tool_input_sha256 = HASH.into();
        assert_eq!(
            reason(validate(&e, &RequestStatus::Pending(c.clone()), &d)),
            DecisionResultReason::Expired
        );
        e.now_ms = NOW;
        assert_eq!(
            reason(validate(&e, &RequestStatus::Pending(c.clone()), &d)),
            DecisionResultReason::ClockSkew
        );
        d.decided_at = Some(ts(NOW));
        assert_eq!(
            reason(validate(&e, &RequestStatus::Pending(c.clone()), &d)),
            DecisionResultReason::NotAllowed
        );
        let all = card(&ALL, &AUTH_DEFAULT, ExtraConfirmation::HoldAndReconfirm);
        assert_eq!(
            reason(validate(&e, &RequestStatus::Pending(all.clone()), &d)),
            DecisionResultReason::AuthRequired
        );
        d.auth = phone(Decision::Allow).auth;
        assert_eq!(
            reason(validate(&e, &RequestStatus::Pending(all.clone()), &d)),
            DecisionResultReason::ExtraConfirmationRequired
        );
        d.extra_confirmation = Some(ExtraConfirmationProof {
            method: ExtraConfirmationMethod::HoldAndReconfirm,
            completed: true,
        });
        assert_eq!(
            reason(validate(&e, &RequestStatus::Pending(all.clone()), &d)),
            DecisionResultReason::Paused
        );
        e.paused = false;
        validate(&e, &RequestStatus::Pending(all), &d).unwrap();
    }

    // ---- desktop path (security.md 6.2.1): every mandatory step fails alone

    #[test]
    fn desktop_mandatory_steps_each_fail_alone() {
        let c = card(&ALL, &AUTH_DEFAULT, ExtraConfirmation::Hold);
        let e = env();
        // 2
        assert_eq!(
            reason(validate(
                &e,
                &RequestStatus::Unknown,
                &desktop(Decision::Allow, true)
            )),
            DecisionResultReason::UnknownRequest
        );
        // 3
        assert_eq!(
            reason(validate(
                &e,
                &RequestStatus::NotPending,
                &desktop(Decision::Allow, true)
            )),
            DecisionResultReason::AlreadyResolved
        );
        // 5: the hash of the card the user saw must equal the stored one
        let mut d = desktop(Decision::Allow, true);
        d.tool_input_sha256 = "0".repeat(64);
        assert_eq!(
            reason(validate(&e, &RequestStatus::Pending(c.clone()), &d)),
            DecisionResultReason::InputHashMismatch
        );
        // 6: only the server clock
        let mut late = e;
        late.now_ms = EXPIRES;
        let r = validate(
            &late,
            &RequestStatus::Pending(c.clone()),
            &desktop(Decision::Allow, true),
        )
        .unwrap_err();
        assert_eq!(r.reason, DecisionResultReason::Expired);
        assert!(r.expire_request);
        // 7
        let only_deny = [Decision::Deny];
        let c7 = card(&only_deny, &AUTH_DEFAULT, ExtraConfirmation::None);
        assert_eq!(
            reason(validate(
                &e,
                &RequestStatus::Pending(c7),
                &desktop(Decision::Allow, true)
            )),
            DecisionResultReason::NotAllowed
        );
        // 8: confirm_ack is required for allow-type decisions on high / critical, not for deny
        for decision in [Decision::Allow, Decision::DenyAndStop] {
            assert_eq!(
                reason(validate(
                    &e,
                    &RequestStatus::Pending(c.clone()),
                    &desktop(decision, false)
                )),
                DecisionResultReason::ExtraConfirmationRequired
            );
            validate(
                &e,
                &RequestStatus::Pending(c.clone()),
                &desktop(decision, true),
            )
            .unwrap();
        }
        validate(
            &e,
            &RequestStatus::Pending(c),
            &desktop(Decision::Deny, false),
        )
        .unwrap();
        // low / medium need no confirmation
        let low = card(&ALL, &AUTH_DEFAULT, ExtraConfirmation::None);
        validate(
            &e,
            &RequestStatus::Pending(low),
            &desktop(Decision::Allow, false),
        )
        .unwrap();
    }

    #[test]
    fn desktop_decisions_need_no_binding_nonce_device_or_biometrics() {
        let c = card(&ALL, &AUTH_DEFAULT, ExtraConfirmation::None);
        let mut e = env();
        e.device_active = false; // not applicable
        let d = desktop(Decision::Allow, false);
        assert!(d.session_key.is_none() && d.nonce_b64.is_none() && d.auth.is_none());
        validate(&e, &RequestStatus::Pending(c), &d).unwrap();
    }

    #[test]
    fn sources_name_themselves_for_the_audit_tables() {
        let p = DecisionSource::Phone {
            device_id: "dev_a".into(),
        };
        assert_eq!(p.actor(), "device:dev_a");
        assert_eq!(p.audit_actor(), "phone:dev_a");
        assert_eq!(p.resolved_by(), "phone");
        assert_eq!(DecisionSource::Desktop.actor(), "desktop");
        assert_eq!(DecisionSource::Desktop.audit_actor(), "desktop");
        assert_eq!(DecisionSource::Desktop.resolved_by(), "desktop");
    }
}
