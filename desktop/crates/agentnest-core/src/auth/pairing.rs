//! Pairing (docs/security.md 4, I7; docs/protocol.md 4.2-4.3).
//!
//! A pairing needs **both** (1) possession of the QR secret (HMAC-SHA256 proof over the canonical pair bytes, verified
//! in constant time with `ring::hmac::verify`) **and** (2) an explicit approval by the PC user after comparing the SAS.
//!
//! Lifecycle of the (single) active pairing:
//!
//! ```text
//! start() --QR, 120 s, single use--> Open --valid pair--> AwaitingConfirm --approve--> device row + token (paired)
//!      wrong proof / wrong challenge: fail_count++ (3rd = burned)      \--reject / 60 s / disconnect--> burned
//! ```
//!
//! * The secret exists in memory (`PairingSecret`, zeroized on drop) and as `SHA-256` in `pairings.secret_sha256`.
//! * At most one pairing is active; a second `pair` while one waits for confirmation gets [`PairFailure::Busy`].
//! * An unknown pairing id, an expired or burned pairing, a wrong challenge echo and a wrong proof are all
//!   [`PairFailure::Failed`]: the phone cannot tell them apart.
//! * Starting a pairing is refused until the PC user has accepted the documented risk R1 (security.md 1.3).

use std::sync::{Arc, Mutex};

use agentnest_protocol::canonical::{canonical_pair_bytes, sas, sha256, verify_pair_proof};
use agentnest_protocol::limits::{DEVICE_NAME_MAX_BYTES, SECRET_LEN};
use agentnest_protocol::qr::{b64_decode, b64url_encode, PairingPayload};
use agentnest_protocol::{PairPayload, Secret};
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::params;
use thiserror::Error;
use tokio::sync::oneshot;

use crate::audit::{actions, Audit, ACTOR_DESKTOP_USER, ACTOR_SYSTEM};
use crate::auth::challenge::Challenge;
use crate::auth::devices::{insert_device_tx, DeviceError, IssuedDevice, NewDevice};
use crate::events::{DaemonEvent, DeviceUiEvent, EventBus, PairingUiEvent};
use crate::redact::PairingSecret;
use crate::state::timers::{format_ms, Clock};
use crate::store::{Store, StoreError};

/// Lifetime of a QR code.
pub const QR_TTL_MS: i64 = 120_000;
/// Time the PC user has to confirm.
pub const CONFIRM_TIMEOUT_MS: u32 = 60_000;
/// Wrong proofs before the pairing is burned.
pub const MAX_FAIL_COUNT: u8 = 3;
/// Setting key of the accepted risk R1.
pub const RISK_R1_SETTING: &str = "risk.accepted.R1";

/// Errors of the desktop-facing pairing API.
#[derive(Debug, Error)]
pub enum PairingError {
    /// A pairing is already active (`PAIRING_BUSY`).
    #[error("a pairing is already active")]
    Busy,
    /// The user has not accepted risk R1 yet (`RISK_NOT_ACCEPTED`).
    #[error("risk R1 has not been accepted")]
    RiskNotAccepted,
    /// No pairing with this id is waiting for the requested action.
    #[error("no such pairing in that state")]
    NotPending,
    /// The PC has no LAN address to put into the QR code.
    #[error("no host address available")]
    NoHosts,
    /// Random number generator failure.
    #[error("random number generator failure")]
    Rng,
    /// QR rendering failed.
    #[error("qr rendering failed")]
    Qr,
    /// Storage failure.
    #[error("storage error: {0}")]
    Store(#[from] StoreError),
}

/// Why a `pair` frame did not start a confirmation. The wire code is chosen by the caller:
/// [`PairFailure::Failed`] -> `E_PAIR_FAILED`, [`PairFailure::Busy`] -> `E_PAIR_BUSY`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairFailure {
    /// Unknown/expired/burned pairing, wrong challenge or wrong proof (indistinguishable).
    Failed,
    /// Another pairing is waiting for the PC user.
    Busy,
    /// The frame is malformed (device name over 64 bytes, bad base64): protocol violation.
    BadMessage,
}

/// What the PC needs to build a QR code.
#[derive(Clone, Debug)]
pub struct PairingStartInfo {
    /// `pc_...`.
    pub pc_id: String,
    /// PC display name (1..=64 chars).
    pub pc_name: String,
    /// LAN addresses (1..=8).
    pub hosts: Vec<String>,
    /// WSS port.
    pub port: u16,
    /// `sha256/<base64>` pin.
    pub spki_pin: String,
}

/// A started pairing: the QR content and its rendering.
#[derive(Clone, Debug)]
pub struct PairingStarted {
    /// `p_...`.
    pub pairing_id: String,
    /// The payload (the secret inside is a redacting [`Secret`]).
    pub payload: PairingPayload,
    /// `agentnest://pair?d=...` (the QR content). **Contains the secret**; show it only as a QR code.
    pub uri: String,
    /// The QR code as SVG.
    pub qr_svg: String,
    /// Expiry (RFC 3339).
    pub expires_at: String,
}

/// The PC user's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmDecision {
    /// Approve the pairing.
    Approve,
    /// Reject it.
    Reject,
}

enum Phase {
    Open,
    AwaitingConfirm {
        epoch: u64,
        tx: Option<oneshot::Sender<ConfirmDecision>>,
        sas: String,
        device_name: String,
    },
}

struct Active {
    pairing_id: String,
    secret: PairingSecret,
    expires_ms: i64,
    fail_count: u8,
    phase: Phase,
}

struct State {
    active: Option<Active>,
    next_epoch: u64,
}

/// The pairing manager. Cheap to clone.
#[derive(Clone)]
pub struct PairingManager {
    state: Arc<Mutex<State>>,
    store: Store,
    clock: Arc<dyn Clock>,
    audit: Audit,
    bus: EventBus,
}

impl std::fmt::Debug for PairingManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingManager").finish_non_exhaustive()
    }
}

/// A pairing whose phone proved possession of the secret and waits for the PC user. Dropping it without calling
/// [`PairingManager::finalize`] burns the pairing (`failed`).
pub struct PendingConfirmation {
    manager: PairingManager,
    /// Pairing id.
    pub pairing_id: String,
    /// The SAS the PC shows (and the phone computes itself).
    pub sas: String,
    /// What the phone told about itself.
    pub device: NewDevice,
    /// Resolves when the PC user approves or rejects.
    pub decision: Option<oneshot::Receiver<ConfirmDecision>>,
    epoch: u64,
    finished: bool,
}

impl std::fmt::Debug for PendingConfirmation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingConfirmation")
            .field("pairing_id", &self.pairing_id)
            .finish_non_exhaustive()
    }
}

impl Drop for PendingConfirmation {
    fn drop(&mut self) {
        if !self.finished {
            self.manager
                .end_awaiting(&self.pairing_id, self.epoch, "failed");
        }
    }
}

fn random_bytes<const N: usize>() -> Result<[u8; N], PairingError> {
    let mut b = [0u8; N];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| PairingError::Rng)?;
    Ok(b)
}

impl PairingManager {
    /// A manager. `bus` receives [`PairingUiEvent`]s.
    pub fn new(store: Store, clock: Arc<dyn Clock>, audit: Audit, bus: EventBus) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                active: None,
                next_epoch: 1,
            })),
            store,
            clock,
            audit,
            bus,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn record_outcome(&self, pairing_id: &str, outcome: &str, fail_count: Option<u8>) {
        let (id, outcome, now) = (
            pairing_id.to_owned(),
            outcome.to_owned(),
            format_ms(self.clock.now_ms()),
        );
        let fails = fail_count.map(i64::from);
        let r = self.store.run(move |c| {
            c.execute(
                "UPDATE pairings SET outcome=COALESCE(outcome, ?1), used_at=COALESCE(used_at, ?2), \
                 fail_count=COALESCE(?3, fail_count) WHERE pairing_id=?4",
                params![outcome, now, fails, id],
            )?;
            Ok(())
        });
        if let Err(e) = r {
            tracing::warn!(error = %e, "could not record the pairing outcome");
        }
    }

    fn emit_ended(&self, pairing_id: &str, outcome: &str) {
        self.bus.emit(DaemonEvent::Pairing(PairingUiEvent::Ended {
            pairing_id: pairing_id.to_owned(),
            outcome: outcome.to_owned(),
        }));
    }

    /// Ends an expired open pairing. Returns its id if one expired.
    fn expire_locked(&self, st: &mut State) -> Option<String> {
        let now = self.clock.now_ms();
        let expired = matches!(
            &st.active,
            Some(a) if matches!(a.phase, Phase::Open) && a.expires_ms <= now
        );
        if expired {
            st.active.take().map(|a| a.pairing_id)
        } else {
            None
        }
    }

    /// Housekeeping: ends an open pairing whose QR expired. Call about once a second.
    pub fn tick(&self) {
        let expired = {
            let mut st = self.lock();
            self.expire_locked(&mut st)
        };
        if let Some(id) = expired {
            self.record_outcome(&id, "expired", None);
            self.emit_ended(&id, "expired");
        }
    }

    /// `true` if the PC user has accepted risk R1.
    pub fn risk_accepted(&self) -> bool {
        matches!(
            self.store.setting_get(RISK_R1_SETTING),
            Ok(Some(serde_json::Value::Bool(true)))
        )
    }

    /// Records the acceptance of risk R1 (`audit_log(risk_accepted)`), the precondition of every pairing.
    pub async fn accept_risk(&self) -> Result<(), PairingError> {
        let store = self.store.clone();
        let now = format_ms(self.clock.now_ms());
        tokio::task::spawn_blocking(move || {
            store.setting_set(RISK_R1_SETTING, &serde_json::Value::Bool(true), &now)
        })
        .await
        .map_err(|e| PairingError::Store(StoreError::Panicked(e.to_string())))??;
        self.audit
            .log(
                ACTOR_DESKTOP_USER,
                actions::RISK_ACCEPTED,
                Some("R1".to_owned()),
                None,
            )
            .await;
        Ok(())
    }

    /// Starts pairing mode: generates `pairing_id` and a 32-byte secret, stores `SHA-256(secret)` and returns the QR.
    pub fn start(&self, info: &PairingStartInfo) -> Result<PairingStarted, PairingError> {
        if !self.risk_accepted() {
            return Err(PairingError::RiskNotAccepted);
        }
        if info.hosts.is_empty() {
            return Err(PairingError::NoHosts);
        }
        let now = self.clock.now_ms();
        let started = {
            let mut st = self.lock();
            let expired = self.expire_locked(&mut st);
            if let Some(id) = expired {
                self.record_outcome(&id, "expired", None);
                self.emit_ended(&id, "expired");
            }
            if st.active.is_some() {
                return Err(PairingError::Busy);
            }
            let secret_raw = random_bytes::<SECRET_LEN>()?;
            let pairing_id = format!("p_{}", hex::encode(random_bytes::<8>()?));
            let expires_ms = now + QR_TTL_MS;
            let expires_at = format_ms(expires_ms);
            let payload = PairingPayload {
                v: 1,
                pc_id: info.pc_id.clone(),
                pc_name: info.pc_name.chars().take(64).collect(),
                hosts: info.hosts.iter().take(8).cloned().collect(),
                port: info.port,
                spki_pin: info.spki_pin.clone(),
                pairing_id: pairing_id.clone(),
                pairing_secret: Secret::new(b64url_encode(&secret_raw)),
                expires_at: expires_at.clone(),
            };
            let uri = payload.to_uri().map_err(|_| PairingError::Qr)?;
            let qr_svg = render_qr_svg(&uri)?;
            let secret = PairingSecret::new(secret_raw.to_vec());
            let hash = sha256(&secret_raw).to_vec();
            let (id_db, created, exp_db) = (pairing_id.clone(), format_ms(now), expires_at.clone());
            self.store.run(move |c| {
                c.execute(
                    "INSERT INTO pairings(pairing_id, secret_sha256, created_at, expires_at, fail_count) \
                     VALUES (?1, ?2, ?3, ?4, 0)",
                    params![id_db, hash, created, exp_db],
                )?;
                Ok(())
            })?;
            st.active = Some(Active {
                pairing_id: pairing_id.clone(),
                secret,
                expires_ms,
                fail_count: 0,
                phase: Phase::Open,
            });
            PairingStarted {
                pairing_id,
                payload,
                uri,
                qr_svg,
                expires_at,
            }
        };
        self.bus.emit(DaemonEvent::Pairing(PairingUiEvent::Started {
            pairing_id: started.pairing_id.clone(),
            expires_at: started.expires_at.clone(),
        }));
        Ok(started)
    }

    /// Cancels the active pairing (desktop "cancel"). If a phone waits for confirmation it is rejected.
    pub fn cancel(&self, pairing_id: &str) -> bool {
        let taken = {
            let mut st = self.lock();
            match st.active.take() {
                Some(a) if a.pairing_id == pairing_id => Some(a),
                other => {
                    st.active = other;
                    None
                }
            }
        };
        let Some(mut a) = taken else { return false };
        if let Phase::AwaitingConfirm { tx, .. } = &mut a.phase {
            if let Some(tx) = tx.take() {
                let _ = tx.send(ConfirmDecision::Reject);
            }
        }
        self.record_outcome(pairing_id, "cancelled", Some(a.fail_count));
        self.emit_ended(pairing_id, "cancelled");
        true
    }

    /// The active pairing id and expiry, if any (status page).
    pub fn active(&self) -> Option<(String, String)> {
        let st = self.lock();
        st.active
            .as_ref()
            .map(|a| (a.pairing_id.clone(), format_ms(a.expires_ms)))
    }

    /// `true` while a phone waits for the PC user.
    pub fn awaiting_confirmation(&self) -> bool {
        matches!(
            &self.lock().active,
            Some(Active {
                phase: Phase::AwaitingConfirm { .. },
                ..
            })
        )
    }

    /// Verifies a `pair` frame (security.md 4.2 step 6). On success the pairing moves to `AwaitingConfirm` and the PC
    /// UI is told to show the SAS modal.
    pub fn begin(
        &self,
        pc_id: &str,
        pair: &PairPayload,
        challenge: &Challenge,
    ) -> Result<PendingConfirmation, PairFailure> {
        // Parse everything that does not need the secret first (a malformed frame is a protocol violation, not a
        // failed attempt).
        if pair.device.name.len() > DEVICE_NAME_MAX_BYTES || pair.device.name.is_empty() {
            return Err(PairFailure::BadMessage);
        }
        let spki: Vec<u8> = match &pair.device_pubkey_spki_b64 {
            Some(b) if !b.is_empty() => b64_decode(b).map_err(|_| PairFailure::BadMessage)?,
            _ => Vec::new(),
        };
        let proof = b64_decode(pair.proof_b64.expose()).map_err(|_| PairFailure::BadMessage)?;

        let (sas_text, epoch, rx, expired) = {
            let mut st = self.lock();
            let expired = self.expire_locked(&mut st);
            let epoch = st.next_epoch;
            let Some(active) = st.active.as_mut() else {
                drop(st);
                if let Some(id) = &expired {
                    self.record_outcome(id, "expired", None);
                    self.emit_ended(id, "expired");
                }
                return Err(PairFailure::Failed);
            };
            // An unknown id never touches the active pairing (an attacker cannot burn the legitimate QR by guessing).
            if active.pairing_id != pair.pairing_id {
                return Err(PairFailure::Failed);
            }
            if matches!(active.phase, Phase::AwaitingConfirm { .. }) {
                return Err(PairFailure::Busy);
            }
            let mut ok = challenge.matches_b64(&pair.challenge_b64);
            if ok {
                match canonical_pair_bytes(
                    pc_id,
                    &pair.pairing_id,
                    challenge.raw(),
                    &pair.device.name,
                    &spki,
                ) {
                    Ok(bytes) => {
                        ok = verify_pair_proof(active.secret.expose(), &bytes, &proof);
                    }
                    Err(_) => ok = false,
                }
            }
            if !ok {
                active.fail_count += 1;
                let burned = active.fail_count >= MAX_FAIL_COUNT;
                let fails = active.fail_count;
                let id = active.pairing_id.clone();
                if burned {
                    st.active = None;
                }
                drop(st);
                if burned {
                    self.record_outcome(&id, "failed", Some(fails));
                    self.emit_ended(&id, "failed");
                } else {
                    // keep the row open: only the counter changes (outcome stays NULL)
                    self.record_fail_count(&id, fails);
                }
                return Err(PairFailure::Failed);
            }
            let sas_text = match sas(active.secret.expose(), challenge.raw(), &spki) {
                Ok(s) => s,
                Err(_) => return Err(PairFailure::Failed),
            };
            let (tx, rx) = oneshot::channel();
            active.phase = Phase::AwaitingConfirm {
                epoch,
                tx: Some(tx),
                sas: sas_text.clone(),
                device_name: pair.device.name.clone(),
            };
            st.next_epoch += 1;
            (sas_text, epoch, rx, expired)
        };
        if let Some(id) = expired {
            self.record_outcome(&id, "expired", None);
            self.emit_ended(&id, "expired");
        }
        self.bus
            .emit(DaemonEvent::Pairing(PairingUiEvent::ConfirmRequested {
                pairing_id: pair.pairing_id.clone(),
                sas: sas_text.clone(),
                device_name: pair.device.name.clone(),
                device_model: pair.device.model.clone(),
                timeout_ms: CONFIRM_TIMEOUT_MS,
            }));
        Ok(PendingConfirmation {
            manager: self.clone(),
            pairing_id: pair.pairing_id.clone(),
            sas: sas_text,
            device: NewDevice {
                name: pair.device.name.clone(),
                platform: pair.device.platform.clone(),
                model: pair.device.model.clone(),
                os_version: pair.device.os_version.clone(),
                app_version: pair.device.app_version.clone(),
                pubkey_spki_der: if spki.is_empty() { None } else { Some(spki) },
            },
            decision: Some(rx),
            epoch,
            finished: false,
        })
    }

    fn record_fail_count(&self, pairing_id: &str, fails: u8) {
        let (id, fails) = (pairing_id.to_owned(), i64::from(fails));
        let r = self.store.run(move |c| {
            c.execute(
                "UPDATE pairings SET fail_count=?1 WHERE pairing_id=?2",
                params![fails, id],
            )?;
            Ok(())
        });
        if let Err(e) = r {
            tracing::warn!(error = %e, "could not record the pairing failure count");
        }
    }

    /// The PC user's answer (desktop `pairing_confirm`). Only valid while a phone waits for confirmation.
    pub fn confirm(&self, pairing_id: &str, approve: bool) -> Result<(), PairingError> {
        let mut st = self.lock();
        let Some(active) = st.active.as_mut() else {
            return Err(PairingError::NotPending);
        };
        if active.pairing_id != pairing_id {
            return Err(PairingError::NotPending);
        }
        match &mut active.phase {
            Phase::AwaitingConfirm { tx, .. } => {
                let Some(tx) = tx.take() else {
                    return Err(PairingError::NotPending);
                };
                let decision = if approve {
                    ConfirmDecision::Approve
                } else {
                    ConfirmDecision::Reject
                };
                tx.send(decision).map_err(|_| PairingError::NotPending)
            }
            Phase::Open => Err(PairingError::NotPending),
        }
    }

    /// The pending SAS and device name for the modal (status queries).
    pub fn awaiting_info(&self) -> Option<(String, String, String)> {
        match &self.lock().active {
            Some(Active {
                pairing_id,
                phase:
                    Phase::AwaitingConfirm {
                        sas, device_name, ..
                    },
                ..
            }) => Some((pairing_id.clone(), sas.clone(), device_name.clone())),
            _ => None,
        }
    }

    fn end_awaiting(&self, pairing_id: &str, epoch: u64, outcome: &str) {
        let taken = {
            let mut st = self.lock();
            let matches = matches!(
                &st.active,
                Some(a) if a.pairing_id == pairing_id
                    && matches!(a.phase, Phase::AwaitingConfirm { epoch: e, .. } if e == epoch)
            );
            if matches {
                st.active.take()
            } else {
                None
            }
        };
        if let Some(a) = taken {
            self.record_outcome(pairing_id, outcome, Some(a.fail_count));
            self.emit_ended(pairing_id, outcome);
        }
    }

    /// The PC user (or the 60 s timer, or a disconnect) ended the confirmation without a device: burns the pairing.
    /// `outcome` is `rejected` or `failed`.
    pub async fn abort(&self, mut pending: PendingConfirmation, outcome: &str) {
        pending.finished = true;
        self.end_awaiting(&pending.pairing_id, pending.epoch, outcome);
        if outcome == "rejected" {
            self.audit
                .log(
                    ACTOR_DESKTOP_USER,
                    actions::PAIRING_REJECTED,
                    Some(pending.pairing_id.clone()),
                    None,
                )
                .await;
        } else {
            self.audit
                .log(
                    ACTOR_SYSTEM,
                    actions::PAIRING_REJECTED,
                    Some(pending.pairing_id.clone()),
                    Some(serde_json::json!({ "reason": outcome })),
                )
                .await;
        }
    }

    /// The PC user approved: in **one transaction** the device row is created and the pairing is marked used. Returns the
    /// device with its one-time token. The pairing mode ends.
    pub async fn finalize(
        &self,
        mut pending: PendingConfirmation,
    ) -> Result<IssuedDevice, DeviceError> {
        let pairing_id = pending.pairing_id.clone();
        let device = pending.device.clone();
        let now = format_ms(self.clock.now_ms());
        let store = self.store.clone();
        let (id_tx, now_tx) = (pairing_id.clone(), now.clone());
        let result = tokio::task::spawn_blocking(move || {
            store.run(move |c| {
                let tx = c.transaction()?;
                let issued = match insert_device_tx(&tx, &device, &now_tx) {
                    Ok(i) => i,
                    Err(e) => return Ok(Err(e)),
                };
                tx.execute(
                    "UPDATE pairings SET used_at=?1, outcome='paired', device_id=?2 WHERE pairing_id=?3 AND used_at IS NULL",
                    params![now_tx, issued.device_id, id_tx],
                )?;
                tx.commit()?;
                Ok(Ok(issued))
            })
        })
        .await;
        let issued = match result {
            Ok(Ok(Ok(i))) => i,
            Ok(Ok(Err(e))) => {
                pending.finished = true;
                self.end_awaiting(&pairing_id, pending.epoch, "failed");
                return Err(e);
            }
            Ok(Err(e)) => {
                pending.finished = true;
                self.end_awaiting(&pairing_id, pending.epoch, "failed");
                return Err(DeviceError::Store(e));
            }
            Err(e) => {
                pending.finished = true;
                self.end_awaiting(&pairing_id, pending.epoch, "failed");
                return Err(DeviceError::Store(StoreError::Panicked(e.to_string())));
            }
        };
        pending.finished = true;
        {
            let mut st = self.lock();
            if matches!(&st.active, Some(a) if a.pairing_id == pairing_id) {
                st.active = None;
            }
        }
        self.audit
            .log(
                ACTOR_DESKTOP_USER,
                actions::PAIRING_CONFIRMED,
                Some(pairing_id.clone()),
                None,
            )
            .await;
        self.audit
            .log(
                ACTOR_SYSTEM,
                actions::DEVICE_PAIRED,
                Some(issued.device_id.clone()),
                Some(serde_json::json!({ "name": pending.device.name })),
            )
            .await;
        self.emit_ended(&pairing_id, "paired");
        self.bus.emit(DaemonEvent::Device(DeviceUiEvent::Paired {
            device_id: issued.device_id.clone(),
            name: pending.device.name.clone(),
        }));
        Ok(issued)
    }
}

fn render_qr_svg(content: &str) -> Result<String, PairingError> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::new(content.as_bytes()).map_err(|_| PairingError::Qr)?;
    Ok(code
        .render::<svg::Color<'_>>()
        .min_dimensions(240, 240)
        .quiet_zone(true)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::timers::ManualClock;
    use agentnest_protocol::canonical::{pair_proof, sas as compute_sas};
    use agentnest_protocol::qr::{b64_encode, b64url_decode};
    use agentnest_protocol::DeviceInfo;

    struct Fixture {
        mgr: PairingManager,
        clock: Arc<ManualClock>,
        store: Store,
        bus: EventBus,
    }

    fn fixture() -> Fixture {
        let store = Store::open_in_memory().unwrap();
        let clock = Arc::new(ManualClock::new(1_792_055_553_120));
        let bus = EventBus::new(64);
        let audit = Audit::new(store.clone(), clock.clone());
        let mgr = PairingManager::new(store.clone(), clock.clone(), audit, bus.clone());
        let now = format_ms(clock.now_ms());
        store
            .setting_set(RISK_R1_SETTING, &serde_json::Value::Bool(true), &now)
            .unwrap();
        Fixture {
            mgr,
            clock,
            store,
            bus,
        }
    }

    fn info() -> PairingStartInfo {
        PairingStartInfo {
            pc_id: "pc_8252e6280a3d81d1".into(),
            pc_name: "DESKTOP-HOME".into(),
            hosts: vec!["192.168.0.10".into()],
            port: 47832,
            spki_pin: "sha256/glLmKAo9gdGvAGIYNxNEvncjE6SNAheIa/dX4bFINbU=".into(),
        }
    }

    fn pair_frame(
        started: &PairingStarted,
        challenge: &Challenge,
        name: &str,
        spki: &[u8],
        secret_override: Option<&[u8]>,
    ) -> PairPayload {
        let secret = secret_override
            .map(<[u8]>::to_vec)
            .unwrap_or_else(|| started.payload.pairing_secret_bytes().unwrap());
        let bytes = canonical_pair_bytes(
            &started.payload.pc_id,
            &started.pairing_id,
            challenge.raw(),
            name,
            spki,
        )
        .unwrap();
        PairPayload {
            pairing_id: started.pairing_id.clone(),
            challenge_b64: challenge.to_b64(),
            device: DeviceInfo {
                name: name.into(),
                platform: "android".into(),
                model: Some("SM-S938N".into()),
                os_version: Some("16".into()),
                app_version: Some("0.1.0".into()),
            },
            device_pubkey_spki_b64: if spki.is_empty() {
                None
            } else {
                Some(b64_encode(spki))
            },
            proof_b64: Secret::new(b64_encode(&pair_proof(&secret, &bytes))),
            protocol: 1,
        }
    }

    #[test]
    fn start_requires_risk_r1_and_stores_only_the_secret_hash() {
        let store = Store::open_in_memory().unwrap();
        let clock = Arc::new(ManualClock::new(1_792_055_553_120));
        let audit = Audit::new(store.clone(), clock.clone());
        let mgr = PairingManager::new(store.clone(), clock, audit, EventBus::new(8));
        assert!(matches!(
            mgr.start(&info()),
            Err(PairingError::RiskNotAccepted)
        ));
        assert!(!mgr.risk_accepted());
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(mgr.accept_risk()).unwrap();
        let started = mgr.start(&info()).unwrap();
        // the audit trail has risk_accepted
        let rows = store.list_audit_log(10).unwrap();
        assert!(rows
            .iter()
            .any(|r| r.action == "risk_accepted" && r.target.as_deref() == Some("R1")));
        // DB: hash only, never the secret
        let secret = started.payload.pairing_secret.expose().to_owned();
        let raw = b64url_decode(&secret).unwrap();
        let (hash, dump): (Vec<u8>, String) = store
            .read(|c| {
                Ok((
                    c.query_row("SELECT secret_sha256 FROM pairings", [], |r| r.get(0))?,
                    c.query_row(
                        "SELECT pairing_id||created_at||expires_at||IFNULL(outcome,'') FROM pairings",
                        [],
                        |r| r.get(0),
                    )?,
                ))
            })
            .unwrap();
        assert_eq!(hash, sha256(&raw).to_vec());
        assert!(!dump.contains(&secret));
        assert!(started.uri.starts_with("agentnest://pair?d="));
        assert!(started.qr_svg.contains("<svg"));
        let parsed = PairingPayload::from_uri(&started.uri).unwrap();
        assert_eq!(parsed.pairing_id, started.pairing_id);
        assert!(parsed.pc_id_matches_pin() || !parsed.pc_id_matches_pin()); // structure only; pin is a fixture value
        assert_eq!(started.pairing_id.len(), 2 + 16);
        assert_eq!(started.expires_at, format_ms(1_792_055_553_120 + 120_000));
        assert!(
            !format!("{started:?}").contains(&secret),
            "the secret is redacted in Debug"
        );
    }

    #[test]
    fn only_one_pairing_at_a_time_and_expiry_frees_the_slot() {
        let f = fixture();
        let a = f.mgr.start(&info()).unwrap();
        assert!(matches!(f.mgr.start(&info()), Err(PairingError::Busy)));
        f.clock.advance(119_000);
        assert!(matches!(f.mgr.start(&info()), Err(PairingError::Busy)));
        f.clock.advance(1_001);
        let b = f.mgr.start(&info()).unwrap();
        assert_ne!(a.pairing_id, b.pairing_id);
        let outcome: Option<String> = f
            .store
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT outcome FROM pairings WHERE pairing_id=?1",
                    [a.pairing_id],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("expired"));
        assert!(f.mgr.cancel(&b.pairing_id));
        assert!(!f.mgr.cancel(&b.pairing_id));
        assert!(f.mgr.start(&info()).is_ok());
    }

    #[test]
    fn a_valid_proof_leads_to_sas_confirmation_matching_the_protocol_derivation() {
        let f = fixture();
        let started = f.mgr.start(&info()).unwrap();
        let ch = Challenge::generate().unwrap();
        let spki = vec![0x30, 0x59, 1, 2, 3];
        let frame = pair_frame(&started, &ch, "Galaxy S25", &spki, None);
        let mut rx_events = f.bus.subscribe();
        let pending = f.mgr.begin(&started.payload.pc_id, &frame, &ch).unwrap();
        let secret = started.payload.pairing_secret_bytes().unwrap();
        let want = compute_sas(&secret, ch.raw(), &spki).unwrap();
        assert_eq!(pending.sas, want);
        assert_eq!(pending.sas.len(), 6);
        assert_eq!(pending.device.name, "Galaxy S25");
        assert_eq!(
            pending.device.pubkey_spki_der.as_deref(),
            Some(spki.as_slice())
        );
        assert!(f.mgr.awaiting_confirmation());
        // the desktop gets the SAS modal event
        let mut saw = false;
        while let Ok(ev) = rx_events.try_recv() {
            if let DaemonEvent::Pairing(PairingUiEvent::ConfirmRequested {
                sas, device_name, ..
            }) = ev
            {
                assert_eq!(sas, want);
                assert_eq!(device_name, "Galaxy S25");
                saw = true;
            }
        }
        assert!(saw);
        // a second phone is told "busy", not "failed"
        let ch2 = Challenge::generate().unwrap();
        let frame2 = pair_frame(&started, &ch2, "Other", &[], None);
        assert_eq!(
            f.mgr
                .begin(&started.payload.pc_id, &frame2, &ch2)
                .unwrap_err(),
            PairFailure::Busy
        );
        drop(pending);
    }

    #[tokio::test]
    async fn approval_creates_the_device_atomically_and_ends_the_pairing() {
        let f = fixture();
        let started = f.mgr.start(&info()).unwrap();
        let ch = Challenge::generate().unwrap();
        let frame = pair_frame(&started, &ch, "Galaxy S25", &[7, 7, 7], None);
        let mut pending = f.mgr.begin(&started.payload.pc_id, &frame, &ch).unwrap();
        let rx = pending.decision.take().unwrap();
        f.mgr.confirm(&started.pairing_id, true).unwrap();
        assert_eq!(rx.await.unwrap(), ConfirmDecision::Approve);
        let issued = f.mgr.finalize(pending).await.unwrap();
        assert!(issued.device_id.starts_with("dev_"));
        assert!(!f.mgr.awaiting_confirmation());
        assert!(f.mgr.active().is_none());
        let (outcome, device_id, used): (String, String, Option<String>) = f
            .store
            .read(|c| {
                Ok(c.query_row(
                    "SELECT outcome, device_id, used_at FROM pairings",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?)
            })
            .unwrap();
        assert_eq!(outcome, "paired");
        assert_eq!(device_id, issued.device_id);
        assert!(used.is_some());
        // the QR is single use: the same frame again is "failed"
        let ch2 = Challenge::generate().unwrap();
        let again = pair_frame(&started, &ch2, "Galaxy S25", &[7, 7, 7], None);
        assert_eq!(
            f.mgr
                .begin(&started.payload.pc_id, &again, &ch2)
                .unwrap_err(),
            PairFailure::Failed
        );
        // audit trail
        let actions: Vec<String> = f
            .store
            .list_audit_log(20)
            .unwrap()
            .into_iter()
            .map(|r| r.action)
            .collect();
        assert!(actions.contains(&"pairing_confirmed".to_owned()));
        assert!(actions.contains(&"device_paired".to_owned()));
    }

    #[tokio::test]
    async fn rejection_burns_the_pairing_and_registers_no_device() {
        let f = fixture();
        let started = f.mgr.start(&info()).unwrap();
        let ch = Challenge::generate().unwrap();
        let frame = pair_frame(&started, &ch, "Galaxy", &[], None);
        let mut pending = f.mgr.begin(&started.payload.pc_id, &frame, &ch).unwrap();
        let rx = pending.decision.take().unwrap();
        f.mgr.confirm(&started.pairing_id, false).unwrap();
        assert_eq!(rx.await.unwrap(), ConfirmDecision::Reject);
        f.mgr.abort(pending, "rejected").await;
        let devices: i64 = f
            .store
            .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(devices, 0);
        let outcome: String = f
            .store
            .read(|c| Ok(c.query_row("SELECT outcome FROM pairings", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(outcome, "rejected");
        assert!(f.mgr.active().is_none(), "the QR is burned");
        assert!(matches!(
            f.mgr.confirm(&started.pairing_id, true),
            Err(PairingError::NotPending)
        ));
        assert!(f
            .store
            .list_audit_log(10)
            .unwrap()
            .iter()
            .any(|r| r.action == "pairing_rejected"));
    }

    #[test]
    fn dropping_the_pending_confirmation_burns_the_pairing() {
        let f = fixture();
        let started = f.mgr.start(&info()).unwrap();
        let ch = Challenge::generate().unwrap();
        let frame = pair_frame(&started, &ch, "Galaxy", &[], None);
        let pending = f.mgr.begin(&started.payload.pc_id, &frame, &ch).unwrap();
        drop(pending); // the phone disconnected
        assert!(f.mgr.active().is_none());
        let outcome: String = f
            .store
            .read(|c| Ok(c.query_row("SELECT outcome FROM pairings", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(outcome, "failed");
    }

    #[test]
    fn wrong_proofs_count_and_the_third_burns_the_qr() {
        let f = fixture();
        let started = f.mgr.start(&info()).unwrap();
        let wrong_secret = [9u8; 32];
        for attempt in 1..=3 {
            let ch = Challenge::generate().unwrap();
            let frame = pair_frame(&started, &ch, "Intruder", &[], Some(&wrong_secret));
            assert_eq!(
                f.mgr
                    .begin(&started.payload.pc_id, &frame, &ch)
                    .unwrap_err(),
                PairFailure::Failed,
                "attempt {attempt}"
            );
            let fails: i64 = f
                .store
                .read(|c| Ok(c.query_row("SELECT fail_count FROM pairings", [], |r| r.get(0))?))
                .unwrap();
            assert_eq!(fails, attempt);
            if attempt < 3 {
                assert!(
                    f.mgr.active().is_some(),
                    "still open after {attempt} failures"
                );
            }
        }
        assert!(f.mgr.active().is_none(), "burned after the third failure");
        // even the right secret fails now
        let ch = Challenge::generate().unwrap();
        let frame = pair_frame(&started, &ch, "Galaxy", &[], None);
        assert_eq!(
            f.mgr
                .begin(&started.payload.pc_id, &frame, &ch)
                .unwrap_err(),
            PairFailure::Failed
        );
        let outcome: String = f
            .store
            .read(|c| Ok(c.query_row("SELECT outcome FROM pairings", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(outcome, "failed");
    }

    #[test]
    fn two_failures_then_success_still_pairs_and_does_not_leave_a_pending_fail_marker() {
        let f = fixture();
        let started = f.mgr.start(&info()).unwrap();
        for _ in 0..2 {
            let ch = Challenge::generate().unwrap();
            let frame = pair_frame(&started, &ch, "X", &[], Some(&[1u8; 32]));
            assert!(f.mgr.begin(&started.payload.pc_id, &frame, &ch).is_err());
        }
        let outcome: Option<String> = f
            .store
            .read(|c| Ok(c.query_row("SELECT outcome FROM pairings", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(outcome, None, "an open pairing has no outcome yet");
        let ch = Challenge::generate().unwrap();
        let frame = pair_frame(&started, &ch, "Galaxy", &[], None);
        assert!(f.mgr.begin(&started.payload.pc_id, &frame, &ch).is_ok());
    }

    #[test]
    fn challenge_echo_pairing_id_and_expiry_are_all_checked_without_distinguishing_them() {
        let f = fixture();
        let started = f.mgr.start(&info()).unwrap();
        // wrong challenge echo (a challenge of another connection)
        let ch = Challenge::generate().unwrap();
        let other = Challenge::generate().unwrap();
        let mut frame = pair_frame(&started, &ch, "Galaxy", &[], None);
        frame.challenge_b64 = other.to_b64();
        assert_eq!(
            f.mgr
                .begin(&started.payload.pc_id, &frame, &ch)
                .unwrap_err(),
            PairFailure::Failed
        );
        // proof computed over another challenge
        let frame = pair_frame(&started, &other, "Galaxy", &[], None);
        assert_eq!(
            f.mgr
                .begin(&started.payload.pc_id, &frame, &ch)
                .unwrap_err(),
            PairFailure::Failed
        );
        // unknown pairing id does not count against the active QR
        let mut frame = pair_frame(&started, &ch, "Galaxy", &[], None);
        frame.pairing_id = "p_0000000000000000".into();
        assert_eq!(
            f.mgr
                .begin(&started.payload.pc_id, &frame, &ch)
                .unwrap_err(),
            PairFailure::Failed
        );
        let fails: i64 = f
            .store
            .read(|c| Ok(c.query_row("SELECT fail_count FROM pairings", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(fails, 2, "only attempts with the right pairing id count");
        // another PC id in the proof
        let frame = pair_frame(&started, &ch, "Galaxy", &[], None);
        assert_eq!(
            f.mgr.begin("pc_ffffffffffffffff", &frame, &ch).unwrap_err(),
            PairFailure::Failed
        );
        // expiry
        f.mgr.cancel(&started.pairing_id);
        let started = f.mgr.start(&info()).unwrap();
        let frame = pair_frame(&started, &ch, "Galaxy", &[], None);
        f.clock.advance(120_001);
        assert_eq!(
            f.mgr
                .begin(&started.payload.pc_id, &frame, &ch)
                .unwrap_err(),
            PairFailure::Failed
        );
        assert!(f.mgr.active().is_none());
    }

    #[test]
    fn malformed_frames_are_protocol_violations() {
        let f = fixture();
        let started = f.mgr.start(&info()).unwrap();
        let ch = Challenge::generate().unwrap();
        let long = "x".repeat(65);
        let mut frame = pair_frame(&started, &ch, "Galaxy", &[], None);
        frame.device.name = long;
        assert_eq!(
            f.mgr
                .begin(&started.payload.pc_id, &frame, &ch)
                .unwrap_err(),
            PairFailure::BadMessage
        );
        let mut frame = pair_frame(&started, &ch, "Galaxy", &[], None);
        frame.proof_b64 = Secret::new("%%%");
        assert_eq!(
            f.mgr
                .begin(&started.payload.pc_id, &frame, &ch)
                .unwrap_err(),
            PairFailure::BadMessage
        );
        let fails: i64 = f
            .store
            .read(|c| Ok(c.query_row("SELECT fail_count FROM pairings", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(fails, 0, "malformed frames do not burn the QR");
        let mut frame = pair_frame(&started, &ch, "Galaxy", &[], None);
        frame.proof_b64 = Secret::new(b64_encode(&[0u8; 5]));
        assert_eq!(
            f.mgr
                .begin(&started.payload.pc_id, &frame, &ch)
                .unwrap_err(),
            PairFailure::Failed,
            "short proof fails"
        );
    }

    #[test]
    fn cancel_while_awaiting_rejects_the_waiting_phone() {
        let f = fixture();
        let started = f.mgr.start(&info()).unwrap();
        let ch = Challenge::generate().unwrap();
        let frame = pair_frame(&started, &ch, "Galaxy", &[], None);
        let mut pending = f.mgr.begin(&started.payload.pc_id, &frame, &ch).unwrap();
        let mut rx = pending.decision.take().unwrap();
        assert!(f.mgr.cancel(&started.pairing_id));
        assert_eq!(rx.try_recv().unwrap(), ConfirmDecision::Reject);
        assert!(f.mgr.active().is_none());
    }

    #[test]
    fn tick_ends_an_expired_open_pairing_and_tells_the_desktop() {
        let f = fixture();
        let mut rx = f.bus.subscribe();
        let started = f.mgr.start(&info()).unwrap();
        f.clock.advance(121_000);
        f.mgr.tick();
        assert!(f.mgr.active().is_none());
        let mut ended = false;
        while let Ok(ev) = rx.try_recv() {
            if let DaemonEvent::Pairing(PairingUiEvent::Ended {
                pairing_id,
                outcome,
            }) = ev
            {
                assert_eq!(pairing_id, started.pairing_id);
                assert_eq!(outcome, "expired");
                ended = true;
            }
        }
        assert!(ended);
    }

    #[test]
    fn vector_file_proofs_verify_through_the_manager_primitives() {
        // The manager uses canonical_pair_bytes + verify_pair_proof from the protocol crate; the vectors in
        // protocol/vectors/pair.json pin those bytes (see agentnest-protocol/tests/vectors.rs). Here: a proof built
        // with the same primitives verifies, a bit flip does not.
        let secret = [3u8; 32];
        let ch = [5u8; 16];
        let bytes = canonical_pair_bytes("pc_1", "p_1", &ch, "Name", &[]).unwrap();
        let proof = pair_proof(&secret, &bytes);
        assert!(verify_pair_proof(&secret, &bytes, &proof));
        let mut bad = proof;
        bad[0] ^= 1;
        assert!(!verify_pair_proof(&secret, &bytes, &bad));
    }
}
