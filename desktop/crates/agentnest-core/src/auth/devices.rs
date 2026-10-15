//! Device registry: token issuance, hash-only storage, authentication and revocation
//! (docs/security.md 5, I3, I6; docs/storage.md `devices`).
//!
//! * The device token is 32 random bytes (`ring::rand::SystemRandom`), sent to the phone **once** as base64url text.
//!   The PC stores **only `SHA-256(token)`** in `devices.token_hash`.
//! * [`DeviceRegistry::authenticate`] looks the device up, decodes the presented token, compares the hash with
//!   `subtle::ConstantTimeEq` (also when the device does not exist, against a dummy hash, so the cost does not reveal
//!   existence) and only then looks at `revoked_at`. Every failure other than "revoked" is the same
//!   [`AuthOutcome::Failed`] (the wire shows `E_AUTH_FAILED` without a reason).
//! * Revocation is a single `UPDATE devices SET revoked_at=...`; there is no way back (I6). Every lookup reads the
//!   database (no cache that could disagree with `revoked_at`).

use std::sync::Arc;

use agentnest_protocol::canonical::sha256;
use agentnest_protocol::limits::SECRET_LEN;
use agentnest_protocol::qr::{b64url_decode, b64url_encode};
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{params, OptionalExtension};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::redact::DeviceToken;
use crate::state::timers::{format_ms, Clock};
use crate::store::{Store, StoreError};

/// Errors of the device registry.
#[derive(Debug, Error)]
pub enum DeviceError {
    /// Storage failure.
    #[error("device storage error: {0}")]
    Store(#[from] StoreError),
    /// The system random number generator failed.
    #[error("random number generator failure")]
    Rng,
    /// Another active device already registered this public key.
    #[error("a device with this public key is already registered")]
    DuplicateKey,
}

/// A device row (no secrets: neither the token nor its hash).
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct DeviceRecord {
    pub device_id: String,
    pub name: String,
    pub platform: String,
    pub model: Option<String>,
    pub os_version: Option<String>,
    pub app_version: Option<String>,
    pub paired_at: String,
    pub last_seen_at: Option<String>,
    pub last_ip_masked: Option<String>,
    pub last_acked_seq: i64,
    pub revoked_at: Option<String>,
    pub revoked_reason: Option<String>,
}

impl DeviceRecord {
    /// `true` while the device may authenticate.
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// What the phone told the PC about itself while pairing.
#[derive(Clone, Debug, Default)]
pub struct NewDevice {
    /// Device name.
    pub name: String,
    /// `android`.
    pub platform: String,
    /// Model.
    pub model: Option<String>,
    /// OS version.
    pub os_version: Option<String>,
    /// App version.
    pub app_version: Option<String>,
    /// Phone EC public key (SPKI DER), stored for Phase 3 signatures.
    pub pubkey_spki_der: Option<Vec<u8>>,
}

/// A freshly registered device with its one-time token.
pub struct IssuedDevice {
    /// `dev_` + 16 random bytes as hex.
    pub device_id: String,
    /// The token to send to the phone exactly once.
    pub token: DeviceToken,
}

impl std::fmt::Debug for IssuedDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedDevice")
            .field("device_id", &self.device_id)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Result of [`DeviceRegistry::authenticate`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum AuthOutcome {
    /// The device and token are valid and the device is not revoked.
    Ok(DeviceRecord),
    /// Valid credentials of a revoked device (`E_DEVICE_REVOKED`, 4003: the phone deletes its token).
    Revoked,
    /// Unknown device, malformed or wrong token: not distinguished (`E_AUTH_FAILED`).
    Failed,
}

/// `SHA-256` of the raw 32-byte token.
pub fn token_hash(raw_token: &[u8]) -> [u8; 32] {
    sha256(raw_token)
}

/// Generates a token: `(base64url text for the phone, hash for the database)`.
pub fn generate_token() -> Result<(DeviceToken, [u8; 32]), DeviceError> {
    let mut raw = [0u8; SECRET_LEN];
    SystemRandom::new()
        .fill(&mut raw)
        .map_err(|_| DeviceError::Rng)?;
    let text = b64url_encode(&raw);
    let hash = token_hash(&raw);
    raw.fill(0);
    Ok((DeviceToken::new(text), hash))
}

/// `dev_` + 16 random bytes as lowercase hex.
pub fn generate_device_id() -> Result<String, DeviceError> {
    let mut raw = [0u8; 16];
    SystemRandom::new()
        .fill(&mut raw)
        .map_err(|_| DeviceError::Rng)?;
    Ok(format!("dev_{}", hex::encode(raw)))
}

const DEVICE_COLUMNS: &str =
    "device_id, name, platform, model, os_version, app_version, paired_at, last_seen_at, \
last_ip_masked, last_acked_seq, revoked_at, revoked_reason";

fn device_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceRecord> {
    Ok(DeviceRecord {
        device_id: r.get(0)?,
        name: r.get(1)?,
        platform: r.get(2)?,
        model: r.get(3)?,
        os_version: r.get(4)?,
        app_version: r.get(5)?,
        paired_at: r.get(6)?,
        last_seen_at: r.get(7)?,
        last_ip_masked: r.get(8)?,
        last_acked_seq: r.get(9)?,
        revoked_at: r.get(10)?,
        revoked_reason: r.get(11)?,
    })
}

/// Inserts a device inside a transaction (used by the pairing completion so that the device row and `pairings.used_at`
/// commit together). Returns the issued device.
pub(crate) fn insert_device_tx(
    tx: &rusqlite::Transaction<'_>,
    new: &NewDevice,
    now: &str,
) -> Result<IssuedDevice, DeviceError> {
    let (token, hash) = generate_token()?;
    let device_id = generate_device_id()?;
    if let Some(key) = &new.pubkey_spki_der {
        // `pubkey_spki_der` is UNIQUE. A revoked device only keeps its key for the audit trail, so the new pairing of the
        // same phone may take it over; an *active* holder means the same key is registered twice.
        let active: Option<String> = tx
            .query_row(
                "SELECT device_id FROM devices WHERE pubkey_spki_der=?1 AND revoked_at IS NULL",
                [key],
                |r| r.get(0),
            )
            .optional()
            .map_err(StoreError::from)?;
        if active.is_some() {
            return Err(DeviceError::DuplicateKey);
        }
        tx.execute(
            "UPDATE devices SET pubkey_spki_der=NULL WHERE pubkey_spki_der=?1",
            [key],
        )
        .map_err(StoreError::from)?;
    }
    tx.execute(
        "INSERT INTO devices(device_id, name, platform, model, os_version, app_version, token_hash, pubkey_spki_der, \
         paired_at, last_acked_seq) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,0)",
        params![
            device_id,
            new.name,
            new.platform,
            new.model,
            new.os_version,
            new.app_version,
            hash.to_vec(),
            new.pubkey_spki_der,
            now
        ],
    )
    .map_err(StoreError::from)?;
    Ok(IssuedDevice { device_id, token })
}

/// The device registry. Cheap to clone. All methods are blocking (SQLite); call them from `spawn_blocking` in async
/// code or use the `*_async` wrappers.
#[derive(Clone)]
pub struct DeviceRegistry {
    store: Store,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for DeviceRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRegistry").finish_non_exhaustive()
    }
}

impl DeviceRegistry {
    /// A registry on `store`.
    pub fn new(store: Store, clock: Arc<dyn Clock>) -> Self {
        Self { store, clock }
    }

    fn now(&self) -> String {
        format_ms(self.clock.now_ms())
    }

    /// One device (including revoked ones).
    pub fn get(&self, device_id: &str) -> Result<Option<DeviceRecord>, DeviceError> {
        let id = device_id.to_owned();
        Ok(self.store.read(move |c| {
            Ok(c.query_row(
                &format!("SELECT {DEVICE_COLUMNS} FROM devices WHERE device_id=?1"),
                [id],
                device_from_row,
            )
            .optional()?)
        })?)
    }

    /// `true` if the device exists and is not revoked. Reads the database every time.
    pub fn is_active(&self, device_id: &str) -> bool {
        matches!(self.get(device_id), Ok(Some(d)) if d.is_active())
    }

    /// All devices, newest pairing first.
    pub fn list(&self) -> Result<Vec<DeviceRecord>, DeviceError> {
        Ok(self.store.read(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {DEVICE_COLUMNS} FROM devices ORDER BY paired_at DESC, device_id"
            ))?;
            let rows = stmt.query_map([], device_from_row)?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })?)
    }

    /// Verifies the credentials of a `hello` (security.md 5): hash comparison in constant time, then revocation.
    pub fn authenticate(
        &self,
        device_id: &str,
        presented_token: &str,
    ) -> Result<AuthOutcome, DeviceError> {
        let id = device_id.to_owned();
        let row: Option<(DeviceRecord, Vec<u8>)> = self.store.read(move |c| {
            Ok(c.query_row(
                &format!("SELECT {DEVICE_COLUMNS}, token_hash FROM devices WHERE device_id=?1"),
                [id],
                |r| Ok((device_from_row(r)?, r.get::<_, Vec<u8>>(12)?)),
            )
            .optional()?)
        })?;
        // Always do the same work: decode, hash, compare against either the stored hash or a dummy.
        let raw = b64url_decode(presented_token)
            .ok()
            .filter(|r| r.len() == SECRET_LEN);
        let presented_hash = raw.as_deref().map(token_hash).unwrap_or([0u8; 32]);
        let dummy = [0xA5u8; 32];
        let stored: &[u8] = match &row {
            Some((_, h)) if h.len() == 32 => h.as_slice(),
            _ => &dummy,
        };
        let hash_equal: bool = presented_hash.ct_eq(stored).into();
        let well_formed = raw.is_some() && row.as_ref().is_some_and(|(_, h)| h.len() == 32);
        if !(hash_equal && well_formed) {
            return Ok(AuthOutcome::Failed);
        }
        match row {
            Some((rec, _)) if rec.revoked_at.is_some() => Ok(AuthOutcome::Revoked),
            Some((rec, _)) => Ok(AuthOutcome::Ok(rec)),
            None => Ok(AuthOutcome::Failed),
        }
    }

    /// Records `last_seen_at` and the masked source address.
    pub fn touch_seen(&self, device_id: &str, ip_masked: Option<&str>) -> Result<(), DeviceError> {
        let (id, ip, now) = (
            device_id.to_owned(),
            ip_masked.map(str::to_owned),
            self.now(),
        );
        self.store.run(move |c| {
            c.execute(
                "UPDATE devices SET last_seen_at=?1, last_ip_masked=COALESCE(?2, last_ip_masked) WHERE device_id=?3",
                params![now, ip, id],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    /// Raises `last_acked_seq` (never lowers it).
    pub fn set_last_acked(&self, device_id: &str, seq: i64) -> Result<(), DeviceError> {
        let id = device_id.to_owned();
        self.store.run(move |c| {
            c.execute(
                "UPDATE devices SET last_acked_seq=?1 WHERE device_id=?2 AND last_acked_seq < ?1",
                params![seq, id],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    /// Revokes a device (`revoked_at` + reason). Irreversible. Returns `false` if the device does not exist or was
    /// already revoked.
    pub fn revoke(&self, device_id: &str, reason: &str) -> Result<bool, DeviceError> {
        let (id, reason, now) = (device_id.to_owned(), reason.to_owned(), self.now());
        Ok(self.store.run(move |c| {
            Ok(c.execute(
                "UPDATE devices SET revoked_at=?1, revoked_reason=?2 WHERE device_id=?3 AND revoked_at IS NULL",
                params![now, reason, id],
            )? == 1)
        })?)
    }

    /// Revokes active devices that have not connected for `days` days (`revoked_reason = inactive_90d`, an opt-in
    /// maintenance step). Returns the revoked ids.
    pub fn revoke_inactive(&self, days: i64) -> Result<Vec<String>, DeviceError> {
        let now_ms = self.clock.now_ms();
        let cutoff = format_ms(now_ms - days * 86_400_000);
        let now = format_ms(now_ms);
        Ok(self.store.run(move |c| {
            let mut stmt = c.prepare(
                "UPDATE devices SET revoked_at=?1, revoked_reason='inactive_90d' \
                 WHERE revoked_at IS NULL AND COALESCE(last_seen_at, paired_at) < ?2 RETURNING device_id",
            )?;
            let ids = stmt
                .query_map(params![now, cutoff], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ids)
        })?)
    }

    /// Registers a device outside a pairing transaction (tests and tools). Production pairing uses the transaction in
    /// `auth::pairing`.
    pub fn register(&self, new: NewDevice) -> Result<IssuedDevice, DeviceError> {
        let now = self.now();
        let result = self.store.run(move |c| {
            let tx = c.transaction()?;
            let issued = insert_device_tx(&tx, &new, &now);
            match issued {
                Ok(i) => {
                    tx.commit()?;
                    Ok(Ok(i))
                }
                Err(e) => Ok(Err(e)),
            }
        })?;
        result
    }

    /// Async wrapper: runs `f` on the blocking pool.
    pub async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&DeviceRegistry) -> T + Send + 'static,
    ) -> T {
        let me = self.clone();
        match tokio::task::spawn_blocking(move || f(&me)).await {
            Ok(v) => v,
            // The closure panicked: propagate (the join error carries the panic).
            Err(e) => std::panic::resume_unwind(e.into_panic()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::timers::ManualClock;

    fn registry() -> (DeviceRegistry, Arc<ManualClock>, Store) {
        let store = Store::open_in_memory().unwrap();
        let clock = Arc::new(ManualClock::new(1_792_055_553_120));
        (
            DeviceRegistry::new(store.clone(), clock.clone()),
            clock,
            store,
        )
    }

    fn phone(name: &str) -> NewDevice {
        NewDevice {
            name: name.into(),
            platform: "android".into(),
            model: Some("SM-S938N".into()),
            os_version: Some("16".into()),
            app_version: Some("0.1.0".into()),
            pubkey_spki_der: None,
        }
    }

    #[test]
    fn only_the_hash_of_the_token_is_stored() {
        let (reg, _clock, store) = registry();
        let issued = reg.register(phone("Galaxy")).unwrap();
        assert!(issued.device_id.starts_with("dev_"));
        assert_eq!(issued.device_id.len(), 4 + 32);
        let token_text = issued.token.expose().to_owned();
        let raw = b64url_decode(&token_text).unwrap();
        assert_eq!(raw.len(), 32);
        let (hash, all_text): (Vec<u8>, String) = store
            .read(|c| {
                let hash: Vec<u8> = c.query_row("SELECT token_hash FROM devices", [], |r| r.get(0))?;
                // dump every text column of the row
                let text: String = c.query_row(
                    "SELECT device_id||name||platform||IFNULL(model,'')||IFNULL(os_version,'')||IFNULL(app_version,'') FROM devices",
                    [],
                    |r| r.get(0),
                )?;
                Ok((hash, text))
            })
            .unwrap();
        assert_eq!(hash, token_hash(&raw).to_vec());
        assert_ne!(hash, raw, "the raw token is not stored");
        assert!(!all_text.contains(&token_text));
        assert!(!format!("{issued:?}").contains(&token_text));
    }

    #[test]
    fn authenticate_accepts_the_issued_token_and_nothing_else() {
        let (reg, _c, _s) = registry();
        let issued = reg.register(phone("Galaxy")).unwrap();
        let good = issued.token.expose().to_owned();
        assert!(matches!(
            reg.authenticate(&issued.device_id, &good).unwrap(),
            AuthOutcome::Ok(d) if d.name == "Galaxy"
        ));
        // wrong token (flip the last char), malformed, empty, wrong length
        let mut bad = good.clone();
        bad.pop();
        bad.push(if good.ends_with('A') { 'B' } else { 'A' });
        for t in [bad.as_str(), "", "!!!", "AAAA", &good[..10]] {
            assert_eq!(
                reg.authenticate(&issued.device_id, t).unwrap(),
                AuthOutcome::Failed,
                "{t}"
            );
        }
        // unknown device with a well formed token
        assert_eq!(
            reg.authenticate("dev_unknown", &good).unwrap(),
            AuthOutcome::Failed
        );
        // a token of another device does not work for this one
        let other = reg.register(phone("Pixel")).unwrap();
        assert_eq!(
            reg.authenticate(&issued.device_id, other.token.expose())
                .unwrap(),
            AuthOutcome::Failed
        );
    }

    #[test]
    fn revocation_is_immediate_and_final() {
        let (reg, _c, _s) = registry();
        let issued = reg.register(phone("Galaxy")).unwrap();
        let tok = issued.token.expose().to_owned();
        assert!(reg.is_active(&issued.device_id));
        assert!(reg.revoke(&issued.device_id, "user_desktop").unwrap());
        assert!(!reg.is_active(&issued.device_id));
        assert_eq!(
            reg.authenticate(&issued.device_id, &tok).unwrap(),
            AuthOutcome::Revoked
        );
        // revoked devices only reveal "revoked" to the holder of a valid token
        assert_eq!(
            reg.authenticate(&issued.device_id, "AAAA").unwrap(),
            AuthOutcome::Failed
        );
        // second revoke is a no-op, the reason is kept
        assert!(!reg.revoke(&issued.device_id, "user_phone").unwrap());
        let rec = reg.get(&issued.device_id).unwrap().unwrap();
        assert_eq!(rec.revoked_reason.as_deref(), Some("user_desktop"));
        assert!(rec.revoked_at.is_some());
        assert!(!rec.is_active());
        assert!(!reg.revoke("dev_nope", "x").unwrap());
    }

    #[test]
    fn list_touch_and_acked_bookkeeping() {
        let (reg, clock, _s) = registry();
        let a = reg.register(phone("A")).unwrap();
        clock.advance(1_000);
        let b = reg.register(phone("B")).unwrap();
        let list = reg.list().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].device_id, b.device_id, "newest first");
        reg.touch_seen(&a.device_id, Some("192.168.0.x")).unwrap();
        let rec = reg.get(&a.device_id).unwrap().unwrap();
        assert_eq!(rec.last_ip_masked.as_deref(), Some("192.168.0.x"));
        assert!(rec.last_seen_at.is_some());
        reg.set_last_acked(&a.device_id, 40).unwrap();
        reg.set_last_acked(&a.device_id, 30).unwrap();
        assert_eq!(reg.get(&a.device_id).unwrap().unwrap().last_acked_seq, 40);
    }

    #[test]
    fn the_same_phone_key_can_be_paired_again_only_after_revocation() {
        let (reg, _c, _s) = registry();
        let mut new = phone("Galaxy");
        new.pubkey_spki_der = Some(vec![1, 2, 3, 4]);
        let first = reg.register(new.clone()).unwrap();
        assert!(matches!(
            reg.register(new.clone()),
            Err(DeviceError::DuplicateKey)
        ));
        reg.revoke(&first.device_id, "user_desktop").unwrap();
        let second = reg.register(new).unwrap();
        assert_ne!(first.device_id, second.device_id);
        assert!(reg.is_active(&second.device_id));
        assert!(!reg.is_active(&first.device_id));
    }

    #[test]
    fn inactive_devices_are_revoked_after_the_configured_days() {
        let (reg, clock, _s) = registry();
        let a = reg.register(phone("A")).unwrap();
        clock.advance(91 * 86_400_000);
        let b = reg.register(phone("B")).unwrap();
        let revoked = reg.revoke_inactive(90).unwrap();
        assert_eq!(revoked, vec![a.device_id.clone()]);
        assert!(!reg.is_active(&a.device_id));
        assert!(reg.is_active(&b.device_id));
        assert_eq!(
            reg.get(&a.device_id)
                .unwrap()
                .unwrap()
                .revoked_reason
                .as_deref(),
            Some("inactive_90d")
        );
    }

    #[test]
    fn generated_tokens_are_unique_and_32_bytes() {
        let (t1, h1) = generate_token().unwrap();
        let (t2, h2) = generate_token().unwrap();
        assert_ne!(t1.expose(), t2.expose());
        assert_ne!(h1, h2);
        assert_eq!(b64url_decode(t1.expose()).unwrap().len(), 32);
        assert_eq!(format!("{t1:?}"), "<redacted>");
    }
}
