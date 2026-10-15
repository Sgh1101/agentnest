//! QR pairing payload (security.md 4.1) and the server identity derivations.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::canonical::sha256;
use crate::error::CanonicalError;
use crate::limits::SECRET_LEN;
use crate::secret::Secret;

/// URI scheme/host/path prefix of the QR content.
pub const PAIR_URI_PREFIX: &str = "agentnest://pair?d=";

/// `spki_pin` = `"sha256/" + base64(SHA-256(DER SubjectPublicKeyInfo))` (OkHttp pin format).
pub fn spki_pin(spki_der: &[u8]) -> String {
    format!("sha256/{}", STANDARD.encode(sha256(spki_der)))
}

/// `pc_id` = `"pc_" + first 8 bytes of SHA-256(SPKI)` as lowercase hex.
pub fn pc_id_from_spki(spki_der: &[u8]) -> String {
    format!("pc_{}", hex::encode(&sha256(spki_der)[..8]))
}

/// Decodes standard base64 (with padding).
pub fn b64_decode(text: &str) -> Result<Vec<u8>, CanonicalError> {
    STANDARD.decode(text).map_err(|_| CanonicalError::BadBase64)
}

/// Encodes standard base64 (with padding).
pub fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decodes base64url without padding.
pub fn b64url_decode(text: &str) -> Result<Vec<u8>, CanonicalError> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| CanonicalError::BadBase64)
}

/// Encodes base64url without padding.
pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The JSON carried by the QR code as `agentnest://pair?d=<base64url(JSON)>`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PairingPayload {
    /// Always 1.
    pub v: u32,
    /// `pc_...`, must equal the first 8 bytes of the SPKI hash in `spki_pin`.
    pub pc_id: String,
    /// PC name.
    pub pc_name: String,
    /// 1..=8 PC addresses.
    pub hosts: Vec<String>,
    /// WSS port.
    pub port: u16,
    /// `sha256/<base64>` SPKI pin.
    pub spki_pin: String,
    /// `p_...`.
    pub pairing_id: String,
    /// base64url of 32 random bytes. Never goes over the wire.
    pub pairing_secret: Secret,
    /// Expiry (120 s after creation).
    pub expires_at: String,
}

impl PairingPayload {
    /// The raw 32-byte pairing secret (HMAC key).
    pub fn pairing_secret_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        let bytes = b64url_decode(self.pairing_secret.expose())?;
        if bytes.len() != SECRET_LEN {
            return Err(CanonicalError::BadLength);
        }
        Ok(bytes)
    }

    /// The QR content.
    pub fn to_uri(&self) -> Result<String, CanonicalError> {
        let json = serde_json::to_vec(self).map_err(|_| CanonicalError::BadUri)?;
        Ok(format!("{PAIR_URI_PREFIX}{}", b64url_encode(&json)))
    }

    /// Parses the QR content (structure only; expiry, pin format and `pc_id` consistency are checked by the caller).
    pub fn from_uri(uri: &str) -> Result<Self, CanonicalError> {
        let data = uri
            .strip_prefix(PAIR_URI_PREFIX)
            .ok_or(CanonicalError::BadUri)?;
        let json = b64url_decode(data)?;
        serde_json::from_slice(&json).map_err(|_| CanonicalError::BadUri)
    }

    /// `true` if `pc_id` matches the SPKI hash inside `spki_pin` (QR vs `challenge.pc_id` consistency, security.md 4.1).
    pub fn pc_id_matches_pin(&self) -> bool {
        let Some(b64) = self.spki_pin.strip_prefix("sha256/") else {
            return false;
        };
        let Ok(hash) = STANDARD.decode(b64) else {
            return false;
        };
        hash.len() == 32 && self.pc_id == format!("pc_{}", hex::encode(&hash[..8]))
    }
}
