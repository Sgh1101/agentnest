//! Error types of the protocol crate.

use thiserror::Error;

/// Errors raised while parsing or building protocol frames.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// The frame was not valid JSON.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The envelope `v` is not the supported major version (`E_PROTO_VERSION`).
    #[error("unsupported protocol version {0}")]
    VersionMismatch(i64),
    /// Structurally invalid message (`E_BAD_MESSAGE`).
    #[error("bad message: {0}")]
    BadMessage(String),
}

/// Errors raised by the canonical encodings and pairing crypto helpers.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CanonicalError {
    /// A challenge must be exactly 16 raw bytes.
    #[error("challenge must be exactly 16 bytes")]
    BadChallengeLength,
    /// The device name exceeds 64 UTF-8 bytes.
    #[error("device name exceeds 64 UTF-8 bytes")]
    DeviceNameTooLong,
    /// A length-prefixed field exceeds 65535 bytes.
    #[error("field exceeds u16 length prefix")]
    FieldTooLong,
    /// A base64 value could not be decoded.
    #[error("invalid base64")]
    BadBase64,
    /// A decoded value has an unexpected length.
    #[error("unexpected decoded length")]
    BadLength,
    /// A QR URI could not be parsed.
    #[error("invalid pairing URI")]
    BadUri,
}
