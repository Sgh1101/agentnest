//! AgentNest wire protocol v1 (PC <-> phone).
//!
//! Single source of truth is `protocol/schema/**` (JSON Schema draft 2020-12); the types in this crate are
//! 1:1 with those schemas and are checked against `protocol/examples/**` in `tests/`.
//!
//! Layout:
//! * [`frame`]: envelope parsing/serialisation ([`Frame`], [`Message`]).
//! * [`messages`]: payload structs of every wire message type.
//! * [`model`]: normalised models (`AgentEvent`, `SessionState`, `ApprovalRequest`, ...).
//! * [`enums`]: protocol enums. Unknown values of server-to-phone enums are kept as `Unknown(String)`;
//!   the phone-to-server [`Decision`] enum is closed and has **no scope-expanding variant** (security.md I11).
//! * [`canonical`]: RFC 8785 canonical JSON, `tool_input_sha256`, pairing proof (HMAC-SHA256) and SAS, all on `ring`.
//! * [`qr`]: the QR pairing payload and SPKI pin helpers.
//! * [`secret`]: [`Secret`], a redacting, zeroizing, constant-time-comparable string for tokens and nonces.
//!
//! Compatibility rules (protocol.md 2, 10): unknown payload fields are ignored on read (no
//! `deny_unknown_fields`), unknown message `type`s become [`Message::Unknown`], optional fields are omitted
//! (never serialised as `null`) but `null` is accepted on read.

pub mod canonical;
pub mod enums;
pub mod error;
pub mod frame;
pub mod limits;
pub mod messages;
pub mod model;
pub mod qr;
pub mod secret;

pub use enums::*;
pub use error::{CanonicalError, ProtocolError};
pub use frame::{direction_of, is_replayable_type, is_uuid7, Direction, Frame, Message};
pub use messages::*;
pub use model::*;
pub use secret::Secret;

/// Protocol major version carried in every envelope (`v`).
pub const PROTOCOL_VERSION: u32 = 1;
