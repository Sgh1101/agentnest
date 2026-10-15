//! Numeric limits and defaults fixed by protocol.md / security.md.

/// Maximum size of a server-to-phone text frame (protocol.md 1).
pub const MAX_FRAME_S2C_BYTES: usize = 256 * 1024;
/// Maximum size of a phone-to-server text frame (protocol.md 1).
pub const MAX_FRAME_C2S_BYTES: usize = 32 * 1024;
/// Default `snapshot` size budget (192 KiB, protocol.md 4.6).
pub const SNAPSHOT_MAX_BYTES: usize = 196_608;
/// Default `events_page` size budget (192 KiB, protocol.md 4.15).
pub const EVENTS_PAGE_MAX_BYTES: usize = 196_608;
/// Loopback hook-collector port (architecture.md 3.3).
pub const HOOK_PORT: u16 = 47831;
/// WSS link port (protocol.md 1).
pub const LINK_PORT: u16 = 47832;
/// WebSocket sub-protocol token (protocol.md 1).
pub const WS_SUBPROTOCOL: &str = "agentnest.v1";
/// Length of `challenge` and `nonce` values in raw bytes.
pub const CHALLENGE_LEN: usize = 16;
/// Length of the pairing secret and of the device token in raw bytes.
pub const SECRET_LEN: usize = 32;
/// Maximum UTF-8 byte length of the device name inside the pairing proof (protocol.md 4.2).
pub const DEVICE_NAME_MAX_BYTES: usize = 64;
/// Maximum number of characters of a user supplied deny reason (protocol.md 4.10).
pub const DECISION_REASON_MAX_CHARS: usize = 200;
/// Default approval TTL in seconds (security.md 6.1).
pub const APPROVAL_TTL_DEFAULT_S: u32 = 120;
/// Largest allowed approval TTL in seconds (security.md 9).
pub const APPROVAL_TTL_MAX_S: u32 = 180;
/// Smallest configurable approval TTL in seconds (security.md 9).
pub const APPROVAL_TTL_MIN_S: u32 = 60;
/// Largest `tool_input` (serialised) that can still be classified without escalating to `critical`.
pub const TOOL_INPUT_MAX_CLASSIFIABLE_BYTES: usize = 64 * 1024;
