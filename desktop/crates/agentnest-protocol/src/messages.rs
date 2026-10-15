//! Payload structs of the wire messages (protocol.md 4). 1:1 with `protocol/schema/c2s/*` and `s2c/*`.
//!
//! `event`, `session_state` and `approval_request` use [`AgentEvent`], [`SessionState`] and
//! [`ApprovalRequest`] directly as payloads.

use serde::{Deserialize, Serialize};

use crate::enums::{
    AdapterMode, AdapterStatusKind, AgentKind, AgentState, ApprovalOutcome, AuthMethod, ByeReason,
    Decision, DecisionResultReason, Delivery, ErrorCode, ExtraConfirmationMethod, ObservedResult,
    ResolvedBy, ResyncMode,
};
use crate::model::{AgentEvent, ApprovalRequest, SessionState};
use crate::secret::Secret;

// ---------------------------------------------------------------- phone -> PC

/// Device description sent in `pair`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device name (NFC, <= 64 UTF-8 bytes; it is part of the pairing proof).
    pub name: String,
    /// `android`.
    pub platform: String,
    /// Hardware model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// OS version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// App version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
}

/// `pair` (phone -> PC): QR secret possession proof plus device key registration (protocol.md 4.2).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PairPayload {
    /// `p_...` from the QR.
    pub pairing_id: String,
    /// Echo of the server challenge, base64 of 16 bytes.
    pub challenge_b64: String,
    /// Device info.
    pub device: DeviceInfo,
    /// Phone EC P-256 public key, X.509 SPKI DER, base64. Stored only (Phase 3 signatures).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_pubkey_spki_b64: Option<String>,
    /// `HMAC-SHA256(pairing_secret, canonical_pair_bytes)`, base64 of 32 bytes.
    pub proof_b64: Secret,
    /// Client protocol major.
    pub protocol: u32,
}

/// `hello` (phone -> PC): authenticate a registered device (protocol.md 4.4).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HelloPayload {
    /// `dev_...`.
    pub device_id: String,
    /// Device token, base64url of 32 bytes.
    pub device_token: Secret,
    /// Echo of the server challenge.
    pub challenge_b64: String,
    /// Client protocol major.
    pub protocol: u32,
    /// App version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    /// Last applied seq (0 if none).
    pub last_seq: i64,
    /// Ask for a snapshot regardless of `last_seq`.
    #[serde(default)]
    pub wants_snapshot: bool,
    /// Phase 3 signature; ignored by Phase 1 servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_b64: Option<Secret>,
}

/// `ack` (phone -> PC).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AckPayload {
    /// Everything up to this seq was received.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub through_seq: Option<i64>,
    /// Approval cards that were received.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_ids: Vec<String>,
}

/// `ping` (phone -> PC).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PingPayload {
    /// Send time.
    pub sent_at: String,
}

/// `snapshot_request` (phone -> PC).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SnapshotRequestPayload {
    /// Why (`pull_to_refresh`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `events_request` (phone -> PC; protocol.md 4.15).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventsRequestPayload {
    /// Restrict to one session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_key: Option<String>,
    /// Exclusive upper bound (`seq < before_seq`).
    pub before_seq: i64,
    /// 1..=100; larger values are clamped by the server.
    pub limit: u32,
    /// Restrict to these kinds (<= 16; unknown values are ignored).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
}

/// Biometric / device-credential claim attached to a decision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DecisionAuth {
    /// Method.
    pub method: AuthMethod,
    /// When the user authenticated (phone clock, skew-corrected).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated_at: Option<String>,
}

/// Extra confirmation the user completed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExtraConfirmationProof {
    /// Method.
    pub method: ExtraConfirmationMethod,
    /// Completed.
    pub completed: bool,
}

/// `decision` (phone -> PC; protocol.md 4.10). The four binding fields are echoed from the `approval_request`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DecisionPayload {
    /// Binding: request id.
    pub request_id: String,
    /// Binding: session key.
    pub session_key: String,
    /// Binding: nonce echo.
    pub nonce_b64: Secret,
    /// Binding: input hash echo.
    pub tool_input_sha256: String,
    /// The decision. Closed set; no scope-expanding values.
    pub decision: Decision,
    /// Deny reason (<= 200 chars); sanitised by the PC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Phone time (skew-corrected).
    pub decided_at: String,
    /// Authentication claim (not proof in Phase 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<DecisionAuth>,
    /// Extra confirmation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_confirmation: Option<ExtraConfirmationProof>,
    /// Phase 3 signature; ignored in Phase 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_b64: Option<Secret>,
}

/// `approval_seen` (phone -> PC).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovalSeenPayload {
    /// Request id.
    pub request_id: String,
    /// When the card was shown.
    pub seen_at: String,
}

/// `unpair` (phone -> PC): exactly one of `device_id` (registered device) or `pairing_id` (abort during `PairPending`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct UnpairPayload {
    /// Registered device to remove.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Pairing to abort.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_id: Option<String>,
}

// ---------------------------------------------------------------- PC -> phone

/// `challenge` (PC -> phone): the only `PreAuth` server frame.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChallengePayload {
    /// 16 random bytes, base64.
    pub challenge_b64: String,
    /// `pc_...`.
    pub pc_id: String,
    /// Server time.
    pub server_time: String,
    /// Time to send a valid `pair`/`hello`.
    pub expires_in_ms: u32,
}

/// `pair_pending` (PC -> phone).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PairPendingPayload {
    /// Pairing id.
    pub pairing_id: String,
    /// 6-digit SAS. The phone computes its own value and compares; it must not display this one.
    pub sas: String,
    /// Time the PC user has to confirm.
    pub confirm_timeout_ms: u32,
}

/// PC identity sent after a successful pairing and in `welcome`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PcInfo {
    /// `pc_...`.
    pub pc_id: String,
    /// PC name.
    pub name: String,
    /// App version.
    pub app_version: String,
    /// `windows`, ...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
}

/// `pair_result` (PC -> phone).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PairResultPayload {
    /// Outcome.
    pub ok: bool,
    /// Device id (success).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Device token, sent exactly once (success).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_token: Option<Secret>,
    /// PC info (success).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pc: Option<PcInfo>,
    /// `E_PAIR_FAILED` | `E_PAIR_REJECTED` | `E_PAIR_BUSY` (failure).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<ErrorCode>,
}

/// Protocol versions in `welcome`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProtocolInfo {
    /// Major.
    pub version: u32,
    /// Minor (additive changes).
    pub minor: u32,
    /// Oldest supported app version.
    pub min_client_version: String,
}

/// PC addresses.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Hosts {
    /// Non-loopback addresses.
    pub addresses: Vec<String>,
    /// Port.
    pub port: u16,
}

/// Heartbeat settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Phone ping interval.
    pub client_ping_interval_s: u32,
    /// Server idle close.
    pub server_idle_close_s: u32,
}

/// Resynchronisation instruction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resync {
    /// Mode.
    pub mode: ResyncMode,
    /// First replayed seq (replay).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_seq: Option<i64>,
    /// Last replayed seq (replay).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_seq: Option<i64>,
}

/// Size limits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Effective approval TTL.
    pub approval_ttl_s: u32,
    /// Frame limit.
    pub max_frame_bytes: u32,
    /// Snapshot budget.
    pub snapshot_max_bytes: u32,
    /// Events page budget.
    pub events_page_max_bytes: u32,
}

/// Remote approval policy for high risk levels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteApprovalPolicy {
    /// `extra_confirmation` | `local_only`.
    pub critical: String,
    /// `hold`.
    pub high: String,
}

/// Policy sent to the phone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Remote approval policy.
    pub remote_approval: RemoteApprovalPolicy,
    /// Owned by PC settings; the phone shows it read-only.
    pub deny_requires_auth: bool,
}

/// `welcome` (PC -> phone).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WelcomePayload {
    /// PC info.
    pub pc: PcInfo,
    /// Versions.
    pub protocol: ProtocolInfo,
    /// Addresses.
    pub hosts: Hosts,
    /// Open capability set.
    pub capabilities: Vec<String>,
    /// Server time.
    pub server_time: String,
    /// Heartbeat.
    pub heartbeat: Heartbeat,
    /// Resync.
    pub resync: Resync,
    /// Limits.
    pub limits: Limits,
    /// Policy.
    pub policy: Policy,
}

/// `adapter_status` payload and `snapshot.adapters[]` entry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AdapterStatus {
    /// Agent family.
    pub agent_kind: AgentKind,
    /// Health.
    pub status: AdapterStatusKind,
    /// Mode.
    pub mode: AdapterMode,
    /// Human readable detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Update time.
    pub updated_at: String,
}

/// Currently focused session.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Focus {
    /// Session key.
    pub session_key: String,
    /// Its state.
    pub state: AgentState,
}

/// Which parts of a snapshot were cut (protocol.md 4.6).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SnapshotTruncated {
    /// Sessions dropped.
    pub sessions: bool,
    /// Pending approvals moved to follow-up frames.
    pub pending_approvals: bool,
    /// Recent events reduced.
    pub recent_events: bool,
    /// Event `detail` removed.
    pub recent_events_detail: bool,
    /// Approval previews removed.
    pub approval_previews: bool,
}

/// `snapshot` (PC -> phone). Replaces the stream up to the envelope `seq`; does not consume a seq.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SnapshotPayload {
    /// Sessions (<= 20).
    pub sessions: Vec<SessionState>,
    /// Pending approvals that fit (<= 20, unexpired only).
    pub pending_approvals: Vec<ApprovalRequest>,
    /// Recent warnings/errors (<= 5).
    pub recent_errors: Vec<AgentEvent>,
    /// Recent events (<= 50, seq ascending).
    pub recent_events: Vec<AgentEvent>,
    /// Adapter health.
    pub adapters: Vec<AdapterStatus>,
    /// Focused session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub focus: Option<Focus>,
    /// Every pending approval id, regardless of truncation.
    pub pending_approval_ids_complete: Vec<String>,
    /// Number of approval cards that follow as separate `approval_request` frames.
    pub pending_followup: u32,
    /// Truncation flags.
    pub truncated: SnapshotTruncated,
}

/// `approval_resolved` (PC -> phone; re-sent with the same `request_id` when `observed_result` changes).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovalResolvedPayload {
    /// Request id.
    pub request_id: String,
    /// Session key.
    pub session_key: String,
    /// Outcome.
    pub outcome: ApprovalOutcome,
    /// Who resolved it.
    pub resolved_by: ResolvedBy,
    /// Device that resolved it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_device_id: Option<String>,
    /// When.
    pub resolved_at: String,
    /// Whether the reply reached the agent.
    pub delivery: Delivery,
    /// Later observation.
    pub observed_result: ObservedResult,
    /// Korean one-liner.
    pub message_ko: String,
}

/// `decision_result` (PC -> phone).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DecisionResultPayload {
    /// Request id.
    pub request_id: String,
    /// Envelope id of the `decision`.
    pub in_reply_to: String,
    /// Whether the decision was applied.
    pub accepted: bool,
    /// Result code.
    pub reason: DecisionResultReason,
    /// Korean text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_ko: Option<String>,
}

/// `events_page` (PC -> phone).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventsPagePayload {
    /// Envelope id of the `events_request`.
    pub in_reply_to: String,
    /// Events, seq ascending.
    pub events: Vec<AgentEvent>,
    /// More pages exist.
    pub has_more: bool,
    /// Pass this as the next `before_seq`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_before_seq: Option<i64>,
    /// `detail` was removed to fit the budget.
    #[serde(default)]
    pub detail_omitted: bool,
}

/// `hosts_update` (PC -> phone).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostsUpdatePayload {
    /// Addresses.
    pub addresses: Vec<String>,
    /// Port.
    pub port: u16,
}

/// `pong` (PC -> phone).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PongPayload {
    /// Envelope id of the `ping`.
    pub in_reply_to: String,
    /// Server time.
    pub server_time: String,
}

/// `error` (PC -> phone).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorPayload {
    /// Code.
    pub code: ErrorCode,
    /// English message for logs.
    pub message: String,
    /// Korean message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_ko: Option<String>,
    /// Envelope id of the offending request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    /// The connection will be closed.
    #[serde(default)]
    pub fatal: bool,
}

/// `bye` (PC -> phone).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ByePayload {
    /// Reason.
    pub reason: ByeReason,
    /// Whether the phone should reconnect.
    pub reconnect: bool,
    /// Korean text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_ko: Option<String>,
}
