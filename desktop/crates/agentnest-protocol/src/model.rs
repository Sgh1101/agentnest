//! Normalised models (protocol.md 5, 6.1). 1:1 with `protocol/schema/model/*.schema.json`.
//!
//! Serde conventions: optional fields are omitted when `None` and accepted as `null` or absent on read; unknown
//! fields are ignored on read; timestamps are kept as RFC 3339 strings exactly as sent.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::enums::{
    AgentKind, AgentState, CommandClass, Decision, DetailsKind, EventCategory, EventKind,
    ExtraConfirmation, FileOp, LocalPrompt, RemoteApproval, ReviewState, RiskLevel, Severity,
    SourceChannel, TestStatus,
};
use crate::secret::Secret;

/// Project reference attached to events, sessions and approvals.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProjectRef {
    /// Lowercase, `/`-normalised path key.
    pub project_key: String,
    /// Display name.
    pub name: String,
    /// Last two path segments only (the full path never leaves the PC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_hint: Option<String>,
    /// `owner/name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// Git branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
}

/// Sub-agent / teammate context of an event.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Actor {
    /// Native agent id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Native agent type (`Explore`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<String>,
    /// `true` for sub-agents.
    #[serde(default)]
    pub is_subagent: bool,
}

/// Korean one-liner built by the PC (`headline <= 40`, `detail <= 200` characters).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventSummary {
    /// Headline.
    pub headline: String,
    /// Optional longer text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Provenance of an event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventSource {
    /// Collection channel.
    pub channel: SourceChannel,
    /// Native event name (`PreToolUse`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_event: Option<String>,
    /// Original identifiers used for correlation and de-duplication.
    #[serde(default)]
    pub native_ids: BTreeMap<String, String>,
}

/// Normalised agent event (protocol.md 5.1).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentEvent {
    /// UUIDv7.
    pub event_id: String,
    /// PC-global sequence number; `None` until the stream assigns one, always present on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<i64>,
    /// Event time (RFC 3339 UTC).
    pub ts: String,
    /// Agent family.
    pub agent_kind: AgentKind,
    /// `<agent_kind>:<native_session_id>`.
    pub session_key: String,
    /// Sub-agent context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,
    /// Project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<ProjectRef>,
    /// Event kind.
    pub kind: EventKind,
    /// Event category.
    pub category: EventCategory,
    /// Severity.
    pub severity: Severity,
    /// Korean summary.
    pub summary: EventSummary,
    /// Suggested state (reducer input).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_hint: Option<AgentState>,
    /// Kind-specific bounded object (<= 8 KiB; never file bodies, full stdout or prompts).
    pub detail: serde_json::Value,
    /// Provenance.
    pub source: EventSource,
    /// `true` if masking happened.
    #[serde(default)]
    pub redacted: bool,
}

/// Turn information of a session.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TurnInfo {
    /// A turn is running.
    #[serde(default)]
    pub active: bool,
    /// Turn start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    /// Turn end (reset by a new prompt).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    /// Masked prompt preview (<= 200 chars).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_preview: Option<String>,
}

/// Activity counters of a session.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Counters {
    /// Tool calls.
    pub tools: u32,
    /// Modified files.
    pub files_modified: u32,
    /// Commands.
    pub commands: u32,
    /// Test runs.
    pub tests: u32,
    /// Errors.
    pub errors: u32,
}

/// One entry of `recent_files`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecentFile {
    /// Last two path segments.
    pub path_hint: String,
    /// Operation.
    pub op: FileOp,
    /// Time.
    pub at: String,
}

/// One entry of `recent_commands`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecentCommand {
    /// Masked command, <= 80 chars.
    pub command_preview: String,
    /// Command class.
    pub command_class: CommandClass,
    /// Exit code once completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Time.
    pub at: String,
}

/// Last test run of a session.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LastTest {
    /// Status.
    pub status: TestStatus,
    /// Always `test`.
    pub command_class: CommandClass,
    /// Runner (`cargo`, `pytest`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner: Option<String>,
    /// Time.
    pub at: String,
}

/// Review counters.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReviewMeta {
    /// P0 findings.
    pub p0: u32,
    /// P1 findings.
    pub p1: u32,
    /// State.
    pub state: ReviewState,
}

/// Session metadata.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SessionMeta {
    /// Session title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Cost in USD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    /// Context window usage in percent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_used_pct: Option<u32>,
    /// Pull request number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr_number: Option<u64>,
    /// Pull request URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr_url: Option<String>,
    /// Review counters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<ReviewMeta>,
}

impl SessionMeta {
    /// `true` if no field is set (such a meta is omitted on the wire).
    pub fn is_empty(&self) -> bool {
        *self == SessionMeta::default()
    }
}

/// Derived per-session state (protocol.md 5.3).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionState {
    /// Session key.
    pub session_key: String,
    /// Agent family.
    pub agent_kind: AgentKind,
    /// Display label (`Claude Code`, `Codex`).
    pub agent_label: String,
    /// Project.
    pub project: ProjectRef,
    /// Derived state.
    pub state: AgentState,
    /// When the state was entered.
    pub state_since: String,
    /// Korean headline (<= 40 chars).
    pub headline: String,
    /// Korean detail (<= 200 chars).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// First observed event.
    pub started_at: String,
    /// Turn info.
    pub turn: TurnInfo,
    /// Permission mode of the agent session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,
    /// Whether remote approval is possible.
    pub remote_approval: RemoteApproval,
    /// Request ids of pending approvals.
    #[serde(default)]
    pub pending_approval_ids: Vec<String>,
    /// Counters.
    #[serde(default)]
    pub counters: Counters,
    /// Newest first, at most 5.
    #[serde(default)]
    pub recent_files: Vec<RecentFile>,
    /// Newest first, at most 3.
    #[serde(default)]
    pub recent_commands: Vec<RecentCommand>,
    /// Last test run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_test: Option<LastTest>,
    /// Metadata.
    #[serde(default, skip_serializing_if = "SessionMeta::is_empty")]
    pub meta: SessionMeta,
    /// Seq of the last event applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_seq: Option<i64>,
    /// Time of the last event.
    pub last_event_at: String,
    /// Session ended.
    #[serde(default)]
    pub ended: bool,
    /// No events for 15 minutes during an active turn.
    #[serde(default)]
    pub stale: bool,
}

/// Risk classification attached to an approval request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Risk {
    /// Level.
    pub level: RiskLevel,
    /// Reason codes.
    pub reasons: Vec<String>,
    /// Korean reasons.
    pub reasons_ko: Vec<String>,
    /// Required extra confirmation.
    pub extra_confirmation: ExtraConfirmation,
}

/// Display-only details of an approval request (bounded and masked).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovalDetails {
    /// What is shown.
    pub kind: DetailsKind,
    /// Command (<= 2,000 chars).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Working directory hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd_hint: Option<String>,
    /// File paths (<= 50).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_paths: Vec<String>,
    /// Diff preview (<= 4 KiB).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_preview: Option<String>,
    /// Content preview (first 20 lines of a new file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_preview: Option<String>,
    /// MCP server name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<String>,
    /// Agent-provided reason (Codex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `true` if any preview was cut.
    #[serde(default)]
    pub truncated: bool,
    /// Number of `permission_suggestions` (the suggestions themselves are never forwarded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_suggestions_count: Option<u32>,
}

/// Approval card (`approval_request.payload`, `snapshot.pending_approvals[]`; protocol.md 6.1).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// `ar_` + UUIDv7.
    pub request_id: String,
    /// 16-byte CSPRNG nonce, standard base64.
    pub nonce_b64: Secret,
    /// Session key (binding).
    pub session_key: String,
    /// Agent family.
    pub agent_kind: AgentKind,
    /// Display label.
    pub agent_label: String,
    /// Project.
    pub project: ProjectRef,
    /// Where the request came from.
    pub origin: SourceChannel,
    /// Creation time (server clock).
    pub created_at: String,
    /// Expiry (server clock). No decision may be applied at or after this time.
    pub expires_at: String,
    /// Effective TTL in seconds.
    pub ttl_seconds: u32,
    /// Tool name.
    pub tool_name: String,
    /// Fixed Korean title per tool.
    pub title: String,
    /// Agent-written description. Unverified, attacker controllable; shown de-emphasised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Bounded display details.
    pub details: ApprovalDetails,
    /// `SHA-256(canonical JSON(tool_input))`, hex; computed by the PC only.
    pub tool_input_sha256: String,
    /// Risk.
    pub risk: Risk,
    /// Decisions the phone may send.
    pub allowed_decisions: Vec<Decision>,
    /// Decisions that need biometric / device credential.
    pub auth_required_for: Vec<Decision>,
    /// Agent permission mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,
    /// Local prompt visibility.
    pub local_prompt: LocalPrompt,
}

impl ApprovalRequest {
    /// `true` if `decision` is offered by this request (security.md 6.2 step 7).
    pub fn allows(&self, decision: Decision) -> bool {
        self.allowed_decisions.contains(&decision)
    }

    /// `true` if `decision` needs strong authentication (security.md 6.2 step 8).
    pub fn requires_auth(&self, decision: Decision) -> bool {
        self.auth_required_for.contains(&decision)
    }
}
