//! What adapters emit.

use std::collections::BTreeMap;
use std::fmt;

use agentnest_protocol::{
    AgentEvent, AgentKind, Decision, ObservedResult, ProjectRef, RemoteApproval, SourceChannel,
};
use serde::{Deserialize, Serialize};

use crate::adapter::AdapterHealth;
use crate::responder::ApprovalResponder;

/// Identifies the native request an approval is bound to, and the native ids used for outcome correlation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeBinding {
    /// Agent family.
    pub agent_kind: AgentKind,
    /// Native session id (`session_id` for Claude Code, `thread.id` for Codex).
    pub native_session_id: String,
    /// claude_code: `{"tool_name","tool_input_sha256","prompt_id"?}`; codex: `{"rpc_id","thread_id","turn_id","item_id","approval_id"?,"kind"}`.
    /// Persisted as `approvals.native_binding_json`.
    pub ids: BTreeMap<String, String>,
}

/// Why the agent closed an approval request on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AgentCloseReason {
    /// The agent resolved it (Codex `serverRequest/resolved`, local dialog answered).
    ResolvedByAgent,
    /// The connection to the agent was lost.
    ConnectionClosed,
    /// The agent cancelled the request.
    Cancelled,
    /// The thread/session ended.
    SessionEnded,
}

/// An adapter's description of an approval request. The broker turns it into an `ApprovalRequest`
/// (hash, nonce, risk, summaries, TTL).
///
/// The raw `tool_input` lives in memory only (never persisted, never logged); `Debug` hides it.
#[derive(Clone)]
pub struct ApprovalDraft {
    /// Native request binding.
    pub binding: NativeBinding,
    /// `<agent_kind>:<native_session_id>`.
    pub session_key: String,
    /// Agent family.
    pub agent_kind: AgentKind,
    /// Sub-agent id, used to decide whether two near-simultaneous requests may be merged into one card.
    pub agent_id: Option<String>,
    /// Project resolved from `cwd`.
    pub project: Option<ProjectRef>,
    /// Raw working directory (PC only).
    pub cwd: Option<String>,
    /// Tool name.
    pub tool_name: String,
    /// Raw tool input; hashed and classified by the broker.
    pub tool_input: serde_json::Value,
    /// Where it came from.
    pub origin: SourceChannel,
    /// Agent permission mode.
    pub permission_mode: Option<String>,
    /// Decisions the native protocol can express. The broker intersects this with its own rules (e.g. Codex hooks never
    /// offer `deny_and_stop`).
    pub available_decisions: Vec<Decision>,
    /// Number of `permission_suggestions` (the suggestions are never forwarded).
    pub permission_suggestions_count: Option<u32>,
    /// Agent-written description (unverified).
    pub agent_description: Option<String>,
    /// Agent-provided reason (Codex).
    pub reason: Option<String>,
    /// Observation time (RFC 3339 UTC).
    pub created_at: String,
}

impl fmt::Debug for ApprovalDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalDraft")
            .field("session_key", &self.session_key)
            .field("agent_kind", &self.agent_kind)
            .field("tool_name", &self.tool_name)
            .field("tool_input_len", &self.tool_input.to_string().len())
            .field("origin", &self.origin)
            .field("available_decisions", &self.available_decisions)
            .finish_non_exhaustive()
    }
}

/// Patch of session metadata (statusline data, Codex thread name, ...). `None` fields are left unchanged.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SessionMetaPatch {
    /// Session title.
    pub title: Option<String>,
    /// Model.
    pub model: Option<String>,
    /// Cost in USD.
    pub cost_usd: Option<f64>,
    /// Context window usage in percent.
    pub context_used_pct: Option<u32>,
    /// Pull request number.
    pub pr_number: Option<u64>,
    /// Pull request URL.
    pub pr_url: Option<String>,
    /// Permission mode.
    pub permission_mode: Option<String>,
    /// Whether remote approval is possible for this session.
    pub remote_approval: Option<RemoteApproval>,
}

/// Everything an adapter can report.
#[allow(clippy::large_enum_variant)]
pub enum RawObservation {
    /// A normalised event (the broker/normaliser adds `seq`, summaries and masking).
    Event(AgentEvent),
    /// An approval request opened by the agent, with the handle to answer it.
    ApprovalOpened {
        /// Description of the request.
        draft: ApprovalDraft,
        /// Answers or abandons the request.
        responder: Box<dyn ApprovalResponder>,
    },
    /// The agent closed an approval request itself.
    ApprovalClosedByAgent {
        /// Which request.
        binding: NativeBinding,
        /// Why.
        reason: AgentCloseReason,
    },
    /// Later evidence of what happened to an approved/denied tool call (`approval_resolved.observed_result`).
    ApprovalOutcomeObserved {
        /// Which request.
        binding: NativeBinding,
        /// What was observed.
        observed: ObservedResult,
        /// UUIDv7 of the event that serves as evidence.
        evidence_event_id: String,
    },
    /// Session metadata update.
    SessionMeta {
        /// Session key.
        session_key: String,
        /// Changes.
        patch: SessionMetaPatch,
    },
    /// Adapter health change.
    Health(AdapterHealth),
}

impl fmt::Debug for RawObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RawObservation::Event(e) => f.debug_tuple("Event").field(&e.kind).finish(),
            RawObservation::ApprovalOpened { draft, .. } => f
                .debug_struct("ApprovalOpened")
                .field("draft", draft)
                .finish_non_exhaustive(),
            RawObservation::ApprovalClosedByAgent { binding, reason } => f
                .debug_struct("ApprovalClosedByAgent")
                .field("binding", binding)
                .field("reason", reason)
                .finish(),
            RawObservation::ApprovalOutcomeObserved {
                binding,
                observed,
                evidence_event_id,
            } => f
                .debug_struct("ApprovalOutcomeObserved")
                .field("binding", binding)
                .field("observed", observed)
                .field("evidence_event_id", evidence_event_id)
                .finish(),
            RawObservation::SessionMeta { session_key, patch } => f
                .debug_struct("SessionMeta")
                .field("session_key", session_key)
                .field("patch", patch)
                .finish(),
            RawObservation::Health(h) => f.debug_tuple("Health").field(h).finish(),
        }
    }
}
