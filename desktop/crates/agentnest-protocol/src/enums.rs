//! Protocol enums.
//!
//! Two families:
//! * **Open** enums (`open_enum!`): every server-to-phone enum. Known values map to variants, anything else is kept
//!   in `Unknown(String)` and written back unchanged (protocol.md 10). Readers must fail safe on `Unknown`
//!   (see [`RiskLevel::effective`], [`AgentState::effective`]).
//! * **Closed** enums: phone-to-server values whose unknown spelling must be rejected as `E_BAD_MESSAGE`:
//!   [`Decision`], [`AuthMethod`], [`ExtraConfirmationMethod`]. [`Decision`] intentionally has no scope-expanding
//!   variant (`allow_for_session`, `updatedPermissions`, `acceptForSession`, ... do not exist in v1, security.md I11).

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! open_enum {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident => $text:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)+
            /// A value this version does not know. Written back unchanged.
            Unknown(String),
        }

        impl $name {
            /// All wire values known to this version, in schema order.
            pub const KNOWN: &'static [&'static str] = &[$($text),+];

            /// The wire spelling.
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $text,)+
                    Self::Unknown(s) => s.as_str(),
                }
            }

            /// Maps a wire string to a variant (never fails).
            pub fn from_wire(value: &str) -> Self {
                match value {
                    $($text => Self::$variant,)+
                    other => Self::Unknown(other.to_owned()),
                }
            }

            /// `true` if this is an `Unknown` value.
            pub fn is_unknown(&self) -> bool {
                matches!(self, Self::Unknown(_))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                Ok(Self::from_wire(&text))
            }
        }
    };
}

/// An approval decision sent by the phone (protocol.md 4.10). Closed set; deserialising anything else fails.
///
/// There is deliberately no scope-expanding variant such as `allow_for_session`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Allow this single tool call.
    Allow,
    /// Deny this single tool call.
    Deny,
    /// Deny and interrupt the agent.
    DenyAndStop,
}

impl Decision {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::DenyAndStop => "deny_and_stop",
        }
    }
}

/// How the user authenticated on the phone (a claim, not proof, in Phase 1; security.md 6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// Biometric prompt.
    Biometric,
    /// Device credential (PIN/pattern/password).
    DeviceCredential,
    /// No authentication.
    None,
}

impl AuthMethod {
    /// `true` for the methods that satisfy `auth_required_for`.
    pub fn is_strong(self) -> bool {
        matches!(self, AuthMethod::Biometric | AuthMethod::DeviceCredential)
    }
}

/// Extra confirmation the user completed on the phone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtraConfirmationMethod {
    /// Long press (1.5 s).
    Hold,
    /// Long press plus re-confirmation sheet.
    HoldAndReconfirm,
}

/// Agent family. `Other` also absorbs unknown values on read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AgentKind {
    /// Claude Code.
    ClaudeCode,
    /// OpenAI Codex.
    Codex,
    /// Gemini CLI (Phase 4).
    GeminiCli,
    /// OpenCode (Phase 4).
    OpenCode,
    /// Anything else.
    Other,
}

impl AgentKind {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            AgentKind::ClaudeCode => "claude_code",
            AgentKind::Codex => "codex",
            AgentKind::GeminiCli => "gemini_cli",
            AgentKind::OpenCode => "opencode",
            AgentKind::Other => "other",
        }
    }

    /// Maps a wire string to a kind; unknown values become `Other`.
    pub fn from_wire(value: &str) -> Self {
        match value {
            "claude_code" => AgentKind::ClaudeCode,
            "codex" => AgentKind::Codex,
            "gemini_cli" => AgentKind::GeminiCli,
            "opencode" => AgentKind::OpenCode,
            _ => AgentKind::Other,
        }
    }
}

impl Serialize for AgentKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AgentKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Ok(Self::from_wire(&text))
    }
}

open_enum! {
    /// Derived per-session state (protocol.md 5.4).
    AgentState {
        /// Nothing running.
        Idle => "idle",
        /// Working (generic).
        Working => "working",
        /// Writing code.
        WritingCode => "writing_code",
        /// Reviewing / reading.
        Reviewing => "reviewing",
        /// Running tests/builds.
        Testing => "testing",
        /// Waiting for an approval.
        AwaitingApproval => "awaiting_approval",
        /// Waiting for user input.
        AwaitingInput => "awaiting_input",
        /// Error.
        Error => "error",
        /// Turn completed.
        Completed => "completed",
        /// Session considered dead / adapter disconnected.
        Disconnected => "disconnected",
    }
}

impl AgentState {
    /// Fail-safe view: unknown states render as `working` (protocol.md 10).
    pub fn effective(&self) -> AgentState {
        match self {
            AgentState::Unknown(_) => AgentState::Working,
            other => other.clone(),
        }
    }

    /// Focus priority, lower is more urgent (protocol.md 5.5). Unknown ranks as `working`.
    pub fn focus_rank(&self) -> u8 {
        match self.effective() {
            AgentState::AwaitingApproval => 0,
            AgentState::AwaitingInput => 1,
            AgentState::Error => 2,
            AgentState::Testing => 3,
            AgentState::WritingCode => 4,
            AgentState::Reviewing => 5,
            AgentState::Working => 6,
            AgentState::Completed => 7,
            AgentState::Idle => 8,
            AgentState::Disconnected => 9,
            AgentState::Unknown(_) => 6,
        }
    }
}

open_enum! {
    /// Event category.
    EventCategory {
        /// Session lifecycle.
        Lifecycle => "lifecycle",
        /// Turn events.
        Turn => "turn",
        /// Tool use.
        Tool => "tool",
        /// File access.
        File => "file",
        /// Commands.
        Command => "command",
        /// Approvals.
        Approval => "approval",
        /// Errors.
        Error => "error",
        /// Review.
        Review => "review",
        /// Notifications.
        Notification => "notification",
        /// Usage.
        Usage => "usage",
        /// Adapter health.
        Adapter => "adapter",
    }
}

open_enum! {
    /// Event severity.
    Severity {
        /// Debug.
        Debug => "debug",
        /// Info.
        Info => "info",
        /// Notice.
        Notice => "notice",
        /// Warning.
        Warning => "warning",
        /// Error.
        Error => "error",
    }
}

open_enum! {
    /// Normalised event kind (protocol.md 5.2).
    EventKind {
        /// Session started.
        SessionStarted => "session_started",
        /// Session ended.
        SessionEnded => "session_ended",
        /// Prompt submitted.
        PromptSubmitted => "prompt_submitted",
        /// Turn started.
        TurnStarted => "turn_started",
        /// Turn completed.
        TurnCompleted => "turn_completed",
        /// Turn failed.
        TurnFailed => "turn_failed",
        /// Turn interrupted.
        TurnInterrupted => "turn_interrupted",
        /// Tool started.
        ToolStarted => "tool_started",
        /// Tool completed.
        ToolCompleted => "tool_completed",
        /// Tool failed.
        ToolFailed => "tool_failed",
        /// File read.
        FileRead => "file_read",
        /// File modified.
        FileModified => "file_modified",
        /// Command started.
        CommandStarted => "command_started",
        /// Command completed.
        CommandCompleted => "command_completed",
        /// Command failed.
        CommandFailed => "command_failed",
        /// Test run started.
        TestRun => "test_run",
        /// Tests passed.
        TestPassed => "test_passed",
        /// Tests failed.
        TestFailed => "test_failed",
        /// Sub-agent started.
        SubagentStarted => "subagent_started",
        /// Sub-agent stopped.
        SubagentStopped => "subagent_stopped",
        /// Task created.
        TaskCreated => "task_created",
        /// Task completed.
        TaskCompleted => "task_completed",
        /// Approval requested (timeline only).
        ApprovalRequested => "approval_requested",
        /// Approval resolved (timeline only).
        ApprovalResolved => "approval_resolved",
        /// Permission denied automatically.
        PermissionDeniedAuto => "permission_denied_auto",
        /// Notification.
        Notification => "notification",
        /// Idle.
        Idle => "idle",
        /// Context compacted.
        ContextCompacted => "context_compacted",
        /// Review started.
        ReviewStarted => "review_started",
        /// Review completed.
        ReviewCompleted => "review_completed",
        /// Review finding.
        ReviewFinding => "review_finding",
        /// Token usage updated.
        TokenUsageUpdated => "token_usage_updated",
        /// Session metadata updated.
        SessionMetaUpdated => "session_meta_updated",
        /// Agent error.
        AgentError => "agent_error",
        /// Adapter status (timeline only).
        AdapterStatus => "adapter_status",
    }
}

impl EventKind {
    /// The category that goes with this kind (protocol.md 5.2). `None` for unknown kinds.
    pub fn category(&self) -> Option<EventCategory> {
        use EventCategory as C;
        use EventKind as K;
        Some(match self {
            K::SessionStarted
            | K::SessionEnded
            | K::SubagentStarted
            | K::SubagentStopped
            | K::Idle
            | K::ContextCompacted
            | K::SessionMetaUpdated => C::Lifecycle,
            K::PromptSubmitted
            | K::TurnStarted
            | K::TurnCompleted
            | K::TurnInterrupted
            | K::TaskCreated
            | K::TaskCompleted => C::Turn,
            K::TurnFailed | K::ToolFailed | K::CommandFailed | K::AgentError => C::Error,
            K::ToolStarted | K::ToolCompleted => C::Tool,
            K::FileRead | K::FileModified => C::File,
            K::CommandStarted
            | K::CommandCompleted
            | K::TestRun
            | K::TestPassed
            | K::TestFailed => C::Command,
            K::ApprovalRequested | K::ApprovalResolved | K::PermissionDeniedAuto => C::Approval,
            K::Notification => C::Notification,
            K::ReviewStarted | K::ReviewCompleted | K::ReviewFinding => C::Review,
            K::TokenUsageUpdated => C::Usage,
            K::AdapterStatus => C::Adapter,
            K::Unknown(_) => return None,
        })
    }

    /// `true` for the three timeline-only kinds that must never drive the phone-side state reducer
    /// (protocol.md 5.1): `approval_requested`, `approval_resolved`, `adapter_status`.
    pub fn is_timeline_only(&self) -> bool {
        matches!(
            self,
            EventKind::ApprovalRequested | EventKind::ApprovalResolved | EventKind::AdapterStatus
        )
    }
}

open_enum! {
    /// Where an event or approval came from (`source.channel`, `origin`).
    SourceChannel {
        /// Claude Code HTTP hook.
        ClaudeCodeHookHttp => "claude_code.hook.http",
        /// Claude Code command hook (fallback).
        ClaudeCodeHookCli => "claude_code.hook.cli",
        /// Claude Code status line.
        ClaudeCodeStatusline => "claude_code.statusline",
        /// Codex command hook.
        CodexHookCli => "codex.hook.cli",
        /// Codex app-server socket (UNVERIFIED, feature flag).
        CodexAppServer => "codex.app_server",
        /// Codex rollout files.
        CodexRollout => "codex.rollout",
        /// `codex exec --json`.
        CodexExecJson => "codex.exec_json",
    }
}

open_enum! {
    /// Command classification shared by the risk tokenizer and the state reducer.
    CommandClass {
        /// Test runners.
        Test => "test",
        /// Builds, linters, formatters.
        Build => "build",
        /// Version control.
        Vcs => "vcs",
        /// Package managers.
        Package => "package",
        /// File system tools.
        Fs => "fs",
        /// Network tools.
        Network => "network",
        /// Anything else.
        Shell => "shell",
    }
}

open_enum! {
    /// File operation (`recent_files[].op`, `file_modified.detail.op`).
    FileOp {
        /// Created.
        Create => "create",
        /// Updated.
        Update => "update",
        /// Deleted.
        Delete => "delete",
        /// Edited.
        Edit => "edit",
        /// Read.
        Read => "read",
    }
}

open_enum! {
    /// Status of the last test run.
    TestStatus {
        /// Running.
        Running => "running",
        /// Passed.
        Passed => "passed",
        /// Failed.
        Failed => "failed",
    }
}

open_enum! {
    /// Whether remote approval is possible for a session (protocol.md 5.3). The phone renders `Unknown` like `Unavailable`.
    RemoteApproval {
        /// Available.
        Available => "available",
        /// Not available (bypass modes, no hook).
        Unavailable => "unavailable",
        /// Paused on the PC.
        Paused => "paused",
        /// Policy cannot be determined.
        PolicyUnknown => "unknown",
    }
}

open_enum! {
    /// State of the review counters (`meta.review.state`).
    ReviewState {
        /// No review.
        None => "none",
        /// Running.
        Running => "running",
        /// Completed.
        Completed => "completed",
        /// No review source available (Codex hooks mode).
        Unavailable => "unavailable",
    }
}

open_enum! {
    /// Risk level of an approval request (integrations/claude-code.md 7).
    RiskLevel {
        /// Low.
        Low => "low",
        /// Medium.
        Medium => "medium",
        /// High.
        High => "high",
        /// Critical.
        Critical => "critical",
    }
}

impl RiskLevel {
    /// Fail-safe view: unknown levels are treated as `high` and never lowered (protocol.md 10).
    pub fn effective(&self) -> RiskLevel {
        match self {
            RiskLevel::Unknown(_) => RiskLevel::High,
            other => other.clone(),
        }
    }
}

open_enum! {
    /// Extra confirmation required by the risk level.
    ExtraConfirmation {
        /// None.
        None => "none",
        /// Long press.
        Hold => "hold",
        /// Long press plus re-confirmation sheet.
        HoldAndReconfirm => "hold_and_reconfirm",
    }
}

impl ExtraConfirmation {
    /// Strength ordering for "same or stronger" checks (security.md 6.2 step 8). Unknown values rank strongest (fail closed).
    pub fn strength(&self) -> u8 {
        match self {
            ExtraConfirmation::None => 0,
            ExtraConfirmation::Hold => 1,
            ExtraConfirmation::HoldAndReconfirm | ExtraConfirmation::Unknown(_) => 2,
        }
    }
}

impl ExtraConfirmationMethod {
    /// Strength on the same scale as [`ExtraConfirmation::strength`].
    pub fn strength(self) -> u8 {
        match self {
            ExtraConfirmationMethod::Hold => 1,
            ExtraConfirmationMethod::HoldAndReconfirm => 2,
        }
    }
}

open_enum! {
    /// What the approval card shows (`details.kind`).
    DetailsKind {
        /// Shell command.
        Command => "command",
        /// File write.
        FileWrite => "file_write",
        /// File edit.
        FileEdit => "file_edit",
        /// File read.
        FileRead => "file_read",
        /// MCP tool.
        McpTool => "mcp_tool",
        /// Web access.
        Web => "web",
        /// Sub-agent.
        Agent => "agent",
        /// Codex file change.
        FileChange => "file_change",
        /// Codex permissions.
        Permissions => "permissions",
        /// Other.
        Other => "other",
    }
}

open_enum! {
    /// Whether the local (terminal) prompt is visible while the request is pending (Phase 0 A2).
    LocalPrompt {
        /// Not yet verified.
        Unverified => "unknown",
        /// Visible.
        Visible => "visible",
        /// Hidden.
        Hidden => "hidden",
    }
}

open_enum! {
    /// Adapter health.
    AdapterStatusKind {
        /// Connected.
        Connected => "connected",
        /// Degraded.
        Degraded => "degraded",
        /// Disconnected.
        Disconnected => "disconnected",
        /// Not configured.
        NotConfigured => "not_configured",
    }
}

open_enum! {
    /// How the adapter collects data.
    AdapterMode {
        /// Claude Code HTTP hooks.
        HooksHttp => "hooks_http",
        /// Command hooks via `agentnest-hook`.
        HooksCli => "hooks_cli",
        /// Codex daemon socket observer (UNVERIFIED).
        DaemonObserver => "daemon_observer",
        /// Rollout tailing.
        RolloutTail => "rollout_tail",
        /// None.
        None => "none",
    }
}

open_enum! {
    /// Final outcome of an approval request (`approval_resolved.outcome`).
    ApprovalOutcome {
        /// Allowed.
        Allowed => "allowed",
        /// Denied.
        Denied => "denied",
        /// Denied and stopped.
        DeniedAndStopped => "denied_and_stopped",
        /// TTL expired, handed to the local prompt.
        Expired => "expired",
        /// Handed to the local prompt.
        HandedOffLocal => "handed_off_local",
        /// Agent or another client resolved first.
        Superseded => "superseded",
        /// Delivery failed.
        Failed => "failed",
    }
}

open_enum! {
    /// Who resolved the request.
    ResolvedBy {
        /// Phone.
        Phone => "phone",
        /// Desktop.
        Desktop => "desktop",
        /// Timeout.
        Timeout => "timeout",
        /// Agent.
        Agent => "agent",
        /// System.
        System => "system",
    }
}

open_enum! {
    /// Whether the reply reached the agent.
    Delivery {
        /// Delivered.
        Delivered => "delivered",
        /// Not delivered.
        NotDelivered => "not_delivered",
    }
}

open_enum! {
    /// What was later observed for an allowed/denied request.
    ObservedResult {
        /// The tool ran.
        Executed => "executed",
        /// The tool did not run.
        Declined => "declined",
        /// Not determined (yet).
        Undetermined => "unknown",
    }
}

open_enum! {
    /// Result code of a `decision` (protocol.md 4.11).
    DecisionResultReason {
        /// Applied.
        Applied => "APPLIED",
        /// Unknown request.
        UnknownRequest => "UNKNOWN_REQUEST",
        /// Already resolved.
        AlreadyResolved => "ALREADY_RESOLVED",
        /// Expired.
        Expired => "EXPIRED",
        /// Binding mismatch.
        BindingMismatch => "BINDING_MISMATCH",
        /// Input hash mismatch.
        InputHashMismatch => "INPUT_HASH_MISMATCH",
        /// Decision not allowed.
        NotAllowed => "NOT_ALLOWED",
        /// Authentication required.
        AuthRequired => "AUTH_REQUIRED",
        /// Extra confirmation required.
        ExtraConfirmationRequired => "EXTRA_CONFIRMATION_REQUIRED",
        /// Clock skew.
        ClockSkew => "CLOCK_SKEW",
        /// Remote approval paused.
        Paused => "PAUSED",
        /// Device revoked.
        DeviceRevoked => "DEVICE_REVOKED",
    }
}

open_enum! {
    /// Protocol error codes (protocol.md 9.1).
    ErrorCode {
        /// Version mismatch.
        ProtoVersion => "E_PROTO_VERSION",
        /// Auth required.
        AuthRequired => "E_AUTH_REQUIRED",
        /// Auth failed.
        AuthFailed => "E_AUTH_FAILED",
        /// Device revoked.
        DeviceRevoked => "E_DEVICE_REVOKED",
        /// Pairing failed.
        PairFailed => "E_PAIR_FAILED",
        /// Pairing rejected.
        PairRejected => "E_PAIR_REJECTED",
        /// Pairing busy.
        PairBusy => "E_PAIR_BUSY",
        /// Rate limited.
        RateLimited => "E_RATE_LIMITED",
        /// Bad message.
        BadMessage => "E_BAD_MESSAGE",
        /// Resume window exceeded.
        ResumeTooOld => "E_RESUME_TOO_OLD",
        /// Internal error.
        Internal => "E_INTERNAL",
    }
}

open_enum! {
    /// Reason of a server `bye`.
    ByeReason {
        /// Device revoked.
        DeviceRevoked => "device_revoked",
        /// Shutdown.
        Shutdown => "shutdown",
        /// Restart.
        Restart => "restart",
        /// Superseded by a newer connection.
        SupersededConnection => "superseded_connection",
        /// Unpaired.
        Unpaired => "unpaired",
    }
}

open_enum! {
    /// How the server resynchronises a reconnecting phone.
    ResyncMode {
        /// Replay `from_seq..to_seq`.
        Replay => "replay",
        /// Send a snapshot.
        Snapshot => "snapshot",
        /// Nothing to do.
        None => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_enum_round_trips_unknown_values() {
        let s: AgentState = serde_json::from_str("\"hyperdrive\"").unwrap();
        assert_eq!(s, AgentState::Unknown("hyperdrive".into()));
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"hyperdrive\"");
        assert_eq!(s.effective(), AgentState::Working);
    }

    #[test]
    fn unknown_risk_is_high_never_low() {
        let r = RiskLevel::from_wire("extreme");
        assert_eq!(r.effective(), RiskLevel::High);
    }

    #[test]
    fn decision_is_closed() {
        assert!(serde_json::from_str::<Decision>("\"allow\"").is_ok());
        for bad in [
            "allow_for_session",
            "acceptForSession",
            "ALLOW",
            "allow_always",
            "",
        ] {
            assert!(
                serde_json::from_str::<Decision>(&format!("\"{bad}\"")).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn known_lists_match_variants() {
        assert_eq!(EventKind::KNOWN.len(), 35);
        for k in EventKind::KNOWN {
            let kind = EventKind::from_wire(k);
            assert!(!kind.is_unknown(), "{k}");
            assert_eq!(kind.as_str(), *k);
            assert!(kind.category().is_some());
        }
    }

    #[test]
    fn focus_rank_is_total_and_ordered() {
        let order = [
            "awaiting_approval",
            "awaiting_input",
            "error",
            "testing",
            "writing_code",
            "reviewing",
            "working",
            "completed",
            "idle",
            "disconnected",
        ];
        for (i, s) in order.iter().enumerate() {
            assert_eq!(AgentState::from_wire(s).focus_rank() as usize, i);
        }
    }

    #[test]
    fn agent_kind_other_absorbs_unknown() {
        let k: AgentKind = serde_json::from_str("\"future_agent\"").unwrap();
        assert_eq!(k, AgentKind::Other);
    }
}
