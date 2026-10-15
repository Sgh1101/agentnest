//! Claude Code adapter: HTTP hook normalisation and PermissionRequest hold.
//!
//! This module currently holds the **pure normalisation** (`normalize`): hook JSON in, [`RawObservation`]s out, golden
//! tested against hook payloads. It contains **no decision logic**: an approval decision is made by the broker (security
//! invariant I5) and only *translated* into a hook reply by the responder that the HTTP layer creates. The settings.json
//! installer, the `PermissionRequest` hold and the `AgentAdapter` implementation are built on top of this in the
//! approvals/http steps.
//!
//! Entry points:
//!
//! * [`normalize::normalize`]: every hook except `PermissionRequest` -> events (`Vec<RawObservation>`);
//! * [`normalize::permission_request_draft`]: `PermissionRequest` -> [`agentnest_adapter_api::ApprovalDraft`] (the HTTP
//!   layer pairs it with the responder into `RawObservation::ApprovalOpened`);
//! * [`normalize::pre_tool_use_risk`] / [`normalize::pre_tool_use_ask_reply`]: the `PreToolUse` risk path
//!   (`force_ask_on_critical`; the only reply ever produced is `ask`, never `allow`).
//!
//! [`RawObservation`]: agentnest_adapter_api::RawObservation

pub mod normalize;

pub use normalize::{
    hook_event_name, normalize, permission_request_draft, pre_tool_use_ask_reply,
    pre_tool_use_risk, NormalizeCtx, NormalizeError,
};
