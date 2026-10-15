//! AgentNest agent adapter plugin API (docs/integrations/codex.md 2.1, ADR-0004).
//!
//! An *adapter* turns what an agent (Claude Code, Codex, ...) does into [`RawObservation`]s and translates the
//! broker's reply back into the agent's native protocol. **Adapters never decide anything.**
//!
//! # Contents
//!
//! * [`AgentAdapter`], [`AdapterCapabilities`], [`AdapterContext`], [`AdapterHandle`]: the plugin trait (async methods
//!   return [`futures_util::future::BoxFuture`]; `async-trait` is not used).
//! * [`RawObservation`], [`NativeBinding`], [`ApprovalDraft`]: what adapters emit.
//! * [`ApprovalResponder`]: the one-shot handle that answers (or abandons) an open approval request.
//! * [`ApprovalReply`], [`ReplyKind`], [`ApplyProof`]: the opaque reply types, see below.
//!
//! # The opaque `ApprovalReply` (security.md I5, I11)
//!
//! An *allow* must be impossible to produce by accident, from an adapter, from a timeout path or from deserialised
//! data. The design:
//!
//! * [`ApprovalReply`] is a tuple struct around a **private** inner enum. It has no `Default`, no `Deserialize`, no
//!   `From` conversions and no public variant; outside this crate it can only be created by
//!   [`ApprovalReply::deny`] and [`ApprovalReply::allow`].
//! * [`ApprovalReply::allow`] needs an [`ApplyProof`]. `ApplyProof` has a private field, so it cannot be written as a
//!   literal, and it is neither `Clone` nor `Copy`: one proof buys exactly one allow.
//! * The only constructor of `ApplyProof` is its `mint` function ([`mint`](struct@ApplyProof#method.mint)). It is called from **one place**: the success
//!   branch of `agentnest-core::approvals::broker::Broker::apply_decision`, after all nine validation steps of
//!   security.md 6.2 and the conditional `UPDATE` succeeded. Desktop (local) decisions pass through the same branch.
//! * Responders receive the reply and may only look at it through [`ApprovalReply::as_wire`], which returns the
//!   read-only [`ReplyKind`] wire view (`Allow` / `Deny{..}`). A `ReplyKind` cannot be turned back into an
//!   `ApprovalReply`. "No decision" is not a reply at all: it is [`ApprovalResponder::abandon`].
//!
//! ## Design choice on the location of `ApplyProof`
//!
//! The docs put `ApplyProof` in this crate and the only caller (`apply_decision`) in `agentnest-core`, i.e. in a
//! different crate, so `pub(crate)` cannot restrict `mint`. It is therefore `#[doc(hidden)] pub` and the guarantee is
//! enforced by three independent checks: (1) the `compile_fail` doctests in `tests/compile_fail.md` (no public allow
//! constructor, no literals, no reuse of a proof, no `From`/`Default`/`Deserialize`), (2) the CI grep that
//! the `mint` function has exactly one non-test call site (security.md 12 #6) and (3) `desktop/clippy.toml`, which puts
//! `mint` on `disallowed-methods` so that the single call site needs a visible
//! `#[allow(clippy::disallowed_methods)]`. Test code uses the `test-util` feature (`ApprovalReply::allow_for_test`),
//! which must never be enabled in release builds.
//!
//! # Compatibility notes
//!
//! * `RawObservation::ApprovalOutcomeObserved::evidence_event_id` is the UUIDv7 *string* of the evidence event (the
//!   docs show `Uuid`; this crate does not depend on the `uuid` crate).
//! * `AgentKind` lives in `agentnest-protocol` and is re-exported here.

#![forbid(unsafe_code)]

mod adapter;
mod observation;
mod reply;
mod responder;

pub use adapter::{
    AdapterCapabilities, AdapterContext, AdapterError, AdapterHandle, AdapterHealth, AgentAdapter,
    HookMeta, HookReply, ObservationSink,
};
pub use agentnest_protocol::{
    AdapterMode, AdapterStatusKind, AgentKind, Decision, ObservedResult, RemoteApproval,
    SourceChannel,
};
pub use observation::{
    AgentCloseReason, ApprovalDraft, NativeBinding, RawObservation, SessionMetaPatch,
};
pub use reply::{ApplyProof, ApprovalReply, ReplyKind};
pub use responder::{AbandonReason, ApprovalResponder, ResponderError};

/// Compile-fail doctests live in `tests/compile_fail.md` so that the CI grep for the `mint` call (which skips
/// `/tests/` paths) does not see the snippets.
#[cfg(doctest)]
#[doc = include_str!("../tests/compile_fail.md")]
pub struct CompileFailDocs;
