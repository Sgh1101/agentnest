//! The opaque approval reply, see the crate documentation.

/// An approval reply that a responder must translate into the agent's native protocol.
///
/// Opaque by design: the inner enum is private, there is no `Default`, no `Deserialize` and no `From<ReplyKind>`.
/// Create it with [`ApprovalReply::deny`] or, with an [`ApplyProof`], [`ApprovalReply::allow`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use = "an ApprovalReply must be handed to ApprovalResponder::respond"]
pub struct ApprovalReply(Inner);

/// Private on purpose: the name cannot be written outside this module.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Inner {
    Allow,
    Deny { message: String, interrupt: bool },
}

/// Read-only wire view of an [`ApprovalReply`], for responders. It cannot be converted back into a reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyKind<'a> {
    /// Allow this single tool call (Claude `behavior:"allow"`, Codex `"accept"`).
    Allow,
    /// Deny. `interrupt == true` means deny and stop the agent (Claude `interrupt:true`, Codex `"cancel"`).
    Deny {
        /// Already sanitised text for the agent.
        message: &'a str,
        /// Interrupt the agent.
        interrupt: bool,
    },
}

/// Proof that a decision passed the broker's validation and conditional update. One proof permits one allow.
///
/// The field is private (no literal), the type is neither `Clone` nor `Copy`.
#[derive(Debug)]
#[must_use = "an ApplyProof exists only to be passed to ApprovalReply::allow"]
pub struct ApplyProof(());

impl ApplyProof {
    /// Mints a proof.
    ///
    /// **Call site rule (security.md 12 #6):** the only non-test caller in the workspace is the success branch of
    /// `agentnest-core::approvals::broker::Broker::apply_decision`. `pub` + `doc(hidden)` only because that code lives
    /// in another crate; CI greps for other callers and `clippy.toml` disallows the method.
    #[doc(hidden)]
    pub fn mint() -> ApplyProof {
        ApplyProof(())
    }

    /// Test-only proof. Enabled by the `test-util` feature, which must not be active in release builds.
    #[cfg(feature = "test-util")]
    pub fn mint_for_test() -> ApplyProof {
        ApplyProof(())
    }
}

impl ApprovalReply {
    /// An allow reply. Requires an [`ApplyProof`] (consumed).
    pub fn allow(_proof: ApplyProof) -> Self {
        ApprovalReply(Inner::Allow)
    }

    /// A deny reply (always safe to create). `interrupt` additionally stops the agent.
    pub fn deny(message: String, interrupt: bool) -> Self {
        ApprovalReply(Inner::Deny { message, interrupt })
    }

    /// Read-only wire view for responders.
    pub fn as_wire(&self) -> ReplyKind<'_> {
        match &self.0 {
            Inner::Allow => ReplyKind::Allow,
            Inner::Deny { message, interrupt } => ReplyKind::Deny {
                message: message.as_str(),
                interrupt: *interrupt,
            },
        }
    }

    /// Test-only allow reply (`test-util` feature).
    #[cfg(feature = "test-util")]
    pub fn allow_for_test() -> Self {
        ApprovalReply(Inner::Allow)
    }
}
