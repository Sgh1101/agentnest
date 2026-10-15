//! The handle that answers an open approval request.

use futures_util::future::BoxFuture;
use thiserror::Error;

use crate::reply::ApprovalReply;

/// Why a request is abandoned (no reply is sent to the agent).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AbandonReason {
    /// TTL elapsed.
    Expired,
    /// The deciding device was revoked.
    DeviceRevoked,
    /// The phone disconnected and the reconnect grace period ran out.
    PhoneDisconnected,
    /// No authenticated device was online when the request arrived.
    NoOnlineDevice,
    /// `link.enabled=false`.
    LinkDisabled,
    /// Remote approval is paused on the PC.
    RemoteApprovalPaused,
    /// The PC user chose "handle locally".
    HandedOffToDesktop,
    /// The daemon is shutting down or restarting.
    DaemonShutdown,
    /// Internal error or panic recovery.
    InternalError,
    /// The agent or another client resolved the request first.
    Superseded,
}

/// Errors while delivering a reply.
#[derive(Debug, Error)]
pub enum ResponderError {
    /// The agent side is gone (HTTP connection dropped, JSON-RPC peer closed).
    #[error("peer closed")]
    PeerClosed,
    /// I/O failure while writing the reply.
    #[error("io error: {0}")]
    Io(String),
    /// The reply could not be serialised for the agent.
    #[error("serialisation error: {0}")]
    Serialization(String),
}

/// One-shot handle bound to a native request (an open HTTP request for Claude, a JSON-RPC request id for Codex).
///
/// Both methods consume the responder, so a request can be answered or abandoned exactly once.
pub trait ApprovalResponder: Send + Sync {
    /// Translates `reply` into the agent's protocol and delivers it. Use [`ApprovalReply::as_wire`] and `match` on
    /// [`crate::ReplyKind`]; never construct allow-like output any other way.
    fn respond(
        self: Box<Self>,
        reply: ApprovalReply,
    ) -> BoxFuture<'static, Result<(), ResponderError>>;

    /// "No decision": expiry, revocation, disconnect, restart, internal error. Sends nothing to the agent (Claude: an
    /// empty 2xx, Codex: no response), which falls back to its local prompt.
    fn abandon(self: Box<Self>, reason: AbandonReason) -> BoxFuture<'static, ()>;
}
