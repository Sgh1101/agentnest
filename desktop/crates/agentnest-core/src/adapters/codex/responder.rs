//! Codex answers: the app-server JSON-RPC decision strings and the hooks reply (docs/integrations/codex.md 6, security.md
//! 6.5).
//!
//! The mapping of the broker's reply to the Codex app-server is `Allow -> "accept"`, `Deny -> "decline"`,
//! `DenyAndStop -> "cancel"`. **Only these three plain strings exist**: `acceptForSession`,
//! `acceptWithExecpolicyAmendment`, `applyNetworkPolicyAmendment` and every object-shaped decision have no generating
//! code (I11). The response envelope is `{"id": <request id>, "result": {"decision": "..."}}` (verified shape of the
//! app-server wire format; whether a third-party connection receives approval requests at all is UNVERIFIED Phase 0 C2
//! and the observer that would use this is behind the `codex-daemon-observer` feature).
//!
//! Expiry, revocation, disconnect and restart send **nothing** (the app-server has no timeout of its own; the TUI prompt
//! handles it): `abandon` is a no-op.

use agentnest_adapter_api::{
    AbandonReason, ApprovalReply, ApprovalResponder, ReplyKind, ResponderError,
};
use futures_util::future::BoxFuture;
use serde_json::{json, Value};
use tokio::sync::mpsc;

/// The JSON-RPC decision string for a reply.
pub fn rpc_decision(reply: ReplyKind<'_>) -> &'static str {
    match reply {
        ReplyKind::Allow => "accept",
        ReplyKind::Deny {
            interrupt: false, ..
        } => "decline",
        ReplyKind::Deny {
            interrupt: true, ..
        } => "cancel",
    }
}

/// The JSON-RPC response line for request `rpc_id`.
pub fn rpc_response(rpc_id: &Value, reply: ReplyKind<'_>) -> Value {
    json!({ "id": rpc_id, "result": { "decision": rpc_decision(reply) } })
}

/// Answers one app-server `requestApproval` request by writing a response line to the transport.
pub struct CodexRpcResponder {
    rpc_id: Value,
    out: mpsc::UnboundedSender<String>,
}

impl std::fmt::Debug for CodexRpcResponder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodexRpcResponder").finish_non_exhaustive()
    }
}

impl CodexRpcResponder {
    /// A responder for the request `rpc_id`; response lines go to `out`.
    pub fn new(rpc_id: Value, out: mpsc::UnboundedSender<String>) -> Self {
        Self { rpc_id, out }
    }
}

impl ApprovalResponder for CodexRpcResponder {
    fn respond(
        self: Box<Self>,
        reply: ApprovalReply,
    ) -> BoxFuture<'static, Result<(), ResponderError>> {
        let line = rpc_response(&self.rpc_id, reply.as_wire()).to_string();
        let out = self.out;
        Box::pin(async move { out.send(line).map_err(|_| ResponderError::PeerClosed) })
    }

    fn abandon(self: Box<Self>, _reason: AbandonReason) -> BoxFuture<'static, ()> {
        // no response: the TUI prompt (or another client) handles the request
        Box::pin(async {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_decisions_map_to_three_plain_strings() {
        assert_eq!(rpc_decision(ReplyKind::Allow), "accept");
        assert_eq!(
            rpc_decision(ReplyKind::Deny {
                message: "m",
                interrupt: false
            }),
            "decline"
        );
        assert_eq!(
            rpc_decision(ReplyKind::Deny {
                message: "m",
                interrupt: true
            }),
            "cancel"
        );
        let r = rpc_response(&json!(17), ReplyKind::Allow);
        assert_eq!(r, json!({"id": 17, "result": {"decision": "accept"}}));
        // no scope-expanding spelling can come out of the mapping
        for kind in [
            ReplyKind::Allow,
            ReplyKind::Deny {
                message: "x",
                interrupt: false,
            },
            ReplyKind::Deny {
                message: "x",
                interrupt: true,
            },
        ] {
            let d = rpc_decision(kind);
            assert!(["accept", "decline", "cancel"].contains(&d));
            assert!(!d.contains("Session") && !d.contains("amendment") && !d.contains("Amendment"));
        }
    }

    #[tokio::test]
    async fn respond_writes_one_line_and_abandon_writes_nothing() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        Box::new(CodexRpcResponder::new(json!(5), tx.clone()))
            .respond(ApprovalReply::deny("m".into(), true))
            .await
            .unwrap();
        let line = rx.recv().await.unwrap();
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v, json!({"id": 5, "result": {"decision": "cancel"}}));
        Box::new(CodexRpcResponder::new(json!(6), tx))
            .abandon(AbandonReason::Expired)
            .await;
        assert!(
            rx.try_recv().is_err(),
            "an abandoned request is never answered"
        );
        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx);
        assert!(matches!(
            Box::new(CodexRpcResponder::new(json!(7), tx))
                .respond(ApprovalReply::deny("m".into(), false))
                .await,
            Err(ResponderError::PeerClosed)
        ));
    }
}
