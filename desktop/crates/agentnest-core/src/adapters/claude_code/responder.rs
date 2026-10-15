//! The reply of a held Claude Code `PermissionRequest` hook (docs/integrations/claude-code.md 4.1, security.md I5, I11).
//!
//! * [`HookOutcome`]: what the HTTP handler answers: [`HookOutcome::Empty`] ("no decision": a 204 with no body, the local
//!   prompt appears) or a JSON body.
//! * [`HookResponder`]: the [`ApprovalResponder`] bound to one open HTTP request. It **only translates** what the broker
//!   gives it ([`ReplyKind`], a read-only view that cannot be turned back into a reply). It never decides.
//! * [`permission_request_reply`]: the exact JSON. `behavior:"allow"` carries **no** `updatedInput` / `updatedPermissions`
//!   (I11); `deny` carries the sanitised `message` and `interrupt`. The text is only ever put into the JSON through the
//!   serialiser, never concatenated.
//!
//! `abandon` and a dropped responder both end as [`HookOutcome::Empty`]: every path that is not a validated decision
//! is "no decision".

use agentnest_adapter_api::{AbandonReason, ApprovalReply, ApprovalResponder, ReplyKind, ResponderError};
use futures_util::future::BoxFuture;
use serde_json::{json, Value};
use tokio::sync::oneshot;

/// What the HTTP handler of a held hook answers.
#[derive(Clone, Debug, PartialEq)]
pub enum HookOutcome {
    /// 204, no body: no decision.
    Empty,
    /// 200 with this JSON body.
    Json(Value),
}

/// Which agent's hook output grammar to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookFlavor {
    /// Claude Code: deny may carry `interrupt`.
    Claude,
    /// Codex hooks: `interrupt` / `updatedInput` / `updatedPermissions` would void the whole decision (codex.md 5.2), so
    /// a deny never carries them and a reply that asks to stop produces no output at all.
    Codex,
}

/// The JSON of a Claude Code `PermissionRequest` reply.
pub fn permission_request_reply(reply: ReplyKind<'_>) -> Value {
    match reply {
        ReplyKind::Allow => json!({
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": { "behavior": "allow" }
            }
        }),
        ReplyKind::Deny { message, interrupt } => json!({
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": { "behavior": "deny", "message": message, "interrupt": interrupt }
            }
        }),
    }
}

/// The JSON of a Codex hooks `PermissionRequest` reply (UNVERIFIED Phase 0 C6: whether hooks can answer at all). A deny
/// uses a fixed message (the user's free text is not forwarded), never `interrupt`; a deny-and-stop has no hooks
/// equivalent and yields `None` (no output = no decision) instead of silently becoming a weaker deny.
pub fn codex_hook_reply(reply: ReplyKind<'_>) -> Option<Value> {
    match reply {
        ReplyKind::Allow => Some(json!({
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": { "behavior": "allow" }
            }
        })),
        ReplyKind::Deny { interrupt: false, .. } => Some(json!({
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": { "behavior": "deny", "message": "AgentNest: 휴대폰에서 거부했어요" }
            }
        })),
        ReplyKind::Deny { interrupt: true, .. } => None,
    }
}

/// The [`ApprovalResponder`] of one open hook HTTP request.
pub struct HookResponder {
    tx: Option<oneshot::Sender<HookOutcome>>,
    flavor: HookFlavor,
}

impl std::fmt::Debug for HookResponder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookResponder")
            .field("flavor", &self.flavor)
            .finish_non_exhaustive()
    }
}

impl HookResponder {
    /// A responder and the receiver the HTTP handler waits on.
    pub fn new(flavor: HookFlavor) -> (Self, oneshot::Receiver<HookOutcome>) {
        let (tx, rx) = oneshot::channel();
        (
            Self {
                tx: Some(tx),
                flavor,
            },
            rx,
        )
    }
}

impl ApprovalResponder for HookResponder {
    fn respond(
        mut self: Box<Self>,
        reply: ApprovalReply,
    ) -> BoxFuture<'static, Result<(), ResponderError>> {
        let outcome = match self.flavor {
            HookFlavor::Claude => HookOutcome::Json(permission_request_reply(reply.as_wire())),
            HookFlavor::Codex => match codex_hook_reply(reply.as_wire()) {
                Some(v) => HookOutcome::Json(v),
                None => HookOutcome::Empty,
            },
        };
        let tx = self.tx.take();
        Box::pin(async move {
            match tx {
                // `send` fails when the HTTP handler is gone (the agent closed the connection)
                Some(tx) => tx.send(outcome).map_err(|_| ResponderError::PeerClosed),
                None => Err(ResponderError::PeerClosed),
            }
        })
    }

    fn abandon(mut self: Box<Self>, _reason: AbandonReason) -> BoxFuture<'static, ()> {
        let tx = self.tx.take();
        Box::pin(async move {
            if let Some(tx) = tx {
                let _ = tx.send(HookOutcome::Empty);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn walk<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
        match v {
            Value::Object(m) => {
                for (k, x) in m {
                    out.push(k.as_str());
                    walk(x, out);
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            _ => {}
        }
    }

    #[test]
    fn allow_reply_has_exactly_the_documented_shape_and_no_scope_expansion() {
        let v = permission_request_reply(ReplyKind::Allow);
        assert_eq!(
            v,
            json!({"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "allow"}}})
        );
        let mut keys = Vec::new();
        walk(&v, &mut keys);
        for forbidden in ["updatedInput", "updatedPermissions", "interrupt", "message"] {
            assert!(!keys.contains(&forbidden), "{forbidden} must not appear in an allow");
        }
    }

    #[test]
    fn deny_reply_carries_message_and_interrupt_through_the_serialiser_only() {
        let nasty = "x\"},\"behavior\":\"allow\",{\"y\":\"";
        let v = permission_request_reply(ReplyKind::Deny { message: nasty, interrupt: true });
        assert_eq!(v["hookSpecificOutput"]["decision"]["behavior"], "deny");
        assert_eq!(v["hookSpecificOutput"]["decision"]["interrupt"], true);
        assert_eq!(v["hookSpecificOutput"]["decision"]["message"], nasty);
        // after a text round trip the structure is unchanged: no injection of an allow
        let text = serde_json::to_string(&v).unwrap();
        let back: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(back["hookSpecificOutput"]["decision"]["behavior"], "deny");
        let mut keys = Vec::new();
        walk(&back, &mut keys);
        assert!(!keys.contains(&"updatedInput") && !keys.contains(&"updatedPermissions"));
        let v = permission_request_reply(ReplyKind::Deny { message: "m", interrupt: false });
        assert_eq!(v["hookSpecificOutput"]["decision"]["interrupt"], false);
    }

    #[test]
    fn codex_hooks_replies_never_carry_interrupt_and_a_stop_is_no_output() {
        let allow = codex_hook_reply(ReplyKind::Allow).unwrap();
        assert_eq!(allow["hookSpecificOutput"]["decision"]["behavior"], "allow");
        let deny = codex_hook_reply(ReplyKind::Deny { message: "private user text", interrupt: false }).unwrap();
        assert_eq!(deny["hookSpecificOutput"]["decision"]["behavior"], "deny");
        let mut keys = Vec::new();
        walk(&deny, &mut keys);
        for forbidden in ["interrupt", "updatedInput", "updatedPermissions"] {
            assert!(!keys.contains(&forbidden), "{forbidden}");
        }
        assert!(!deny.to_string().contains("private user text"), "free text is not forwarded to Codex");
        assert_eq!(codex_hook_reply(ReplyKind::Deny { message: "x", interrupt: true }), None);
    }

    #[tokio::test]
    async fn abandon_and_drop_both_end_as_no_decision() {
        let (r, rx) = HookResponder::new(HookFlavor::Claude);
        Box::new(r).abandon(AbandonReason::Expired).await;
        assert_eq!(rx.await.unwrap(), HookOutcome::Empty);
        let (r, rx) = HookResponder::new(HookFlavor::Claude);
        drop(r);
        assert!(rx.await.is_err(), "a dropped responder closes the channel; the handler treats it as Empty");
    }

    #[tokio::test]
    async fn respond_to_a_gone_handler_is_peer_closed() {
        let (r, rx) = HookResponder::new(HookFlavor::Claude);
        drop(rx);
        let reply = ApprovalReply::deny("m".into(), false);
        assert!(matches!(Box::new(r).respond(reply).await, Err(ResponderError::PeerClosed)));
    }

    #[tokio::test]
    async fn deny_flows_through_the_responder() {
        let (r, rx) = HookResponder::new(HookFlavor::Claude);
        Box::new(r).respond(ApprovalReply::deny("no".into(), true)).await.unwrap();
        match rx.await.unwrap() {
            HookOutcome::Json(v) => {
                assert_eq!(v["hookSpecificOutput"]["decision"]["message"], "no");
                assert_eq!(v["hookSpecificOutput"]["decision"]["interrupt"], true);
            }
            other => panic!("{other:?}"),
        }
    }
}
