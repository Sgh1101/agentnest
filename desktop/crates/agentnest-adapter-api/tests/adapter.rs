//! The adapter trait, observations and responder protocol, exercised with in-test mocks.

use std::sync::{Arc, Mutex};

use agentnest_adapter_api::{
    AbandonReason, AdapterCapabilities, AdapterContext, AdapterError, AdapterHandle, AdapterHealth,
    AdapterMode, AdapterStatusKind, AgentAdapter, AgentKind, ApprovalDraft, ApprovalReply,
    ApprovalResponder, Decision, HookMeta, HookReply, NativeBinding, ObservationSink,
    RawObservation, ReplyKind, ResponderError, SourceChannel,
};
use futures_util::future::BoxFuture;
use serde_json::json;
use tokio::sync::{mpsc, watch};

/// A responder that records what it would have sent to the agent: `None` = nothing at all.
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<String>>>);

struct MockResponder(Recorder);

impl ApprovalResponder for MockResponder {
    fn respond(
        self: Box<Self>,
        reply: ApprovalReply,
    ) -> BoxFuture<'static, Result<(), ResponderError>> {
        Box::pin(async move {
            // Adapters translate only: they match on the wire view and never construct allow themselves.
            let native = match reply.as_wire() {
                ReplyKind::Allow => "behavior:allow".to_owned(),
                ReplyKind::Deny { message, interrupt } => {
                    format!("behavior:deny interrupt:{interrupt} message:{message}")
                }
            };
            self.0 .0.lock().unwrap().push(native);
            Ok(())
        })
    }

    fn abandon(self: Box<Self>, reason: AbandonReason) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            // "No decision": nothing is sent to the agent.
            self.0
                 .0
                .lock()
                .unwrap()
                .push(format!("<nothing sent: {reason:?}>"));
        })
    }
}

struct MockAdapter;

impl AgentAdapter for MockAdapter {
    fn kind(&self) -> AgentKind {
        AgentKind::Other
    }
    fn label(&self) -> &'static str {
        "Mock"
    }
    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            observe_sessions: true,
            remote_approval: true,
            approval_decisions: vec![Decision::Allow, Decision::Deny],
            ..Default::default()
        }
    }
    fn start(
        &self,
        ctx: AdapterContext,
    ) -> BoxFuture<'static, Result<AdapterHandle, AdapterError>> {
        Box::pin(async move {
            let sink = ctx.sink.clone();
            sink.emit(RawObservation::Health(AdapterHealth {
                status: AdapterStatusKind::Connected,
                mode: AdapterMode::HooksHttp,
                detail: None,
            }))
            .await;
            Ok(AdapterHandle::noop())
        })
    }
    fn health(&self) -> BoxFuture<'static, AdapterHealth> {
        Box::pin(async {
            AdapterHealth {
                status: AdapterStatusKind::Connected,
                mode: AdapterMode::None,
                detail: Some("ok".into()),
            }
        })
    }
}

fn draft() -> ApprovalDraft {
    ApprovalDraft {
        binding: NativeBinding {
            agent_kind: AgentKind::ClaudeCode,
            native_session_id: "s1".into(),
            ids: [("tool_name".to_owned(), "Bash".to_owned())]
                .into_iter()
                .collect(),
        },
        session_key: "claude_code:s1".into(),
        agent_kind: AgentKind::ClaudeCode,
        agent_id: None,
        project: None,
        cwd: Some("C:\\dev\\agentnest".into()),
        tool_name: "Bash".into(),
        tool_input: json!({"command": "echo super-secret-command-body"}),
        origin: SourceChannel::ClaudeCodeHookHttp,
        permission_mode: Some("default".into()),
        available_decisions: vec![Decision::Allow, Decision::Deny, Decision::DenyAndStop],
        permission_suggestions_count: Some(1),
        agent_description: None,
        reason: None,
        created_at: "2026-10-15T12:35:00.000Z".into(),
    }
}

#[tokio::test]
async fn default_ingest_hook_is_empty_and_start_emits_health() {
    let (tx, mut rx) = mpsc::channel(8);
    let (_stop_tx, stop_rx) = watch::channel(false);
    let adapter = MockAdapter;
    let handle = adapter
        .start(AdapterContext {
            sink: ObservationSink::new(tx),
            shutdown: stop_rx,
        })
        .await
        .unwrap();
    handle.shutdown();
    assert!(
        matches!(rx.recv().await, Some(RawObservation::Health(h)) if h.status == AdapterStatusKind::Connected)
    );

    let meta = HookMeta {
        channel: SourceChannel::ClaudeCodeHookHttp,
        received_at: "2026-10-15T12:35:00.000Z".into(),
        content_length: 2,
    };
    assert_eq!(adapter.ingest_hook(json!({}), meta).await, HookReply::Empty);
    assert_eq!(adapter.health().await.detail.as_deref(), Some("ok"));
    assert!(adapter
        .capabilities()
        .approval_decisions
        .iter()
        .all(|d| *d != Decision::DenyAndStop));
}

#[tokio::test]
async fn responder_translates_deny_and_abandon_sends_nothing() {
    let rec = Recorder::default();
    let deny = ApprovalReply::deny("no thanks".into(), true);
    Box::new(MockResponder(rec.clone()))
        .respond(deny)
        .await
        .unwrap();
    Box::new(MockResponder(rec.clone()))
        .abandon(AbandonReason::Expired)
        .await;
    let log = rec.0.lock().unwrap().clone();
    assert_eq!(
        log,
        [
            "behavior:deny interrupt:true message:no thanks",
            "<nothing sent: Expired>"
        ]
    );
}

#[tokio::test]
async fn observations_flow_through_the_sink_and_debug_hides_tool_input() {
    let (tx, mut rx) = mpsc::channel(8);
    let sink = ObservationSink::new(tx);
    let rec = Recorder::default();
    assert!(
        sink.emit(RawObservation::ApprovalOpened {
            draft: draft(),
            responder: Box::new(MockResponder(rec))
        })
        .await
    );
    let obs = rx.recv().await.unwrap();
    let dbg = format!("{obs:?}");
    assert!(dbg.contains("ApprovalOpened"));
    assert!(
        !dbg.contains("super-secret-command-body"),
        "raw tool input must never reach Debug output: {dbg}"
    );
    drop(rx);
    assert!(
        !sink
            .emit(RawObservation::Health(AdapterHealth {
                status: AdapterStatusKind::Disconnected,
                mode: AdapterMode::None,
                detail: None
            }))
            .await
    );
}

#[test]
fn capabilities_default_to_nothing_and_cannot_express_scope_expansion() {
    let caps = AdapterCapabilities::default();
    assert!(!caps.remote_approval && caps.approval_decisions.is_empty());
    let v = serde_json::to_value(AdapterCapabilities {
        approval_decisions: vec![Decision::Allow, Decision::DenyAndStop],
        ..Default::default()
    })
    .unwrap();
    assert_eq!(v["approval_decisions"], json!(["allow", "deny_and_stop"]));
}

#[test]
fn native_binding_round_trips_for_storage() {
    let b = draft().binding;
    let back: NativeBinding = serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
    assert_eq!(back, b);
}
