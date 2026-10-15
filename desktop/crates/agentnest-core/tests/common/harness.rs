//! A broker harness for the approval tests: in-memory store, manual clock, a registry with fake phone connections and
//! responders that record what the agent would have received.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

use agentnest_adapter_api::{
    AbandonReason, ApprovalDraft, ApprovalResponder, NativeBinding, ReplyKind, ResponderError,
};
use agentnest_core::approvals::broker::{
    default_classifier, Broker, BrokerDeps, BrokerSettings, ClassifierFn, OpenOutcome,
};
use agentnest_core::approvals::validator::{DecisionInput, DecisionSource};
use agentnest_core::audit::Audit;
use agentnest_core::auth::devices::{DeviceRegistry, NewDevice};
use agentnest_core::events::EventBus;
use agentnest_core::link::registry::{ConnCommand, Registry};
use agentnest_core::normalize::{NormalizeEnv, ProjectResolver, SequentialIdGen};
use agentnest_core::pipeline::Pipeline;
use agentnest_core::state::timers::{format_ms, ManualClock};
use agentnest_core::store::Store;
use agentnest_protocol::qr::b64_encode;
use agentnest_protocol::{
    AgentKind, ApprovalRequest, AuthMethod, Decision, DecisionAuth, ExtraConfirmation,
    ExtraConfirmationMethod, ExtraConfirmationProof, Secret, SourceChannel,
};
use futures_util::future::BoxFuture;
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};

/// What the agent side received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seen {
    Allow,
    Deny { message: String, interrupt: bool },
    Abandoned(AbandonReason),
}

pub struct TestResponder {
    tx: Option<oneshot::Sender<Seen>>,
    fail_respond: bool,
}

impl ApprovalResponder for TestResponder {
    fn respond(
        mut self: Box<Self>,
        reply: agentnest_adapter_api::ApprovalReply,
    ) -> BoxFuture<'static, Result<(), ResponderError>> {
        let seen = match reply.as_wire() {
            ReplyKind::Allow => Seen::Allow,
            ReplyKind::Deny { message, interrupt } => Seen::Deny {
                message: message.to_owned(),
                interrupt,
            },
        };
        let fail = self.fail_respond;
        let tx = self.tx.take();
        Box::pin(async move {
            if fail {
                return Err(ResponderError::PeerClosed);
            }
            match tx {
                Some(tx) => tx.send(seen).map_err(|_| ResponderError::PeerClosed),
                None => Err(ResponderError::PeerClosed),
            }
        })
    }

    fn abandon(mut self: Box<Self>, reason: AbandonReason) -> BoxFuture<'static, ()> {
        let tx = self.tx.take();
        Box::pin(async move {
            if let Some(tx) = tx {
                let _ = tx.send(Seen::Abandoned(reason));
            }
        })
    }
}

pub fn responder() -> (Box<dyn ApprovalResponder>, oneshot::Receiver<Seen>) {
    let (tx, rx) = oneshot::channel();
    (
        Box::new(TestResponder {
            tx: Some(tx),
            fail_respond: false,
        }),
        rx,
    )
}

pub fn failing_responder() -> (Box<dyn ApprovalResponder>, oneshot::Receiver<Seen>) {
    let (tx, rx) = oneshot::channel();
    (
        Box::new(TestResponder {
            tx: Some(tx),
            fail_respond: true,
        }),
        rx,
    )
}

/// Receives without waiting: `None` if nothing was sent yet.
pub fn try_seen(rx: &mut oneshot::Receiver<Seen>) -> Option<Seen> {
    rx.try_recv().ok()
}

pub const T0: i64 = 1_792_055_553_120;
pub const SESSION: &str = "s-1";

pub struct Harness {
    pub broker: Arc<Broker>,
    pub store: Store,
    pub clock: Arc<ManualClock>,
    pub registry: Arc<Registry>,
    pub pipeline: Arc<Pipeline>,
    pub devices: DeviceRegistry,
    pub settings: Arc<BrokerSettings>,
    pub bus: EventBus,
    pub audit: Audit,
    pub env: NormalizeEnv,
}

pub struct Phone {
    pub device_id: String,
    pub rx: mpsc::UnboundedReceiver<ConnCommand>,
    pub conn_id: u64,
}

impl Harness {
    pub fn new() -> Self {
        Self::with(default_classifier(), 120, 10, false, false)
    }

    pub fn with(
        classifier: ClassifierFn,
        ttl_s: u32,
        grace_s: u32,
        critical_local_only: bool,
        deny_requires_auth: bool,
    ) -> Self {
        let store = Store::open_in_memory().unwrap();
        let clock = Arc::new(ManualClock::new(T0));
        let registry = Arc::new(Registry::new());
        let bus = EventBus::new(256);
        let env = NormalizeEnv::new(
            clock.clone(),
            Arc::new(SequentialIdGen::default()),
            Arc::new(ProjectResolver::with_probe(
                Box::new(super::MapFs::default()),
                clock.clone(),
            )),
        );
        let pipeline = Arc::new(Pipeline::new(
            store.clone(),
            clock.clone(),
            registry.clone(),
            bus.clone(),
        ));
        let audit = Audit::new(store.clone(), clock.clone());
        let devices = DeviceRegistry::new(store.clone(), clock.clone());
        let settings = Arc::new(BrokerSettings::new(
            ttl_s,
            grace_s,
            critical_local_only,
            deny_requires_auth,
        ));
        let broker = Broker::new(BrokerDeps {
            store: store.clone(),
            clock: clock.clone(),
            pipeline: pipeline.clone(),
            registry: registry.clone(),
            bus: bus.clone(),
            audit: audit.clone(),
            devices: devices.clone(),
            env: env.clone(),
            settings: settings.clone(),
            classifier,
        });
        Self {
            broker,
            store,
            clock,
            registry,
            pipeline,
            devices,
            settings,
            bus,
            audit,
            env,
        }
    }

    pub fn now_ms(&self) -> i64 {
        use agentnest_core::state::Clock;
        self.clock.now_ms()
    }

    /// Registers a device in the database and connects it (fake socket).
    pub fn add_phone(&self, name: &str) -> Phone {
        let issued = self
            .devices
            .register(NewDevice {
                name: name.into(),
                platform: "android".into(),
                ..Default::default()
            })
            .unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        let conn_id = self.registry.register(&issued.device_id, tx);
        Phone {
            device_id: issued.device_id,
            rx,
            conn_id,
        }
    }

    pub async fn disconnect(&self, phone: &Phone) {
        self.registry.unregister(&phone.device_id, phone.conn_id);
        self.broker.device_disconnected().await;
    }

    pub fn draft(&self, tool: &str, input: Value) -> ApprovalDraft {
        self.draft_for(SESSION, None, tool, input)
    }

    pub fn draft_for(
        &self,
        session: &str,
        agent_id: Option<&str>,
        tool: &str,
        input: Value,
    ) -> ApprovalDraft {
        let mut ids = BTreeMap::new();
        ids.insert("tool_name".to_owned(), tool.to_owned());
        ids.insert(
            "tool_input_sha256".to_owned(),
            agentnest_protocol::canonical::tool_input_sha256(&input),
        );
        ids.insert("http_handle".to_owned(), uuid::Uuid::now_v7().to_string());
        ApprovalDraft {
            binding: NativeBinding {
                agent_kind: AgentKind::ClaudeCode,
                native_session_id: session.into(),
                ids,
            },
            session_key: format!("claude_code:{session}"),
            agent_kind: AgentKind::ClaudeCode,
            agent_id: agent_id.map(str::to_owned),
            project: None,
            cwd: Some("C:\\dev\\agentnest".into()),
            tool_name: tool.into(),
            tool_input: input,
            origin: SourceChannel::ClaudeCodeHookHttp,
            permission_mode: Some("default".into()),
            available_decisions: vec![Decision::Allow, Decision::Deny, Decision::DenyAndStop],
            permission_suggestions_count: Some(1),
            agent_description: Some("Run the tests".into()),
            reason: None,
            created_at: format_ms(self.now_ms()),
        }
    }

    pub async fn open(
        &self,
        draft: ApprovalDraft,
    ) -> (OpenOutcome, tokio::sync::oneshot::Receiver<Seen>) {
        let (r, rx) = responder();
        (self.broker.open(draft, r).await, rx)
    }

    /// A low-risk request that is open and waiting.
    pub async fn open_low(&self) -> (ApprovalRequest, tokio::sync::oneshot::Receiver<Seen>) {
        let (out, rx) = self
            .open(self.draft("Bash", json!({"command": "cargo test -p agentnest-core"})))
            .await;
        let OpenOutcome::Opened { request_id } = out else {
            panic!("expected Opened, got {out:?}");
        };
        (self.broker.pending_card(&request_id).await.unwrap(), rx)
    }

    /// A critical request (`rm -rf /`).
    pub async fn open_critical(&self) -> (ApprovalRequest, tokio::sync::oneshot::Receiver<Seen>) {
        let (out, rx) = self
            .open(self.draft("Bash", json!({"command": "rm -rf /"})))
            .await;
        let OpenOutcome::Opened { request_id } = out else {
            panic!("expected Opened, got {out:?}");
        };
        (self.broker.pending_card(&request_id).await.unwrap(), rx)
    }

    /// A fully valid phone decision for `card`.
    pub fn phone_decision(
        &self,
        card: &ApprovalRequest,
        device_id: &str,
        decision: Decision,
    ) -> DecisionInput {
        let now = self.now_ms();
        let extra = match (&card.risk.extra_confirmation, decision) {
            (_, Decision::Deny) | (ExtraConfirmation::None, _) => None,
            (ExtraConfirmation::Hold, _) => Some(ExtraConfirmationProof {
                method: ExtraConfirmationMethod::Hold,
                completed: true,
            }),
            _ => Some(ExtraConfirmationProof {
                method: ExtraConfirmationMethod::HoldAndReconfirm,
                completed: true,
            }),
        };
        DecisionInput {
            source: DecisionSource::Phone {
                device_id: device_id.to_owned(),
            },
            decision_id: uuid::Uuid::now_v7().to_string(),
            request_id: card.request_id.clone(),
            session_key: Some(card.session_key.clone()),
            nonce_b64: Some(Secret::new(card.nonce_b64.expose())),
            tool_input_sha256: card.tool_input_sha256.clone(),
            decision,
            reason: None,
            decided_at: Some(format_ms(now)),
            auth: Some(DecisionAuth {
                method: AuthMethod::Biometric,
                authenticated_at: Some(format_ms(now - 500)),
            }),
            extra_confirmation: extra,
            confirm_ack: false,
        }
    }

    pub fn row(&self, request_id: &str) -> agentnest_core::store::ApprovalRow {
        self.store.get_approval(request_id).unwrap().unwrap()
    }

    pub fn audit_actions(&self, request_id: &str) -> Vec<String> {
        self.store
            .list_approval_audit(request_id)
            .unwrap()
            .into_iter()
            .map(|a| a.action)
            .collect()
    }

    /// Advances the clock and runs the broker timer step.
    pub async fn advance(&self, ms: i64) {
        self.clock.advance(ms);
        self.broker.tick().await;
    }

    /// Message types broadcast so far through a subscription taken with `registry.subscribe()`.
    pub fn drain(rx: &mut tokio::sync::broadcast::Receiver<Arc<agentnest_core::link::registry::Published>>) -> Vec<(i64, String, Value)> {
        let mut out = Vec::new();
        while let Ok(p) = rx.try_recv() {
            out.push((p.seq, p.msg_type.clone(), p.payload.clone()));
        }
        out
    }
}

/// `b64_encode` re-export for tests building their own nonces.
pub fn b64(bytes: &[u8]) -> String {
    b64_encode(bytes)
}

// ---------------------------------------------------------------------------------------------------------------------
// loopback hook collector harness
// ---------------------------------------------------------------------------------------------------------------------

use agentnest_core::http::{
    self, DaemonInfo, GuardState, HookTokenVerifier, HttpContext, HttpServer, HttpSettings,
};
use agentnest_core::redact::HookToken;

pub const HOOK_TOKEN: &str = "an_hk_test_token_0123456789";

pub struct HttpHarness {
    pub h: Harness,
    pub server: Option<HttpServer>,
    pub port: u16,
    pub ctx: Arc<HttpContext>,
    pub settings: Arc<HttpSettings>,
}

impl HttpHarness {
    pub async fn new() -> Self {
        Self::with(Harness::new()).await
    }

    pub async fn with(h: Harness) -> Self {
        let settings = Arc::new(HttpSettings::new(true, false));
        let info = Arc::new(DaemonInfo::new(0, 47832));
        let ctx = HttpContext::new(
            h.pipeline.clone(),
            h.broker.clone(),
            h.clock.clone(),
            h.env.clone(),
            settings.clone(),
            info,
        );
        let guard = Arc::new(GuardState {
            tokens: HookTokenVerifier::new(&HookToken::new(HOOK_TOKEN)),
        });
        let router = http::router(ctx.clone(), guard);
        let (v4, v6) = http::bind_loopback(0).unwrap();
        let server = http::serve(router, v4, v6).unwrap();
        let port = server.port();
        Self {
            h,
            server: Some(server),
            port,
            ctx,
            settings,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, path)
    }

    /// POST with the valid token (blocking call on the blocking pool).
    pub async fn post(&self, path: &str, body: Value) -> (u16, String) {
        self.request("POST", path, &[("X-AgentNest-Token", HOOK_TOKEN)], Some(body.to_string().into_bytes()))
            .await
    }

    pub async fn request(
        &self,
        method: &'static str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> (u16, String) {
        let url = self.url(path);
        let headers: Vec<(String, String)> =
            headers.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
        tokio::task::spawn_blocking(move || http_call(method, &url, &headers, body))
            .await
            .unwrap()
    }
}

/// A blocking HTTP call that reports the status of any response (4xx/5xx included).
pub fn http_call(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<Vec<u8>>,
) -> (u16, String) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build()
        .into();
    let result = match method {
        "GET" => {
            let mut req = agent.get(url);
            for (k, v) in headers {
                req = req.header(k, v);
            }
            req.call()
        }
        _ => {
            let mut req = agent.post(url);
            for (k, v) in headers {
                req = req.header(k, v);
            }
            req.send(body.unwrap_or_default())
        }
    };
    match result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.into_body().read_to_string().unwrap_or_default();
            (status, text)
        }
        Err(e) => panic!("transport error: {e}"),
    }
}

/// A PermissionRequest hook body for a Bash command.
pub fn permission_request(session: &str, command: &str) -> Value {
    json!({
        "hook_event_name": "PermissionRequest",
        "session_id": session,
        "cwd": "C:\\dev\\agentnest",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_input": {"command": command, "description": "test"},
        "permission_suggestions": [{"type": "addRules"}]
    })
}

/// Waits (polling, bounded) until `f` returns `Some`.
pub async fn eventually<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    for _ in 0..400 {
        if let Some(v) = f() {
            return v;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}
