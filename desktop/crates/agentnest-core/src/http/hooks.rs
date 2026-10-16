//! The hook routes (docs/integrations/claude-code.md 4, codex.md 5.2):
//! `POST /v1/hooks/claude-code`, `POST /v1/hooks/codex`, `POST /v1/statusline/claude-code`, `GET /v1/health`,
//! `GET /v1/daemon`.
//!
//! # Reply rules
//!
//! * Observation hooks are queued and answered **at once** with `204` (target < 10 ms); a worker normalises, stores and
//!   publishes them.
//! * `PreToolUse` may be answered with exactly one body: the `ask` reply of
//!   [`pre_tool_use_ask_reply`](crate::adapters::claude_code::pre_tool_use_ask_reply) for a critical call (when
//!   `risk.force_ask_on_critical` is on). **Never `allow`.** Codex `PreToolUse` is always `204`.
//! * `PermissionRequest` is **held**: the handler opens an approval with the broker and waits until the broker answers (a
//!   validated decision -> `200` JSON) or ends it without a decision (-> `204`, empty). Every error, panic recovery and
//!   timeout in that path is `204`: "no decision", the agent falls back to its local prompt. If the agent drops the
//!   connection, the [`DropGuard`] marks the request `superseded`.
//! * A malformed body is `400` (a caller bug, not a hook failure); guard failures are `401`/`403`/`413`
//!   ([`super::guard`]); the observation rate limit is `429` (never for `PermissionRequest`).

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentnest_adapter_api::{
    AdapterMode, AdapterStatusKind, AgentKind, RawObservation, SourceChannel,
};
use agentnest_protocol::canonical::tool_input_sha256;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use futures_util::FutureExt;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::adapters::claude_code::responder::{HookFlavor, HookOutcome, HookResponder};
use crate::adapters::claude_code::{
    hook_event_name, normalize as claude_normalize, permission_request_draft as claude_draft,
    pre_tool_use_ask_reply, pre_tool_use_risk, statusline, NormalizeCtx,
};
use crate::approvals::broker::{Broker, OpenOutcome, ToolObservation};
use crate::approvals::correlator::HookPhase;
use crate::approvals::drop_guard::DropGuard;
use crate::http::guard::HookAuth;
use crate::normalize::dedupe::{dedupe_key, DedupeKey, DedupeWindow};
use crate::normalize::NormalizeEnv;
use crate::pipeline::Pipeline;
use crate::ratelimit::TokenBucket;
use crate::state::timers::Clock;

/// Observation hooks per second before `429` (security.md 11; `PermissionRequest` is exempt).
pub const OBSERVATION_RATE_PER_S: u32 = 200;
/// Extra time the handler waits beyond the TTL before it gives up on a held request (the broker's timer is the real limit).
const HOLD_SLACK_MS: u64 = 20_000;
/// Queue length of the observation worker.
const QUEUE_LEN: usize = 8192;

/// Settings the daemon can change at run time.
#[derive(Debug)]
pub struct HttpSettings {
    /// Answer a critical `PreToolUse` with `ask`.
    pub force_ask_on_critical: AtomicBool,
    /// Hold Codex hooks `PermissionRequest` (feature `codex-hooks-approval` AND Codex mode hooks). UNVERIFIED (C6).
    pub codex_hold: AtomicBool,
    /// Extra time (ms) a held request waits beyond the approval TTL for the broker's own answer before the handler
    /// answers "no decision" itself (the broker timer not running is an abnormal case). Tests shorten it.
    pub hold_slack_ms: AtomicU64,
    /// `PermissionRequest`s that arrive through Claude Code's own `type: "http"` hooks may be answered. The daemon turns
    /// this off while the installed HTTP hooks point at another port than the one the collector listens on: such a
    /// request did not come through the hook configuration, and an HTTP hook cannot authenticate the daemon (security.md
    /// 1.2). Command hooks (`agentnest-hook`) authenticate both ways and are not affected.
    pub http_approvals_enabled: AtomicBool,
}

impl HttpSettings {
    /// Settings with the given values; approvals over HTTP hooks are enabled.
    pub fn new(force_ask_on_critical: bool, codex_hold: bool) -> Self {
        Self {
            force_ask_on_critical: AtomicBool::new(force_ask_on_critical),
            codex_hold: AtomicBool::new(codex_hold),
            hold_slack_ms: AtomicU64::new(HOLD_SLACK_MS),
            http_approvals_enabled: AtomicBool::new(true),
        }
    }

    /// Like [`HttpSettings::new`], but approvals over HTTP hooks start **closed** (answered with "no decision") until the
    /// owner opens the gate after checking that the installed hooks point at this collector. The daemon builds its
    /// settings this way so that nothing can be answered between "listening" and "verified".
    pub fn new_closed(force_ask_on_critical: bool, codex_hold: bool) -> Self {
        let s = Self::new(force_ask_on_critical, codex_hold);
        s.http_approvals_enabled.store(false, Ordering::Relaxed);
        s
    }
}

/// What `GET /v1/daemon` reports.
#[derive(Debug)]
pub struct DaemonInfo {
    /// Collector port.
    pub hook_port: AtomicU16,
    /// WSS link port.
    pub wss_port: AtomicU16,
    started: Instant,
}

impl DaemonInfo {
    /// Info with the ports.
    pub fn new(hook_port: u16, wss_port: u16) -> Self {
        Self {
            hook_port: AtomicU16::new(hook_port),
            wss_port: AtomicU16::new(wss_port),
            started: Instant::now(),
        }
    }

    /// Seconds since start.
    pub fn uptime_s(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Adapter {
    Claude,
    Codex,
}

struct QueuedHook {
    adapter: Adapter,
    value: Value,
    channel: SourceChannel,
    key: Option<DedupeKey>,
}

/// Shared state of the hook routes.
pub struct HttpContext {
    pipeline: Arc<Pipeline>,
    broker: Arc<Broker>,
    clock: Arc<dyn Clock>,
    env: NormalizeEnv,
    settings: Arc<HttpSettings>,
    info: Arc<DaemonInfo>,
    queue: mpsc::Sender<QueuedHook>,
    dedupe: Mutex<DedupeWindow>,
    rate: Mutex<TokenBucket>,
    statusline_seen: Mutex<HashMap<String, i64>>,
}

impl std::fmt::Debug for HttpContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpContext").finish_non_exhaustive()
    }
}

impl HttpContext {
    /// Builds the context and starts the observation worker (needs a tokio runtime).
    pub fn new(
        pipeline: Arc<Pipeline>,
        broker: Arc<Broker>,
        clock: Arc<dyn Clock>,
        env: NormalizeEnv,
        settings: Arc<HttpSettings>,
        info: Arc<DaemonInfo>,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(QUEUE_LEN);
        let now = clock.now_ms();
        let ctx = Arc::new(Self {
            pipeline: pipeline.clone(),
            broker: broker.clone(),
            clock,
            env: env.clone(),
            settings,
            info,
            queue: tx,
            dedupe: Mutex::new(DedupeWindow::default()),
            rate: Mutex::new(TokenBucket::new(
                OBSERVATION_RATE_PER_S,
                OBSERVATION_RATE_PER_S,
                now,
            )),
            statusline_seen: Mutex::new(HashMap::new()),
        });
        tokio::spawn(worker(rx, pipeline, broker, env));
        ctx
    }

    fn rate_ok(&self) -> bool {
        let now = self.clock.now_ms();
        match self.rate.lock() {
            Ok(mut r) => r.try_acquire(now),
            Err(e) => e.into_inner().try_acquire(now),
        }
    }

    fn is_duplicate(&self, key: &DedupeKey) -> bool {
        let now = self.clock.now_ms();
        match self.dedupe.lock() {
            Ok(mut d) => d.is_duplicate(&key.key, now),
            Err(e) => e.into_inner().is_duplicate(&key.key, now),
        }
    }
}

fn no_decision() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

fn json_reply(v: Value) -> Response {
    (StatusCode::OK, Json(v)).into_response()
}

#[allow(clippy::result_large_err)]
fn parse_body(body: &Bytes) -> Result<Value, Response> {
    match serde_json::from_slice::<Value>(body) {
        Ok(v @ Value::Object(_)) => Ok(v),
        _ => Err(StatusCode::BAD_REQUEST.into_response()),
    }
}

/// The channel a Claude Code hook request used. It follows from **how the request authenticated** (the guard's
/// [`HookAuth`]), never from a header the caller is free to set: only a request that passed the relay's one-time proof is
/// a command-hook (CLI) request; a request that merely knows the token is an HTTP-hook request, whatever it claims.
fn claude_channel(auth: HookAuth) -> SourceChannel {
    match auth {
        HookAuth::RelayProof => SourceChannel::ClaudeCodeHookCli,
        HookAuth::Token | HookAuth::None => SourceChannel::ClaudeCodeHookHttp,
    }
}

fn queue_hook(ctx: &HttpContext, hook: QueuedHook) -> Response {
    match ctx.queue.try_send(hook) {
        Ok(()) => no_decision(),
        Err(_) => StatusCode::TOO_MANY_REQUESTS.into_response(),
    }
}

fn session_id(v: &Value) -> &str {
    v.get("session_id").and_then(Value::as_str).unwrap_or("")
}

fn observation_key(v: &Value, name: &str, body: &Bytes) -> Option<DedupeKey> {
    let sid = session_id(v);
    if sid.is_empty() {
        return None;
    }
    let tool_use_id = v.get("tool_use_id").and_then(Value::as_str);
    Some(dedupe_key(sid, name, tool_use_id, body))
}

/// `POST /v1/hooks/claude-code`.
pub async fn claude_hook(
    State(ctx): State<Arc<HttpContext>>,
    Extension(auth): Extension<HookAuth>,
    body: Bytes,
) -> Response {
    let value = match parse_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let name = hook_event_name(&value).unwrap_or("").to_owned();
    let channel = claude_channel(auth);
    if name == "PermissionRequest" {
        if channel == SourceChannel::ClaudeCodeHookHttp
            && !ctx.settings.http_approvals_enabled.load(Ordering::Relaxed)
        {
            // hook_port_unavailable: the installed HTTP hooks point elsewhere; never answer approvals here
            tracing::warn!("a PermissionRequest over HTTP is not answered: the installed hooks point at another port");
            return no_decision();
        }
        return hold(ctx, HookFlavor::Claude, value, channel).await;
    }
    if !ctx.rate_ok() {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    // PreToolUse: the only hook that can get a body, and only `ask`
    let ask = if name == "PreToolUse" {
        let force = ctx.settings.force_ask_on_critical.load(Ordering::Relaxed);
        pre_tool_use_risk(&value).and_then(|risk| pre_tool_use_ask_reply(&risk, force))
    } else {
        None
    };
    let key = observation_key(&value, &name, &body);
    if let Some(k) = &key {
        if ctx.is_duplicate(k) {
            return match ask {
                Some(v) => json_reply(v),
                None => no_decision(),
            };
        }
    }
    let queued = queue_hook(
        &ctx,
        QueuedHook {
            adapter: Adapter::Claude,
            value,
            channel,
            key,
        },
    );
    match ask {
        Some(v) if queued.status() == StatusCode::NO_CONTENT => json_reply(v),
        _ => queued,
    }
}

/// `POST /v1/hooks/codex`. `PreToolUse` is always `204` (observation only).
pub async fn codex_hook(State(ctx): State<Arc<HttpContext>>, body: Bytes) -> Response {
    let value = match parse_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let name = hook_event_name(&value).unwrap_or("").to_owned();
    if name == "PermissionRequest" {
        // UNVERIFIED (Phase 0 C6): whether a hooks PermissionRequest can be answered. Until then it is observed only.
        if cfg!(feature = "codex-hooks-approval") && ctx.settings.codex_hold.load(Ordering::Relaxed)
        {
            return hold(ctx, HookFlavor::Codex, value, SourceChannel::CodexHookCli).await;
        }
        return no_decision();
    }
    if !ctx.rate_ok() {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let key = observation_key(&value, &name, &body);
    if let Some(k) = &key {
        if ctx.is_duplicate(k) {
            return no_decision();
        }
    }
    queue_hook(
        &ctx,
        QueuedHook {
            adapter: Adapter::Codex,
            value,
            channel: SourceChannel::CodexHookCli,
            key,
        },
    )
}

/// `POST /v1/statusline/claude-code`.
pub async fn statusline_hook(State(ctx): State<Arc<HttpContext>>, body: Bytes) -> Response {
    let value = match parse_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some((session_key, patch)) = statusline::parse(&value) else {
        return no_decision();
    };
    let now = ctx.clock.now_ms();
    {
        let mut seen = match ctx.statusline_seen.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if seen
            .get(&session_key)
            .is_some_and(|t| now - *t < statusline::THROTTLE_MS)
        {
            return no_decision();
        }
        seen.insert(session_key.clone(), now);
        if seen.len() > 512 {
            seen.retain(|_, t| now - *t < statusline::THROTTLE_MS);
        }
    }
    let pipeline = ctx.pipeline.clone();
    tokio::spawn(async move {
        pipeline
            .apply_meta(&session_key, AgentKind::ClaudeCode, &patch)
            .await;
    });
    no_decision()
}

/// `GET /v1/health`.
pub async fn health() -> Response {
    json_reply(json!({ "ok": true, "version": env!("CARGO_PKG_VERSION") }))
}

/// `GET /v1/daemon`.
pub async fn daemon(State(ctx): State<Arc<HttpContext>>) -> Response {
    json_reply(json!({
        "hook_port": ctx.info.hook_port.load(Ordering::Relaxed),
        "wss_port": ctx.info.wss_port.load(Ordering::Relaxed),
        "uptime_s": ctx.info.uptime_s(),
    }))
}

// ---------------------------------------------------------------------------------------------------------------------
// the held PermissionRequest
// ---------------------------------------------------------------------------------------------------------------------

/// Holds a `PermissionRequest` until the broker answers or ends it. Every failure is "no decision" (`204`).
async fn hold(
    ctx: Arc<HttpContext>,
    flavor: HookFlavor,
    value: Value,
    channel: SourceChannel,
) -> Response {
    let draft_result = match flavor {
        HookFlavor::Claude => {
            let ctx_norm = NormalizeCtx {
                env: &ctx.env,
                channel,
            };
            claude_draft(&value, &ctx_norm).map_err(|e| e.to_string())
        }
        HookFlavor::Codex => {
            crate::adapters::codex::hooks::permission_request_draft(&value, &ctx.env)
                .map_err(|e| e.to_string())
        }
    };
    let mut draft = match draft_result {
        Ok(d) => d,
        Err(_) => return no_decision(),
    };
    // A unique id per held request makes "this very HTTP connection went away" exactly addressable.
    draft
        .binding
        .ids
        .insert("http_handle".to_owned(), uuid::Uuid::now_v7().to_string());
    let (responder, rx) = HookResponder::new(flavor);
    let mut guard = DropGuard::new(ctx.broker.clone(), draft.binding.clone());
    let wait = Duration::from_millis(
        u64::try_from(ctx.broker.settings().ttl_ms()).unwrap_or(120_000)
            + ctx.settings.hold_slack_ms.load(Ordering::Relaxed),
    );
    let broker = ctx.broker.clone();
    let opened = AssertUnwindSafe(async move { broker.open(draft, Box::new(responder)).await })
        .catch_unwind()
        .await;
    match opened {
        Ok(OpenOutcome::Failed) | Err(_) => {
            // internal error or a recovered panic: the responder was dropped or abandoned, so "no decision"
            guard.disarm();
            return no_decision();
        }
        Ok(_) => {}
    }
    let outcome = tokio::time::timeout(wait, rx).await;
    match outcome {
        Ok(Ok(HookOutcome::Json(v))) => {
            guard.disarm();
            json_reply(v)
        }
        Ok(Ok(HookOutcome::Empty)) | Ok(Err(_)) => {
            guard.disarm();
            no_decision()
        }
        // The broker did not answer in time (its timer is not running): answer "no decision" and let the guard close
        // the request as superseded.
        Err(_) => no_decision(),
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// the observation worker
// ---------------------------------------------------------------------------------------------------------------------

async fn worker(
    mut rx: mpsc::Receiver<QueuedHook>,
    pipeline: Arc<Pipeline>,
    broker: Arc<Broker>,
    env: NormalizeEnv,
) {
    let mut claude_seen = false;
    let mut codex_seen = false;
    while let Some(hook) = rx.recv().await {
        let adapter = hook.adapter;
        let value = hook.value;
        let key = hook.key;
        let channel = hook.channel;
        let env2 = env.clone();
        let channel_norm = channel.clone();
        let value_for_norm = value.clone();
        // normalisation reads the file system (project resolution): keep it off the async threads
        let observations = tokio::task::spawn_blocking(move || match adapter {
            Adapter::Claude => claude_normalize(
                &value_for_norm,
                &NormalizeCtx {
                    env: &env2,
                    channel: channel_norm,
                },
            ),
            Adapter::Codex => crate::adapters::codex::hooks::normalize(&value_for_norm, &env2),
        })
        .await
        .unwrap_or_default();

        let mut first_event_id: Option<String> = None;
        for (i, obs) in observations.into_iter().enumerate() {
            match obs {
                RawObservation::Event(e) => {
                    first_event_id.get_or_insert_with(|| e.event_id.clone());
                    let db_key = key
                        .as_ref()
                        .filter(|k| k.from_tool_use_id)
                        .map(|k| format!("{}:{i}", k.key));
                    pipeline.ingest_event(e, db_key).await;
                }
                RawObservation::SessionMeta { session_key, patch } => {
                    pipeline
                        .apply_meta(&session_key, adapter_kind(adapter), &patch)
                        .await;
                }
                RawObservation::Health(h) => {
                    pipeline
                        .set_adapter_status(adapter_kind(adapter), h.status, h.mode, h.detail)
                        .await;
                }
                // approvals do not arrive through the observation path
                RawObservation::ApprovalOpened { responder, .. } => {
                    responder
                        .abandon(agentnest_adapter_api::AbandonReason::InternalError)
                        .await;
                }
                RawObservation::ApprovalClosedByAgent { .. }
                | RawObservation::ApprovalOutcomeObserved { .. } => {}
            }
        }
        // the first hook of an adapter marks it connected
        let seen = match adapter {
            Adapter::Claude => &mut claude_seen,
            Adapter::Codex => &mut codex_seen,
        };
        if !*seen {
            *seen = true;
            let (kind, mode, detail) = match adapter {
                Adapter::Claude => (
                    AgentKind::ClaudeCode,
                    if channel == SourceChannel::ClaudeCodeHookCli {
                        AdapterMode::HooksCli
                    } else {
                        AdapterMode::HooksHttp
                    },
                    "hooks installed (user settings)",
                ),
                Adapter::Codex => (
                    AgentKind::Codex,
                    AdapterMode::HooksCli,
                    "hooks mode · review: not available (hooks mode)",
                ),
            };
            pipeline
                .set_adapter_status(
                    kind,
                    AdapterStatusKind::Connected,
                    mode,
                    Some(detail.to_owned()),
                )
                .await;
        }
        // outcome correlation for approved / denied calls
        let name = hook_event_name(&value).unwrap_or("");
        let phase = match name {
            "PreToolUse" => Some(HookPhase::Pre),
            "PostToolUse" => Some(HookPhase::Post),
            "PostToolUseFailure" => Some(HookPhase::PostFailure),
            _ => None,
        };
        if let (Some(phase), Some(tool), Some(sid)) = (
            phase,
            value.get("tool_name").and_then(Value::as_str),
            value.get("session_id").and_then(Value::as_str),
        ) {
            let input = value.get("tool_input").cloned().unwrap_or(Value::Null);
            let prefix = match adapter {
                Adapter::Claude => "claude_code",
                Adapter::Codex => "codex",
            };
            broker
                .observe_tool(ToolObservation {
                    session_key: format!("{prefix}:{sid}"),
                    tool_name: tool.to_owned(),
                    input_sha256: tool_input_sha256(&input),
                    phase,
                    evidence_event_id: first_event_id
                        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string()),
                })
                .await;
        }
    }
}

fn adapter_kind(a: Adapter) -> AgentKind {
    match a {
        Adapter::Claude => AgentKind::ClaudeCode,
        Adapter::Codex => AgentKind::Codex,
    }
}
