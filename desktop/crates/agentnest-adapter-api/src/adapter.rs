//! The adapter plugin trait and its supporting types.

use futures_util::future::BoxFuture;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch};

use agentnest_protocol::{AdapterMode, AdapterStatusKind, AgentKind, Decision, SourceChannel};

use crate::observation::RawObservation;

/// What an adapter can do.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct AdapterCapabilities {
    /// Sessions started by the user can be observed.
    pub observe_sessions: bool,
    /// Approval requests can be answered.
    pub remote_approval: bool,
    /// Subset of `{allow, deny, deny_and_stop}` the native protocol can express. Scope-expanding decisions do not exist.
    pub approval_decisions: Vec<Decision>,
    /// Can start a turn (Phase 2).
    pub start_turn: bool,
    /// Provides review results.
    pub review: bool,
    /// Provides token usage.
    pub token_usage: bool,
    /// Needs the `/v1/hooks/<kind>` route.
    pub hook_ingest: bool,
}

/// Adapter health, reported as `RawObservation::Health` and by [`AgentAdapter::health`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdapterHealth {
    /// Status.
    pub status: AdapterStatusKind,
    /// Collection mode.
    pub mode: AdapterMode,
    /// Human readable detail.
    pub detail: Option<String>,
}

/// Errors of adapter start-up and operation.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// The adapter is not configured (hooks missing, socket absent, ...).
    #[error("adapter not configured: {0}")]
    NotConfigured(String),
    /// The feature is disabled in this build.
    #[error("feature disabled: {0}")]
    FeatureDisabled(&'static str),
    /// I/O failure.
    #[error("io error: {0}")]
    Io(String),
    /// Anything else.
    #[error("{0}")]
    Other(String),
}

/// Sends observations from an adapter to the daemon.
#[derive(Clone, Debug)]
pub struct ObservationSink(mpsc::Sender<RawObservation>);

impl ObservationSink {
    /// Wraps a channel sender.
    pub fn new(sender: mpsc::Sender<RawObservation>) -> Self {
        Self(sender)
    }

    /// Emits an observation. Returns `false` if the daemon side is gone.
    pub async fn emit(&self, observation: RawObservation) -> bool {
        self.0.send(observation).await.is_ok()
    }
}

/// Handed to [`AgentAdapter::start`].
#[derive(Debug)]
pub struct AdapterContext {
    /// Where to send observations.
    pub sink: ObservationSink,
    /// Flips to `true` when the daemon shuts down.
    pub shutdown: watch::Receiver<bool>,
}

/// Returned by [`AgentAdapter::start`]; stops the adapter.
#[derive(Debug)]
pub struct AdapterHandle {
    shutdown: Option<oneshot::Sender<()>>,
}

impl AdapterHandle {
    /// A handle whose `shutdown` signals the given channel.
    pub fn new(shutdown: oneshot::Sender<()>) -> Self {
        Self {
            shutdown: Some(shutdown),
        }
    }

    /// A handle for adapters that have nothing to stop (pure hook ingestion).
    pub fn noop() -> Self {
        Self { shutdown: None }
    }

    /// Signals the adapter to stop.
    pub fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Metadata of an inbound hook request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookMeta {
    /// Channel the hook arrived on.
    pub channel: SourceChannel,
    /// Receive time (RFC 3339 UTC).
    pub received_at: String,
    /// Body size in bytes.
    pub content_length: usize,
}

/// Reply to a hook request.
#[derive(Clone, Debug, PartialEq)]
pub enum HookReply {
    /// 204 / empty body: the agent proceeds as if the hook had no opinion. This is the fail-closed reply.
    Empty,
    /// A JSON body for the agent. Never contains `updatedInput` / `updatedPermissions` (security.md I11).
    Json(serde_json::Value),
}

/// An agent integration.
pub trait AgentAdapter: Send + Sync + 'static {
    /// Agent family.
    fn kind(&self) -> AgentKind;

    /// Display label (`Claude Code`, `Codex`).
    fn label(&self) -> &'static str;

    /// Capabilities.
    fn capabilities(&self) -> AdapterCapabilities;

    /// Starts the adapter.
    fn start(&self, ctx: AdapterContext)
        -> BoxFuture<'static, Result<AdapterHandle, AdapterError>>;

    /// Handles an inbound hook. The default ignores it (an empty reply). A held `PermissionRequest` may resolve this
    /// future late, after the responder was answered or abandoned.
    fn ingest_hook(
        &self,
        _body: serde_json::Value,
        _meta: HookMeta,
    ) -> BoxFuture<'static, HookReply> {
        Box::pin(async { HookReply::Empty })
    }

    /// Current health.
    fn health(&self) -> BoxFuture<'static, AdapterHealth>;
}
