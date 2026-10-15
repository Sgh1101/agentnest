//! The approval broker: the **single path** through which an approval request changes state (docs/security.md 6, I4, I5;
//! docs/integrations/claude-code.md 6; docs/storage.md 2).
//!
//! # What it owns
//!
//! * the table of **pending requests** with their open native handles (the `ApprovalResponder`s: an open HTTP request
//!   for Claude Code / Codex hooks, a JSON-RPC request id for the Codex app-server),
//! * every transition out of `pending`:
//!
//!   | transition | how | agent sees |
//!   | --- | --- | --- |
//!   | decided | [`Broker::apply_decision`] (phone or desktop, validated) | allow / deny reply |
//!   | `expired` | [`Broker::tick`] at `expires_at` | nothing (empty 2xx / no reply) |
//!   | `handed_off_local` | no device online, grace over, "handle locally", pause, link off, device revoked, shutdown | nothing |
//!   | `superseded` | the agent closed it first ([`Broker::agent_closed`], [`crate::approvals::drop_guard::DropGuard`]) | n/a |
//!   | startup | [`Broker::recover_on_startup`] expires every row left `pending` by a previous process | n/a |
//!
//! # The one place that can allow (I5)
//!
//! An allow reply can only be created by [`Broker::apply_decision`], in the success branch that follows the nine
//! validation steps and the conditional `UPDATE`. Everything else in this file (expiry, hand-off, errors, panics
//! recovery, `abandon`) can only end in "no decision". CI greps for a second creation site; do not add one.
//!
//! # Locking
//!
//! One `tokio` mutex guards the pending table and is held from the database write to the reply, so decisions, expiries
//! and hand-offs of a request are strictly serialised (this is the "single writer" of storage.md). Publishing to the
//! pipeline happens under that lock (lock order: broker, then pipeline).

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;

use agentnest_adapter_api::{
    AbandonReason, AgentCloseReason, ApprovalDraft, ApprovalReply, ApprovalResponder, ApplyProof,
    NativeBinding,
};
use agentnest_protocol::canonical::tool_input_sha256;
use agentnest_protocol::qr::b64_encode;
use agentnest_protocol::{
    AgentKind, ApprovalOutcome, ApprovalRequest, ApprovalResolvedPayload, Decision,
    DecisionResultReason, Delivery, EventKind, LocalPrompt, ObservedResult,
    ProjectRef, RemoteApproval, ResolvedBy, Risk, RiskLevel, Secret, SourceChannel,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::json;
use tokio::sync::Mutex;

use crate::approvals::card::{
    build_details, deny_message, decision_result_message_ko, purpose, resolved_message_ko,
    risk_level_str,
};
use crate::approvals::correlator::{Correlator, HookPhase, Observation, TrackedOutcome};
use crate::approvals::validator::{
    validate, CardView, DecisionInput, DecisionSource, RequestStatus, ValidationEnv,
};
use crate::audit::{approval_actions, Audit};
use crate::auth::devices::DeviceRegistry;
use crate::events::{ApprovalChannel, ApprovalUiEvent, DaemonEvent, EventBus};
use crate::link::registry::Registry;
use crate::normalize::post::{build_event, EventDraft};
use crate::normalize::NormalizeEnv;
use crate::pipeline::Pipeline;
use crate::risk::classify::{classify_input, RiskInput};
use crate::risk::rules::Level;
use crate::state::reducer::{agent_label, remote_approval_for_mode};
use crate::state::timers::{format_ms, Clock};
use crate::store::{
    CloseRequest, CloseStatus, NewApproval, NewDecision, ResolveOutcome, ResolveRequest, Store,
    StoreError,
};
use agentnest_protocol::{AgentState, Severity};

/// Duplicate hooks of the same call (user and project settings both define the hook) arrive within this window and
/// share one card (claude-code.md 6). Requests of different `agent_id`s, or further apart, are separate cards.
///
/// Phase 0 A14 (does `PermissionRequest` carry `agent_id`?) is open; until it is answered the window also applies to
/// requests without an `agent_id` (both sides `""`).
pub const MERGE_WINDOW_MS: i64 = 2_000;

/// The classifier signature (injectable so that tests can prove the fail-closed panic path).
pub type ClassifierFn = for<'a> fn(&RiskInput<'a>) -> Risk;

/// The production classifier: [`classify_input`] (code-constant rules, a failure or panic is `critical`).
pub fn default_classifier() -> ClassifierFn {
    classify_input
}

/// Settings the daemon changes at run time. Cheap atomics; the broker reads them on every request.
#[derive(Debug)]
pub struct BrokerSettings {
    ttl_ms: AtomicI64,
    grace_ms: AtomicI64,
    critical_local_only: AtomicBool,
    deny_requires_auth: AtomicBool,
    paused: AtomicBool,
    merge_window_ms: AtomicI64,
}

impl BrokerSettings {
    /// Settings with the effective TTL (seconds), grace (seconds) and the two policy switches.
    pub fn new(
        effective_ttl_s: u32,
        reconnect_grace_s: u32,
        critical_local_only: bool,
        deny_requires_auth: bool,
    ) -> Self {
        Self {
            ttl_ms: AtomicI64::new(i64::from(effective_ttl_s) * 1000),
            grace_ms: AtomicI64::new(i64::from(reconnect_grace_s) * 1000),
            critical_local_only: AtomicBool::new(critical_local_only),
            deny_requires_auth: AtomicBool::new(deny_requires_auth),
            paused: AtomicBool::new(false),
            merge_window_ms: AtomicI64::new(MERGE_WINDOW_MS),
        }
    }

    /// Effective TTL in milliseconds.
    pub fn ttl_ms(&self) -> i64 {
        self.ttl_ms.load(Ordering::Relaxed)
    }

    /// Sets the effective TTL in milliseconds.
    pub fn set_ttl_ms(&self, ms: i64) {
        self.ttl_ms.store(ms, Ordering::Relaxed);
    }

    /// Reconnect grace in milliseconds.
    pub fn grace_ms(&self) -> i64 {
        self.grace_ms.load(Ordering::Relaxed)
    }

    /// Sets the reconnect grace in milliseconds.
    pub fn set_grace_ms(&self, ms: i64) {
        self.grace_ms.store(ms, Ordering::Relaxed);
    }

    /// `true` if critical requests never go to the phone.
    pub fn critical_local_only(&self) -> bool {
        self.critical_local_only.load(Ordering::Relaxed)
    }

    /// Sets `approval.critical_remote == local_only`.
    pub fn set_critical_local_only(&self, v: bool) {
        self.critical_local_only.store(v, Ordering::Relaxed);
    }

    /// `true` if a deny also needs authentication.
    pub fn deny_requires_auth(&self) -> bool {
        self.deny_requires_auth.load(Ordering::Relaxed)
    }

    /// Sets `approval.deny_requires_auth`.
    pub fn set_deny_requires_auth(&self, v: bool) {
        self.deny_requires_auth.store(v, Ordering::Relaxed);
    }

    /// `true` while remote approval is paused.
    pub fn paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    fn set_paused(&self, v: bool) {
        self.paused.store(v, Ordering::SeqCst);
    }

    /// The duplicate merge window in milliseconds.
    pub fn merge_window_ms(&self) -> i64 {
        self.merge_window_ms.load(Ordering::Relaxed)
    }

    /// Overrides the merge window (`0` never merges).
    pub fn set_merge_window_ms(&self, ms: i64) {
        self.merge_window_ms.store(ms, Ordering::Relaxed);
    }
}

/// Everything the broker is built from.
pub struct BrokerDeps {
    /// Storage.
    pub store: Store,
    /// Clock (server time is the only time used for security judgements).
    pub clock: Arc<dyn Clock>,
    /// Event pipeline (timeline events, stream, reducers).
    pub pipeline: Arc<Pipeline>,
    /// Connections (presence, live fan-out).
    pub registry: Arc<Registry>,
    /// Desktop event bus.
    pub bus: EventBus,
    /// Audit writer.
    pub audit: Audit,
    /// Device registry (revocation check of step 1).
    pub devices: DeviceRegistry,
    /// Normalisation environment (ids, clock, projects) for the timeline events.
    pub env: NormalizeEnv,
    /// Run-time settings.
    pub settings: Arc<BrokerSettings>,
    /// The risk classifier.
    pub classifier: ClassifierFn,
}

/// How a request was routed when it arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Remote,
    NoDevice,
    Paused,
    CriticalLocalOnly,
    Unavailable,
}

impl Route {
    fn channel(self) -> ApprovalChannel {
        match self {
            Route::Remote => ApprovalChannel::Remote,
            Route::NoDevice => ApprovalChannel::NoDevice,
            _ => ApprovalChannel::LocalOnly,
        }
    }

    fn channel_str(self) -> &'static str {
        match self {
            Route::Remote => "remote",
            Route::NoDevice => "no_device",
            _ => "local_only",
        }
    }

    fn abandon_reason(self) -> AbandonReason {
        match self {
            Route::NoDevice => AbandonReason::NoOnlineDevice,
            Route::Paused => AbandonReason::RemoteApprovalPaused,
            _ => AbandonReason::HandedOffToDesktop,
        }
    }
}

/// What [`Broker::open`] did with a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenOutcome {
    /// A new card is waiting for a decision.
    Opened {
        /// The request.
        request_id: String,
    },
    /// The handle joined an identical pending request (duplicate hook within the merge window).
    Merged {
        /// The existing request.
        request_id: String,
    },
    /// The request was handed to the local prompt immediately (no device, paused, critical local-only, ...).
    HandedOff {
        /// The request.
        request_id: String,
        /// Why no phone is involved.
        channel: ApprovalChannel,
    },
    /// Internal failure; the handle was abandoned (empty reply).
    Failed,
}

/// The result of a decision attempt, for `decision_result`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionOutcome {
    /// The request.
    pub request_id: String,
    /// Applied?
    pub accepted: bool,
    /// Reason code.
    pub reason: DecisionResultReason,
    /// Korean text.
    pub message_ko: String,
}

struct Handle {
    binding: NativeBinding,
    responder: Box<dyn ApprovalResponder>,
}

#[derive(Clone, Debug, Default)]
struct DeliveryTimes {
    sent_at: Option<String>,
    acked_at: Option<String>,
    seen_at: Option<String>,
}

struct Entry {
    card: ApprovalRequest,
    nonce: Vec<u8>,
    expires_ms: i64,
    created_ms: i64,
    handles: Vec<Handle>,
    delivery: BTreeMap<String, DeliveryTimes>,
    agent_kind: AgentKind,
    native_session_id: String,
    agent_id: Option<String>,
    cwd: Option<String>,
    origin: SourceChannel,
}

struct ResolvedRecord {
    payload: ApprovalResolvedPayload,
    resolved_ms: i64,
}

struct State {
    pending: HashMap<String, Entry>,
    correlator: Correlator,
    resolved: HashMap<String, ResolvedRecord>,
    grace_deadline_ms: Option<i64>,
}

/// A tool hook observed after approvals (see [`Broker::observe_tool`]).
#[derive(Clone, Debug)]
pub struct ToolObservation {
    /// Session key.
    pub session_key: String,
    /// Tool name.
    pub tool_name: String,
    /// Lower-case hex SHA-256 of the canonical tool input.
    pub input_sha256: String,
    /// Which hook.
    pub phase: HookPhase,
    /// Event id of the observation (evidence).
    pub evidence_event_id: String,
}

/// What the desktop shows for a pending request.
#[derive(Clone, Debug)]
pub struct PendingOverview {
    /// The card.
    pub card: ApprovalRequest,
    /// Devices the card was sent to.
    pub sent_to: Vec<String>,
    /// A phone acknowledged it.
    pub acked: bool,
    /// A phone opened it.
    pub seen: bool,
}

/// The approval broker. Create with [`Broker::new`] and share the `Arc`.
pub struct Broker {
    deps: BrokerDeps,
    state: Mutex<State>,
}

impl std::fmt::Debug for Broker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Broker").finish_non_exhaustive()
    }
}

fn level_of(risk: &Risk) -> Level {
    match risk.level.effective() {
        RiskLevel::Low => Level::Low,
        RiskLevel::Medium => Level::Medium,
        RiskLevel::Critical => Level::Critical,
        _ => Level::High,
    }
}

#[cfg(feature = "codex-daemon-observer")]
fn risk_with_level(mut risk: Risk, level: Level) -> Risk {
    risk.level = level.to_risk_level();
    risk.extra_confirmation = level.extra_confirmation();
    risk
}

/// UNVERIFIED (Phase 0 C8): the Codex "+1 risk level when `approvalPolicy=never`" rule. It is applied here, not in
/// `risk::classify`, and only in builds that carry the Codex adapter flag. The policy is read from the draft's
/// `permission_mode` hint (how Codex exposes the thread's `approvalPolicy` is itself unverified).
#[cfg(feature = "codex-daemon-observer")]
fn codex_policy_bump(draft: &ApprovalDraft, risk: Risk) -> Risk {
    if draft.agent_kind == AgentKind::Codex
        && matches!(
            draft.permission_mode.as_deref(),
            Some("never" | "danger-full-access")
        )
    {
        let raised = level_of(&risk).raised();
        return risk_with_level(risk, raised);
    }
    risk
}

#[cfg(not(feature = "codex-daemon-observer"))]
fn codex_policy_bump(_draft: &ApprovalDraft, risk: Risk) -> Risk {
    risk
}

fn auth_method_str(m: agentnest_protocol::AuthMethod) -> &'static str {
    match m {
        agentnest_protocol::AuthMethod::Biometric => "biometric",
        agentnest_protocol::AuthMethod::DeviceCredential => "device_credential",
        agentnest_protocol::AuthMethod::None => "none",
    }
}

fn extra_method_str(m: agentnest_protocol::ExtraConfirmationMethod) -> &'static str {
    match m {
        agentnest_protocol::ExtraConfirmationMethod::Hold => "hold",
        agentnest_protocol::ExtraConfirmationMethod::HoldAndReconfirm => "hold_and_reconfirm",
    }
}

fn random_nonce() -> Option<[u8; 16]> {
    let mut n = [0u8; 16];
    SystemRandom::new().fill(&mut n).ok()?;
    Some(n)
}

fn is_subset(wanted: &BTreeMap<String, String>, have: &BTreeMap<String, String>) -> bool {
    wanted.iter().all(|(k, v)| have.get(k) == Some(v))
}

impl Broker {
    /// A broker. Call [`Broker::recover_on_startup`] once before serving requests.
    pub fn new(deps: BrokerDeps) -> Arc<Self> {
        Arc::new(Self {
            deps,
            state: Mutex::new(State {
                pending: HashMap::new(),
                correlator: Correlator::new(),
                resolved: HashMap::new(),
                grace_deadline_ms: None,
            }),
        })
    }

    /// The run-time settings.
    pub fn settings(&self) -> &Arc<BrokerSettings> {
        &self.deps.settings
    }

    fn now_ms(&self) -> i64 {
        self.deps.clock.now_ms()
    }

    async fn db<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Store) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let store = self.deps.store.clone();
        tokio::task::spawn_blocking(move || f(&store))
            .await
            .map_err(|e| StoreError::Panicked(e.to_string()))?
    }

    // -----------------------------------------------------------------------------------------------------------------
    // startup
    // -----------------------------------------------------------------------------------------------------------------

    /// Daemon start: every approval left `pending` by a previous process becomes `expired` (its HTTP handle is gone, so
    /// there is nothing to answer; security.md 6.3, 7). Returns how many were expired. Phones learn about it through
    /// `approval_resolved{expired}` in the stream.
    pub async fn recover_on_startup(&self) -> usize {
        let now = format_ms(self.now_ms());
        let n2 = now.clone();
        let expired = match self.db(move |s| s.expire_all_pending_on_startup(&n2)).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "could not expire pending approvals at startup");
                return 0;
            }
        };
        for e in &expired {
            let payload = ApprovalResolvedPayload {
                request_id: e.request_id.clone(),
                session_key: e.session_key.clone(),
                outcome: ApprovalOutcome::Expired,
                resolved_by: ResolvedBy::System,
                resolved_device_id: None,
                resolved_at: now.clone(),
                delivery: Delivery::NotDelivered,
                observed_result: ObservedResult::Undetermined,
                message_ko: resolved_message_ko(&ApprovalOutcome::Expired, AgentKind::Other),
            };
            self.deps.pipeline.publish_approval_resolved(&payload).await;
        }
        expired.len()
    }

    // -----------------------------------------------------------------------------------------------------------------
    // opening a request
    // -----------------------------------------------------------------------------------------------------------------

    fn route_for(&self, draft: &ApprovalDraft, risk: &Risk) -> Route {
        if draft.agent_kind == AgentKind::ClaudeCode
            && draft
                .permission_mode
                .as_deref()
                .is_some_and(|m| remote_approval_for_mode(m) == RemoteApproval::Unavailable)
        {
            return Route::Unavailable;
        }
        if self.deps.settings.paused() {
            return Route::Paused;
        }
        if self.deps.settings.critical_local_only() && level_of(risk) == Level::Critical {
            return Route::CriticalLocalOnly;
        }
        if self.deps.registry.online_count() == 0 {
            return Route::NoDevice;
        }
        Route::Remote
    }

    /// Opens an approval request for `draft` and takes ownership of its `responder`. The responder is answered exactly
    /// once by a validated decision, or abandoned ("no decision") on every other path.
    pub async fn open(
        &self,
        draft: ApprovalDraft,
        responder: Box<dyn ApprovalResponder>,
    ) -> OpenOutcome {
        let now_ms = self.now_ms();
        let Some(nonce) = random_nonce() else {
            responder.abandon(AbandonReason::InternalError).await;
            return OpenOutcome::Failed;
        };
        let classifier = self.deps.classifier;
        let risk = classifier(&RiskInput {
            agent_kind: draft.agent_kind,
            tool_name: &draft.tool_name,
            tool_input: &draft.tool_input,
            cwd: draft.cwd.as_deref(),
            permission_mode: draft.permission_mode.as_deref(),
            extra_dirs: &[],
        });
        let risk = codex_policy_bump(&draft, risk);
        let hash_hex = tool_input_sha256(&draft.tool_input);
        let Ok(hash_bytes) = hex::decode(&hash_hex) else {
            responder.abandon(AbandonReason::InternalError).await;
            return OpenOutcome::Failed;
        };
        let summary = crate::summarize::ko::summarize_tool(&crate::summarize::ko::ToolObservation {
            agent_kind: draft.agent_kind,
            tool_name: &draft.tool_name,
            tool_input: &draft.tool_input,
            cwd: draft.cwd.as_deref(),
            command_class: None,
            file_exists: None,
            permission_request: true,
        });
        let details = build_details(&draft);
        let ttl_ms = self.deps.settings.ttl_ms();
        let request_id = format!("ar_{}", uuid::Uuid::now_v7());
        let route = self.route_for(&draft, &risk);

        // Allowed decisions: what the native protocol can express, restricted by our rules. A hooks-origin Codex card
        // never offers deny_and_stop (a hooks reply with `interrupt` would void the whole decision, codex.md 5.2).
        let mut allowed: Vec<Decision> = draft
            .available_decisions
            .iter()
            .copied()
            .filter(|d| {
                !(*d == Decision::DenyAndStop && draft.origin == SourceChannel::CodexHookCli)
            })
            .collect();
        allowed.dedup();
        let mut auth_required = vec![Decision::Allow, Decision::DenyAndStop];
        if self.deps.settings.deny_requires_auth() {
            auth_required.push(Decision::Deny);
        }
        let project = draft.project.clone().unwrap_or_else(|| ProjectRef {
            project_key: "unknown".to_owned(),
            name: "알 수 없음".to_owned(),
            path_hint: None,
            repo: None,
            branch: None,
        });
        let created_ms = now_ms;
        let expires_ms = now_ms + ttl_ms;
        let card = ApprovalRequest {
            request_id: request_id.clone(),
            nonce_b64: Secret::new(b64_encode(&nonce)),
            session_key: draft.session_key.clone(),
            agent_kind: draft.agent_kind,
            agent_label: agent_label(draft.agent_kind).to_owned(),
            project,
            origin: draft.origin.clone(),
            created_at: format_ms(created_ms),
            expires_at: format_ms(expires_ms),
            ttl_seconds: u32::try_from(ttl_ms / 1000).unwrap_or(120),
            tool_name: draft.tool_name.clone(),
            title: summary.title.clone(),
            purpose: purpose(draft.agent_description.as_deref()),
            details,
            tool_input_sha256: hash_hex.clone(),
            risk: risk.clone(),
            allowed_decisions: allowed.clone(),
            auth_required_for: auth_required,
            permission_mode: draft.permission_mode.clone(),
            local_prompt: LocalPrompt::Unverified,
        };
        let binding_json = serde_json::to_string(&draft.binding.ids).unwrap_or_else(|_| "{}".into());
        let new = NewApproval {
            request_id: request_id.clone(),
            nonce: nonce.to_vec(),
            session_key: card.session_key.clone(),
            agent_kind: draft.agent_kind.as_str().to_owned(),
            agent_id: draft.agent_id.clone().unwrap_or_default(),
            origin: card.origin.as_str().to_owned(),
            native_binding_json: binding_json,
            tool_name: card.tool_name.clone(),
            tool_kind: card.details.kind.as_str().to_owned(),
            tool_input_sha256: hash_bytes,
            created_at: card.created_at.clone(),
            expires_at: card.expires_at.clone(),
            title: card.title.clone(),
            purpose: card.purpose.clone(),
            details_json: serde_json::to_string(&card.details).ok(),
            risk_level: risk_level_str(&risk).to_owned(),
            risk_reasons_json: serde_json::to_string(&risk.reasons).unwrap_or_else(|_| "[]".into()),
            extra_confirmation: risk.extra_confirmation.as_str().to_owned(),
            allowed_decisions_json: serde_json::to_string(&allowed).unwrap_or_else(|_| "[]".into()),
            permission_mode: draft.permission_mode.clone(),
        };
        let merge_window = self.deps.settings.merge_window_ms();

        let mut st = self.state.lock().await;
        let inserted = match self.db(move |s| s.insert_approval(new, merge_window)).await {
            Ok(v) => v,
            Err(e) => {
                // Fail closed: the request could not be recorded, so it must not be answered at all.
                tracing::error!(error = %e, "could not store an approval request");
                drop(st);
                responder.abandon(AbandonReason::InternalError).await;
                return OpenOutcome::Failed;
            }
        };
        if let crate::store::InsertApproval::Merged { request_id: existing } = inserted {
            // A duplicate hook of the same call: it shares the existing card, but only while that card is still open.
            if route != Route::Remote || !st.pending.contains_key(&existing) {
                drop(st);
                responder.abandon(route.abandon_reason()).await;
                return OpenOutcome::HandedOff {
                    request_id: existing,
                    channel: route.channel(),
                };
            }
            if let Some(entry) = st.pending.get_mut(&existing) {
                entry.handles.push(Handle {
                    binding: draft.binding.clone(),
                    responder,
                });
            }
            return OpenOutcome::Merged { request_id: existing };
        }

        tracing::info!(
            request_id = %request_id,
            tool = %card.tool_name,
            risk = risk_level_str(&risk),
            route = route.channel_str(),
            "approval request opened"
        );
        let mut entry = Entry {
            card,
            nonce: nonce.to_vec(),
            expires_ms,
            created_ms,
            handles: vec![Handle {
                binding: draft.binding.clone(),
                responder,
            }],
            delivery: BTreeMap::new(),
            agent_kind: draft.agent_kind,
            native_session_id: draft.binding.native_session_id.clone(),
            agent_id: draft.agent_id.clone(),
            cwd: draft.cwd.clone(),
            origin: draft.origin.clone(),
        };
        // timeline event: the reducer moves the session to awaiting_approval
        self.publish_requested_event(&entry, route, &summary.headline, summary.detail.clone())
            .await;
        self.deps
            .bus
            .emit(DaemonEvent::Approval(ApprovalUiEvent::Opened {
                request: Box::new(entry.card.clone()),
                channel: route.channel(),
            }));
        if route != Route::Remote {
            // No phone is involved: hand it to the local prompt right away (empty reply).
            let reason = route.abandon_reason();
            let handles = std::mem::take(&mut entry.handles);
            let closed = self
                .db({
                    let (rid, now) = (request_id.clone(), format_ms(self.now_ms()));
                    move |s| {
                        s.close_approval(CloseRequest {
                            request_id: rid,
                            status: CloseStatus::HandedOffLocal,
                            resolved_by: "system".to_owned(),
                            now,
                            audit_actor: "daemon".to_owned(),
                            audit_action: "handed_off".to_owned(),
                            audit_detail_json: Some(
                                json!({ "reason": route.channel_str() }).to_string(),
                            ),
                        })
                    }
                })
                .await;
            if let Err(e) = closed {
                tracing::warn!(error = %e, "could not record the local hand-off");
            }
            for h in handles {
                h.responder.abandon(reason).await;
            }
            self.publish_resolved(
                &mut st,
                &entry,
                ApprovalOutcome::HandedOffLocal,
                ResolvedBy::System,
                None,
                Delivery::NotDelivered,
                false,
            )
            .await;
            return OpenOutcome::HandedOff {
                request_id,
                channel: route.channel(),
            };
        }
        // the card goes to every online phone through the stream
        self.deps.pipeline.publish_approval_request(&entry.card).await;
        st.pending.insert(request_id.clone(), entry);
        OpenOutcome::Opened { request_id }
    }

    async fn publish_requested_event(
        &self,
        entry: &Entry,
        route: Route,
        headline: &str,
        detail: Option<String>,
    ) {
        let mut d = EventDraft::new(
            entry.agent_kind,
            entry.native_session_id.clone(),
            EventKind::ApprovalRequested,
            entry.origin.clone(),
            "PermissionRequest",
        );
        d.state_hint = Some(AgentState::AwaitingApproval);
        d.headline = headline.to_owned();
        d.summary_detail = detail;
        d.severity = Severity::Notice;
        d.cwd = entry.cwd.clone();
        d.actor = entry.agent_id.clone().map(|id| agentnest_protocol::Actor {
            agent_id: Some(id),
            agent_type: None,
            is_subagent: true,
        });
        if let serde_json::Value::Object(m) = json!({
            "request_id": entry.card.request_id,
            "risk": risk_level_str(&entry.card.risk),
            "tool_name": entry.card.tool_name,
            "title": entry.card.title,
            "channel": route.channel_str(),
        }) {
            d.detail = m;
        }
        d.native_ids
            .insert("request_id".to_owned(), entry.card.request_id.clone());
        let event = build_event(d, &self.deps.env);
        self.deps.pipeline.ingest_event(event, None).await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn publish_resolved(
        &self,
        st: &mut State,
        entry: &Entry,
        outcome: ApprovalOutcome,
        resolved_by: ResolvedBy,
        device_id: Option<String>,
        delivery: Delivery,
        wire: bool,
    ) {
        let now_ms = self.now_ms();
        let message_ko = resolved_message_ko(&outcome, entry.agent_kind);
        let payload = ApprovalResolvedPayload {
            request_id: entry.card.request_id.clone(),
            session_key: entry.card.session_key.clone(),
            outcome: outcome.clone(),
            resolved_by: resolved_by.clone(),
            resolved_device_id: device_id,
            resolved_at: format_ms(now_ms),
            delivery: delivery.clone(),
            observed_result: ObservedResult::Undetermined,
            message_ko: message_ko.clone(),
        };
        if wire {
            self.deps.pipeline.publish_approval_resolved(&payload).await;
        }
        let mut d = EventDraft::new(
            entry.agent_kind,
            entry.native_session_id.clone(),
            EventKind::ApprovalResolved,
            entry.origin.clone(),
            "PermissionRequest",
        );
        d.headline = message_ko.clone();
        d.cwd = entry.cwd.clone();
        if let serde_json::Value::Object(m) = json!({
            "request_id": entry.card.request_id,
            "outcome": outcome.as_str(),
            "resolved_by": resolved_by.as_str(),
        }) {
            d.detail = m;
        }
        d.native_ids
            .insert("request_id".to_owned(), entry.card.request_id.clone());
        let event = build_event(d, &self.deps.env);
        self.deps.pipeline.ingest_event(event, None).await;
        self.deps
            .bus
            .emit(DaemonEvent::Approval(ApprovalUiEvent::Resolved {
                request_id: payload.request_id.clone(),
                session_key: payload.session_key.clone(),
                outcome,
                resolved_by,
                delivery,
                observed_result: ObservedResult::Undetermined,
                message_ko,
            }));
        // remember for the observed-result update
        st.resolved.insert(
            payload.request_id.clone(),
            ResolvedRecord {
                payload,
                resolved_ms: now_ms,
            },
        );
        if st.resolved.len() > 512 {
            let cutoff = now_ms - 120_000;
            st.resolved.retain(|_, r| r.resolved_ms >= cutoff);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    // closing without a decision
    // -----------------------------------------------------------------------------------------------------------------

    /// Ends a pending request without a decision. The database is updated first, the handles are abandoned after
    /// (empty reply), the resolution is published. Returns `false` if the request was not pending.
    async fn close_entry(&self, st: &mut State, request_id: &str, how: Closure) -> bool {
        let Some(mut entry) = st.pending.remove(request_id) else {
            return false;
        };
        let (status, outcome, resolved_by_db, resolved_by, abandon, audit_actor, audit_action) = match how {
            Closure::Expired => (
                CloseStatus::Expired,
                ApprovalOutcome::Expired,
                "timeout",
                ResolvedBy::Timeout,
                AbandonReason::Expired,
                "daemon",
                "expired",
            ),
            Closure::HandOff { by_desktop, reason } => (
                CloseStatus::HandedOffLocal,
                ApprovalOutcome::HandedOffLocal,
                if by_desktop { "desktop" } else { "system" },
                if by_desktop { ResolvedBy::Desktop } else { ResolvedBy::System },
                reason,
                if by_desktop { "desktop" } else { "daemon" },
                "handed_off",
            ),
            Closure::Superseded => (
                CloseStatus::Superseded,
                ApprovalOutcome::Superseded,
                "agent",
                ResolvedBy::Agent,
                AbandonReason::Superseded,
                "agent",
                "superseded",
            ),
        };
        let now = format_ms(self.now_ms());
        let rid = request_id.to_owned();
        let result = self
            .db(move |s| {
                s.close_approval(CloseRequest {
                    request_id: rid,
                    status,
                    resolved_by: resolved_by_db.to_owned(),
                    now,
                    audit_actor: audit_actor.to_owned(),
                    audit_action: audit_action.to_owned(),
                    audit_detail_json: None,
                })
            })
            .await;
        if let Err(e) = result {
            // The row stays pending in the database; the next start expires it. The agent still gets "no decision".
            tracing::error!(error = %e, "could not record the end of an approval");
        }
        for h in std::mem::take(&mut entry.handles) {
            h.responder.abandon(abandon).await;
        }
        self.publish_resolved(st, &entry, outcome, resolved_by, None, Delivery::NotDelivered, true)
            .await;
        true
    }

    async fn handoff_all(&self, st: &mut State, by_desktop: bool, reason: AbandonReason) -> usize {
        let ids: Vec<String> = st.pending.keys().cloned().collect();
        let mut n = 0;
        for id in ids {
            if self
                .close_entry(st, &id, Closure::HandOff { by_desktop, reason })
                .await
            {
                n += 1;
            }
        }
        n
    }

    /// "Handle locally" (desktop button): the request is handed to the local prompt at once (empty reply). Always
    /// allowed, whatever the risk: it creates no decision.
    pub async fn handoff_local(&self, request_id: &str) -> bool {
        let mut st = self.state.lock().await;
        self.close_entry(
            &mut st,
            request_id,
            Closure::HandOff {
                by_desktop: true,
                reason: AbandonReason::HandedOffToDesktop,
            },
        )
        .await
    }

    /// The agent closed the request itself (Codex `serverRequest/resolved`, the HTTP connection of a hook went away).
    /// The matching handle is dropped; when the last handle of a request is gone the request becomes `superseded`.
    /// `binding.ids` must be a subset of the handle's binding (a unique per-connection id makes it exact).
    pub async fn agent_closed(&self, binding: &NativeBinding, _reason: AgentCloseReason) {
        let mut st = self.state.lock().await;
        let mut found: Option<(String, usize)> = None;
        'outer: for (id, entry) in &st.pending {
            for (i, h) in entry.handles.iter().enumerate() {
                if h.binding.agent_kind == binding.agent_kind
                    && h.binding.native_session_id == binding.native_session_id
                    && is_subset(&binding.ids, &h.binding.ids)
                {
                    found = Some((id.clone(), i));
                    break 'outer;
                }
            }
        }
        let Some((id, idx)) = found else { return };
        let empty = {
            let Some(entry) = st.pending.get_mut(&id) else { return };
            let h = entry.handles.remove(idx);
            h.responder.abandon(AbandonReason::Superseded).await;
            entry.handles.is_empty()
        };
        if empty {
            self.close_entry(&mut st, &id, Closure::Superseded).await;
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    // timers, presence, switches
    // -----------------------------------------------------------------------------------------------------------------

    /// Timer step: expires requests at `expires_at` and ends the reconnect grace. Call it every 100-250 ms.
    pub async fn tick(&self) {
        let now = self.now_ms();
        let mut st = self.state.lock().await;
        let due: Vec<String> = st
            .pending
            .iter()
            .filter(|(_, e)| e.expires_ms <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in due {
            self.close_entry(&mut st, &id, Closure::Expired).await;
        }
        if let Some(deadline) = st.grace_deadline_ms {
            if now >= deadline {
                st.grace_deadline_ms = None;
                if self.deps.registry.online_count() == 0 && !st.pending.is_empty() {
                    self.handoff_all(&mut st, false, AbandonReason::PhoneDisconnected)
                        .await;
                }
            }
        }
        st.correlator.prune(now);
    }

    /// A device authenticated: the reconnect grace ends (nothing is handed off).
    pub async fn device_connected(&self) {
        let mut st = self.state.lock().await;
        st.grace_deadline_ms = None;
    }

    /// A device disconnected (call after the connection left the registry). When no phone is online any more the
    /// pending requests are handed to the local prompt after the reconnect grace (10 s by default, 0 = at once).
    pub async fn device_disconnected(&self) {
        let mut st = self.state.lock().await;
        if self.deps.registry.online_count() > 0 || st.pending.is_empty() {
            return;
        }
        let grace = self.deps.settings.grace_ms();
        if grace <= 0 {
            self.handoff_all(&mut st, false, AbandonReason::PhoneDisconnected)
                .await;
        } else {
            st.grace_deadline_ms = Some(self.now_ms() + grace);
        }
    }

    /// A device was revoked (call after the registry kicked it): its decisions are void from now on (step 1 reads the
    /// database), and if no other phone is online the pending requests go to the local prompt immediately.
    pub async fn device_revoked(&self) {
        let mut st = self.state.lock().await;
        if self.deps.registry.online_count() == 0 && !st.pending.is_empty() {
            self.handoff_all(&mut st, false, AbandonReason::DeviceRevoked).await;
        }
    }

    /// `link.enabled=false`: every pending request ends as `handed_off_local` (resolved by the desktop).
    pub async fn link_disabled(&self) -> usize {
        let mut st = self.state.lock().await;
        self.handoff_all(&mut st, true, AbandonReason::LinkDisabled).await
    }

    /// Daemon shutdown: every pending request is handed to the local prompt (empty replies) so no hook hangs.
    pub async fn shutdown(&self) -> usize {
        let mut st = self.state.lock().await;
        self.handoff_all(&mut st, false, AbandonReason::DaemonShutdown).await
    }

    /// Pauses or resumes remote approval. While paused new requests go straight to the local prompt and phone decisions
    /// are refused with `PAUSED`; desktop decisions still apply.
    pub async fn set_paused(&self, paused: bool) {
        self.deps.settings.set_paused(paused);
        self.deps.pipeline.set_paused(paused).await;
    }

    // -----------------------------------------------------------------------------------------------------------------
    // delivery bookkeeping
    // -----------------------------------------------------------------------------------------------------------------

    async fn persist_delivery(&self, entry: &Entry) {
        let map: serde_json::Map<String, serde_json::Value> = entry
            .delivery
            .iter()
            .map(|(dev, t)| {
                (
                    dev.clone(),
                    json!({ "sent_at": t.sent_at, "acked_at": t.acked_at, "seen_at": t.seen_at }),
                )
            })
            .collect();
        let (rid, text) = (
            entry.card.request_id.clone(),
            serde_json::Value::Object(map).to_string(),
        );
        if let Err(e) = self.db(move |s| s.set_delivered_to(&rid, &text)).await {
            tracing::warn!(error = %e, "could not store the delivery state");
        }
        let sent_to: Vec<String> = entry.delivery.keys().cloned().collect();
        let acked = entry.delivery.values().any(|t| t.acked_at.is_some());
        let seen = entry.delivery.values().any(|t| t.seen_at.is_some());
        self.deps
            .bus
            .emit(DaemonEvent::Approval(ApprovalUiEvent::Delivery {
                request_id: entry.card.request_id.clone(),
                sent_to,
                acked,
                seen,
            }));
    }

    /// The card was written to the socket of `device_id` (first time per device is audited as `sent_to_phone`).
    pub async fn mark_sent(&self, request_id: &str, device_id: &str) {
        let mut st = self.state.lock().await;
        let Some(entry) = st.pending.get_mut(request_id) else { return };
        let first = !entry.delivery.contains_key(device_id);
        if first {
            entry.delivery.entry(device_id.to_owned()).or_default().sent_at =
                Some(format_ms(self.now_ms()));
            if let Some(entry) = st.pending.get(request_id) {
                self.persist_delivery(entry).await;
            }
            self.deps
                .audit
                .approval(
                    request_id,
                    "daemon",
                    approval_actions::SENT_TO_PHONE,
                    Some(json!({ "device_id": device_id })),
                )
                .await;
        }
    }

    /// The phone acknowledged cards (`ack.approval_ids`).
    pub async fn mark_acked(&self, request_ids: &[String], device_id: &str) {
        let mut st = self.state.lock().await;
        for id in request_ids {
            let Some(entry) = st.pending.get_mut(id) else { continue };
            let t = entry.delivery.entry(device_id.to_owned()).or_default();
            if t.acked_at.is_some() {
                continue;
            }
            t.acked_at = Some(format_ms(self.now_ms()));
            if let Some(entry) = st.pending.get(id) {
                self.persist_delivery(entry).await;
            }
            self.deps
                .audit
                .approval(
                    id,
                    format!("phone:{device_id}"),
                    approval_actions::ACKED,
                    None,
                )
                .await;
        }
    }

    /// The phone showed the card (`approval_seen`).
    pub async fn mark_seen(&self, request_id: &str, device_id: &str) {
        let mut st = self.state.lock().await;
        let Some(entry) = st.pending.get_mut(request_id) else { return };
        let t = entry.delivery.entry(device_id.to_owned()).or_default();
        if t.seen_at.is_some() {
            return;
        }
        t.seen_at = Some(format_ms(self.now_ms()));
        if let Some(entry) = st.pending.get(request_id) {
            self.persist_delivery(entry).await;
        }
        self.deps
            .audit
            .approval(
                request_id,
                format!("phone:{device_id}"),
                approval_actions::SEEN,
                None,
            )
            .await;
    }

    /// The card could not be delivered to any phone after the retries (the request keeps waiting until its TTL).
    pub fn delivery_failed(&self, request_id: &str) {
        self.deps
            .bus
            .emit(DaemonEvent::Approval(ApprovalUiEvent::DeliveryFailed {
                request_id: request_id.to_owned(),
            }));
    }

    // -----------------------------------------------------------------------------------------------------------------
    // queries
    // -----------------------------------------------------------------------------------------------------------------

    /// The cards of all pending, unexpired requests in creation order (snapshot `pending_approvals`).
    pub async fn pending_cards(&self) -> Vec<ApprovalRequest> {
        let now = self.now_ms();
        let st = self.state.lock().await;
        let mut v: Vec<&Entry> = st.pending.values().filter(|e| e.expires_ms > now).collect();
        v.sort_by_key(|e| e.created_ms);
        v.into_iter().map(|e| e.card.clone()).collect()
    }

    /// The pending requests with their delivery state (desktop `approvals_pending`).
    pub async fn pending_overview(&self) -> Vec<PendingOverview> {
        let st = self.state.lock().await;
        let mut v: Vec<&Entry> = st.pending.values().collect();
        v.sort_by_key(|e| e.created_ms);
        v.into_iter()
            .map(|e| PendingOverview {
                card: e.card.clone(),
                sent_to: e.delivery.keys().cloned().collect(),
                acked: e.delivery.values().any(|t| t.acked_at.is_some()),
                seen: e.delivery.values().any(|t| t.seen_at.is_some()),
            })
            .collect()
    }

    /// Number of pending requests.
    pub async fn pending_count(&self) -> usize {
        self.state.lock().await.pending.len()
    }

    /// The card of one pending request.
    pub async fn pending_card(&self, request_id: &str) -> Option<ApprovalRequest> {
        self.state
            .lock()
            .await
            .pending
            .get(request_id)
            .map(|e| e.card.clone())
    }

    // -----------------------------------------------------------------------------------------------------------------
    // observed result
    // -----------------------------------------------------------------------------------------------------------------

    /// Feeds a `PreToolUse` / `PostToolUse` / `PostToolUseFailure` observation to the correlator. When it proves what
    /// happened to an approved or denied call, `observed_result` is stored and `approval_resolved` is re-sent with the
    /// same `request_id` (idempotent for the phone).
    pub async fn observe_tool(&self, obs: ToolObservation) {
        let now = self.now_ms();
        let mut st = self.state.lock().await;
        let correlated = st.correlator.observe(&Observation {
            session_key: &obs.session_key,
            tool_name: &obs.tool_name,
            input_sha256: &obs.input_sha256,
            phase: obs.phase,
            now_ms: now,
        });
        let Some(c) = correlated else { return };
        let observed = match c.observed {
            ObservedResult::Executed => "executed",
            ObservedResult::Declined => "declined",
            _ => "unknown",
        };
        let (rid, ev, ts, obs_s) = (
            c.request_id.clone(),
            obs.evidence_event_id.clone(),
            format_ms(now),
            observed.to_owned(),
        );
        if let Err(e) = self
            .db(move |s| s.set_observed_result(&rid, &obs_s, &ev, &ts))
            .await
        {
            tracing::warn!(error = %e, "could not store the observed result");
            return;
        }
        if let Some(rec) = st.resolved.get_mut(&c.request_id) {
            rec.payload.observed_result = c.observed.clone();
            let payload = rec.payload.clone();
            self.deps.pipeline.publish_approval_resolved(&payload).await;
            self.deps
                .bus
                .emit(DaemonEvent::Approval(ApprovalUiEvent::Resolved {
                    request_id: payload.request_id,
                    session_key: payload.session_key,
                    outcome: payload.outcome,
                    resolved_by: payload.resolved_by,
                    delivery: payload.delivery,
                    observed_result: c.observed,
                    message_ko: payload.message_ko,
                }));
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    // decisions
    // -----------------------------------------------------------------------------------------------------------------

    /// Desktop decision (`approval_decide_local`): the same transition as a phone decision, validated by the desktop
    /// table of security.md 6.2.1.
    #[allow(clippy::too_many_arguments)]
    pub async fn decide_local(
        &self,
        request_id: &str,
        decision: Decision,
        tool_input_sha256: &str,
        confirm_ack: bool,
        reason: Option<String>,
    ) -> DecisionOutcome {
        self.apply_decision(DecisionInput {
            source: DecisionSource::Desktop,
            decision_id: format!("desktop-{}", uuid::Uuid::now_v7()),
            request_id: request_id.to_owned(),
            session_key: None,
            nonce_b64: None,
            tool_input_sha256: tool_input_sha256.to_owned(),
            decision,
            reason,
            decided_at: None,
            auth: None,
            extra_confirmation: None,
            confirm_ack,
        })
        .await
    }

    async fn reject(
        &self,
        st: &mut State,
        input: &DecisionInput,
        rejection: crate::approvals::validator::Rejection,
        stored_status: Option<String>,
    ) -> DecisionOutcome {
        let now = format_ms(self.now_ms());
        let reason_str = rejection.reason.as_str().to_owned();
        if rejection.warn {
            tracing::warn!(
                request_id = %input.request_id,
                actor = %input.source.actor(),
                "decision refused: binding mismatch"
            );
        }
        let decision_row = NewDecision {
            id: input.decision_id.clone(),
            request_id: input.request_id.clone(),
            actor: input.source.actor(),
            decision: input.decision.as_str().to_owned(),
            decided_at: input.decided_at.clone().unwrap_or_else(|| now.clone()),
            received_at: now.clone(),
            auth_method: input.auth.as_ref().map(|a| auth_method_str(a.method).to_owned()),
            extra_confirmation: input
                .extra_confirmation
                .as_ref()
                .map(|e| extra_method_str(e.method).to_owned()),
            verify_result: reason_str.clone(),
            signature: None,
        };
        let audit_row = crate::store::NewApprovalAudit {
            request_id: input.request_id.clone(),
            ts: now.clone(),
            actor: input.source.audit_actor(),
            action: approval_actions::DECISION_REJECTED.to_owned(),
            detail_json: Some(json!({ "reason": reason_str }).to_string()),
        };
        let late = matches!(
            stored_status.as_deref(),
            Some("superseded" | "expired" | "handed_off_local")
        );
        let late_row = late.then(|| crate::store::NewApprovalAudit {
            request_id: input.request_id.clone(),
            ts: now.clone(),
            actor: input.source.audit_actor(),
            action: approval_actions::LATE_DECISION.to_owned(),
            detail_json: Some(json!({ "stored_status": stored_status }).to_string()),
        });
        let recorded = self
            .db(move |s| {
                s.insert_decision(decision_row)?;
                s.insert_approval_audit(audit_row)?;
                if let Some(l) = late_row {
                    s.insert_approval_audit(l)?;
                }
                Ok(())
            })
            .await;
        if let Err(e) = recorded {
            tracing::warn!(error = %e, "could not record a refused decision");
        }
        if rejection.expire_request {
            self.close_entry(st, &input.request_id, Closure::Expired).await;
        }
        let agent = st
            .pending
            .get(&input.request_id)
            .map(|e| e.agent_kind)
            .unwrap_or(AgentKind::Other);
        self.deps
            .bus
            .emit(DaemonEvent::Approval(ApprovalUiEvent::DecisionRejected {
                request_id: input.request_id.clone(),
                reason: rejection.reason.as_str().to_owned(),
            }));
        DecisionOutcome {
            request_id: input.request_id.clone(),
            accepted: false,
            message_ko: decision_result_message_ko(&rejection.reason, None, agent),
            reason: rejection.reason,
        }
    }

    /// Applies a decision of the phone or the desktop. **The only function that can produce an allow reply.**
    ///
    /// Order, all before any state change: idempotency check by decision id, then the nine validation steps
    /// ([`validate`]). Only a decision that passes all of them reaches the conditional `UPDATE`
    /// (`WHERE status='pending' AND expires_at > now`) together with the `decisions` and `approval_audit` rows in one
    /// transaction; **after that commit** the reply is built and delivered. A failure anywhere leaves the request
    /// pending (until TTL) or ends it without a decision, never with an allow.
    pub async fn apply_decision(&self, input: DecisionInput) -> DecisionOutcome {
        let mut st = self.state.lock().await;
        let now_ms = self.now_ms();

        // idempotency: a decision id that was already processed gets its stored result, nothing is re-applied
        let did = input.decision_id.clone();
        if let Ok(Some(prev)) = self.db(move |s| s.decision_verify_result(&did)).await {
            let reason = DecisionResultReason::from_wire(&prev);
            let accepted = reason == DecisionResultReason::Applied;
            return DecisionOutcome {
                request_id: input.request_id.clone(),
                accepted,
                message_ko: decision_result_message_ko(
                    &reason,
                    Some(&if input.decision == Decision::Allow {
                        ApprovalOutcome::Allowed
                    } else {
                        ApprovalOutcome::Denied
                    }),
                    AgentKind::Other,
                ),
                reason,
            };
        }

        // steps 2 and 3 read the database; the card data for steps 4-9 comes from the pending table
        let rid = input.request_id.clone();
        let row = match self.db(move |s| s.get_approval(&rid)).await {
            Ok(r) => r,
            Err(e) => {
                // cannot even read the request: refuse (fail closed), nothing recorded beyond the log
                tracing::error!(error = %e, "decision refused: storage failure");
                return DecisionOutcome {
                    request_id: input.request_id.clone(),
                    accepted: false,
                    reason: DecisionResultReason::UnknownRequest,
                    message_ko: decision_result_message_ko(
                        &DecisionResultReason::UnknownRequest,
                        None,
                        AgentKind::Other,
                    ),
                };
            }
        };
        let stored_status = row.as_ref().map(|r| r.status.clone());
        let device_active = match &input.source {
            DecisionSource::Phone { device_id } => {
                let devices = self.deps.devices.clone();
                let id = device_id.clone();
                tokio::task::spawn_blocking(move || devices.is_active(&id))
                    .await
                    .unwrap_or(false)
            }
            DecisionSource::Desktop => true,
        };
        let env = ValidationEnv {
            now_ms,
            device_active,
            paused: self.deps.settings.paused(),
        };
        let allowed_buf: Vec<Decision>;
        let auth_buf: Vec<Decision>;
        let nonce_buf: Vec<u8>;
        let hash_buf: String;
        let session_buf: String;
        let status = match (&row, st.pending.get(&input.request_id)) {
            (None, _) => RequestStatus::Unknown,
            (Some(r), _) if r.status != "pending" => RequestStatus::NotPending,
            // pending in the database but not in memory: cannot be answered (a previous process); refuse
            (Some(_), None) => RequestStatus::NotPending,
            (Some(_), Some(e)) => {
                allowed_buf = e.card.allowed_decisions.clone();
                auth_buf = e.card.auth_required_for.clone();
                nonce_buf = e.nonce.clone();
                hash_buf = e.card.tool_input_sha256.clone();
                session_buf = e.card.session_key.clone();
                RequestStatus::Pending(CardView {
                    session_key: &session_buf,
                    nonce: &nonce_buf,
                    tool_input_sha256_hex: &hash_buf,
                    created_ms: e.created_ms,
                    expires_ms: e.expires_ms,
                    allowed: &allowed_buf,
                    auth_required_for: &auth_buf,
                    extra_confirmation: e.card.risk.extra_confirmation.clone(),
                })
            }
        };
        if let Err(rejection) = validate(&env, &status, &input) {
            return self.reject(&mut st, &input, rejection, stored_status).await;
        }

        // step 10: the single conditional transition, with the decision and audit rows, one synchronous=FULL transaction
        let outcome_text = match input.decision {
            Decision::Allow => "allowed",
            Decision::Deny => "denied",
            Decision::DenyAndStop => "denied_and_stopped",
        };
        let device_id = match &input.source {
            DecisionSource::Phone { device_id } => Some(device_id.clone()),
            DecisionSource::Desktop => None,
        };
        let now = format_ms(now_ms);
        let auth_json = json!({
            "method": input.auth.as_ref().map(|a| auth_method_str(a.method)),
            "authenticated_at": input.auth.as_ref().and_then(|a| a.authenticated_at.clone()),
            "extra_confirmation": input.extra_confirmation.as_ref().map(|e| json!({
                "method": extra_method_str(e.method),
                "completed": e.completed,
            })),
            "confirm_ack": matches!(input.source, DecisionSource::Desktop).then_some(input.confirm_ack),
        })
        .to_string();
        let resolve = ResolveRequest {
            request_id: input.request_id.clone(),
            outcome: outcome_text.to_owned(),
            resolved_by: input.source.resolved_by().to_owned(),
            resolved_device_id: device_id.clone(),
            now: now.clone(),
            decision_id: input.decision_id.clone(),
            actor: input.source.actor(),
            decision: input.decision.as_str().to_owned(),
            decided_at: input.decided_at.clone().unwrap_or_else(|| now.clone()),
            auth_method: input.auth.as_ref().map(|a| auth_method_str(a.method).to_owned()),
            extra_confirmation: input
                .extra_confirmation
                .as_ref()
                .map(|e| extra_method_str(e.method).to_owned()),
            auth_json: Some(auth_json),
            signature: None,
            audit_actor: input.source.audit_actor(),
            audit_detail_json: Some(
                json!({
                    "decision": input.decision.as_str(),
                    "risk": st.pending.get(&input.request_id).map(|e| risk_level_str(&e.card.risk)),
                })
                .to_string(),
            ),
        };
        match self.db(move |s| s.resolve_approval_conditional(resolve)).await {
            Ok(ResolveOutcome::Applied) => {}
            Ok(ResolveOutcome::NotApplied(why)) => {
                let reason = match why {
                    crate::store::NotApplied::UnknownRequest => DecisionResultReason::UnknownRequest,
                    crate::store::NotApplied::AlreadyResolved => DecisionResultReason::AlreadyResolved,
                    crate::store::NotApplied::Expired => DecisionResultReason::Expired,
                };
                // the attempt is already recorded by the store transaction
                if reason == DecisionResultReason::Expired {
                    self.close_entry(&mut st, &input.request_id, Closure::Expired).await;
                }
                let agent = AgentKind::Other;
                return DecisionOutcome {
                    request_id: input.request_id.clone(),
                    accepted: false,
                    message_ko: decision_result_message_ko(&reason, None, agent),
                    reason,
                };
            }
            Err(e) => {
                tracing::error!(error = %e, "decision not applied: storage failure");
                return DecisionOutcome {
                    request_id: input.request_id.clone(),
                    accepted: false,
                    reason: DecisionResultReason::AlreadyResolved,
                    message_ko: decision_result_message_ko(
                        &DecisionResultReason::AlreadyResolved,
                        None,
                        AgentKind::Other,
                    ),
                };
            }
        }

        // ---- success branch: the decision is committed; now (and only now) the reply is built and delivered ----------
        let Some(mut entry) = st.pending.remove(&input.request_id) else {
            // Cannot happen (the validator saw the entry and we hold the lock); fail closed: no reply to anyone.
            return DecisionOutcome {
                request_id: input.request_id.clone(),
                accepted: true,
                reason: DecisionResultReason::Applied,
                message_ko: decision_result_message_ko(
                    &DecisionResultReason::Applied,
                    Some(&ApprovalOutcome::Denied),
                    AgentKind::Other,
                ),
            };
        };
        let message = deny_message(
            input.reason.as_deref(),
            matches!(input.source, DecisionSource::Phone { .. }),
        );
        let reply = match input.decision {
            Decision::Allow => {
                #[allow(clippy::disallowed_methods)]
                let proof = ApplyProof::mint();
                ApprovalReply::allow(proof)
            }
            Decision::Deny => ApprovalReply::deny(message, false),
            Decision::DenyAndStop => ApprovalReply::deny(message, true),
        };
        let mut delivered = false;
        for h in std::mem::take(&mut entry.handles) {
            if h.responder.respond(reply.clone()).await.is_ok() {
                delivered = true;
            }
        }
        let (outcome, tracked) = match input.decision {
            Decision::Allow => (ApprovalOutcome::Allowed, TrackedOutcome::Allowed),
            Decision::Deny => (ApprovalOutcome::Denied, TrackedOutcome::Denied),
            Decision::DenyAndStop => (ApprovalOutcome::DeniedAndStopped, TrackedOutcome::Denied),
        };
        let (rid, ts) = (input.request_id.clone(), format_ms(self.now_ms()));
        if let Err(e) = self.db(move |s| s.set_delivery(&rid, delivered, &ts)).await {
            tracing::warn!(error = %e, "could not record the delivery state");
        }
        let delivery = if delivered {
            Delivery::Delivered
        } else {
            Delivery::NotDelivered
        };
        st.correlator.track(
            &entry.card.request_id,
            &entry.card.session_key,
            &entry.card.tool_name,
            &entry.card.tool_input_sha256,
            now_ms,
            tracked,
        );
        self.publish_resolved(
            &mut st,
            &entry,
            outcome.clone(),
            if matches!(input.source, DecisionSource::Phone { .. }) {
                ResolvedBy::Phone
            } else {
                ResolvedBy::Desktop
            },
            device_id,
            delivery,
            true,
        )
        .await;
        DecisionOutcome {
            request_id: input.request_id.clone(),
            accepted: true,
            message_ko: decision_result_message_ko(
                &DecisionResultReason::Applied,
                Some(&outcome),
                entry.agent_kind,
            ),
            reason: DecisionResultReason::Applied,
        }
    }
}

#[derive(Clone, Copy)]
enum Closure {
    Expired,
    HandOff { by_desktop: bool, reason: AbandonReason },
    Superseded,
}

