//! The per-connection state machine (docs/protocol.md 1, 3, 4, 8, 9; docs/security.md 4, 5, 11, I1, I6, I7).
//!
//! ```text
//! accept --admission--> TLS --upgrade--> PreAuth --valid hello--> Authenticated
//!  (16 total / 4 per IP / blocked IP,          |--valid pair--> PairPending --PC user approves--> Authenticated
//!   all before TLS: link/mod.rs)
//! ```
//!
//! **PreAuth (I1):** the server sends the `challenge` frame and nothing else. The phone may send exactly one valid `pair`
//! or `hello`; anything else (a `ping`, an unknown type, binary data, garbage) closes the connection with **4001** and not
//! a byte of PC data leaves. The 5 s timer covers the wait for that first valid frame and is measured **from the TCP
//! accept** (the TLS handshake and the HTTP upgrade count against it too).
//!
//! **PairPending (I1, I7):** after a valid `pair` the server may send `pair_pending`, `pair_result` and `error` only; the
//! phone may send `unpair{pairing_id}` or close; any other phone frame is **4001**; the PC user has 60 s (**4002**).
//!
//! **Authenticated:** `welcome` (+ replay / snapshot), then `ack`, `ping`, `snapshot_request`, `events_request`,
//! `decision`, `approval_seen`, `unpair`. Per-device limits: 10 decisions, 6 pings, 6 snapshot requests and 12 events
//! requests per minute (`E_RATE_LIMITED`, three strikes close with 4005). A connection without frames for 90 s is 4008.
//!
//! Close codes: 4001 pre-auth timeout / forbidden frame, 4002 authentication or pairing failure (after a 1 s delay), 4003
//! revoked, 4004 protocol violations, 4005 rate limit, 4008 heartbeat, 4009 superseded, 4010 version, 1003 binary,
//! 1009 too big, 1013 connection cap.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use agentnest_protocol::limits::{
    EVENTS_PAGE_MAX_BYTES, MAX_FRAME_C2S_BYTES, MAX_FRAME_S2C_BYTES, SNAPSHOT_MAX_BYTES,
};
use agentnest_protocol::{
    ApprovalOutcome, ApprovalResolvedPayload, ByePayload, ByeReason, ChallengePayload,
    DecisionPayload, DecisionResultPayload, Delivery, ErrorCode, ErrorPayload, EventsPagePayload,
    EventsRequestPayload, Focus, Frame, Heartbeat, HelloPayload, Hosts, Limits, Message,
    ObservedResult, PairPayload, PairPendingPayload, PairResultPayload, PcInfo, Policy,
    PongPayload, ProtocolError, ProtocolInfo, RemoteApprovalPolicy, ResolvedBy, Resync, ResyncMode,
    SnapshotPayload, UnpairPayload, WelcomePayload,
};
use axum::extract::ws::{CloseFrame, Message as WsMessage, WebSocket};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc};
use tokio::time::Instant;

use crate::approvals::broker::DecisionOutcome;
use crate::approvals::validator::{DecisionInput, DecisionSource};
use crate::audit::{actions, device_actor};
use crate::auth::challenge::{Admission, Challenge};
use crate::auth::devices::{AuthOutcome, IssuedDevice};
use crate::auth::pairing::{ConfirmDecision, PairFailure, PendingConfirmation};
use crate::events::{DaemonEvent, DeviceUiEvent};
use crate::link::registry::{ConnCommand, DeviceLimiter, Published, MAX_RATE_STRIKES};
use crate::link::snapshot::{self, SnapshotInputs};
use crate::link::LinkContext;
use crate::redact::mask_ip;
use crate::state::timers::format_ms;
use crate::store::{ApprovalReplayState, EventsQuery, ResyncPlan};

/// Malformed frames before the connection is closed with 4004.
const MAX_BAD_MESSAGES: u32 = 3;
/// Replay rows read at once.
const REPLAY_LIMIT: u32 = 100_000;

enum Recv {
    Text(String),
    Binary,
    Closed,
    TooBig,
    Timeout,
}

enum Flow {
    Continue,
    End,
}

struct Conn {
    ws: WebSocket,
    ctx: Arc<LinkContext>,
    ip: IpAddr,
}

struct AckTrack {
    text: String,
    last_sent: Instant,
    retries: u32,
}

struct AuthState {
    device_id: String,
    conn_id: u64,
    cmd_rx: mpsc::UnboundedReceiver<ConnCommand>,
    live: broadcast::Receiver<Arc<Published>>,
    sent_up_to: i64,
    acks: HashMap<String, AckTrack>,
    /// The device's limits, shared by all its connections (they survive a reconnect).
    limits: Arc<std::sync::Mutex<DeviceLimiter>>,
    /// Highest `through_seq` already written to the database.
    last_acked_written: i64,
    bad_messages: u32,
    last_rx: Instant,
}

impl AuthState {
    /// Runs `f` on the device's limiter.
    fn limit<T>(&self, f: impl FnOnce(&mut DeviceLimiter) -> T) -> T {
        let mut g = self.limits.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut g)
    }
}

/// Runs one WebSocket connection to its end. `admission` is the connection slot taken when the TCP connection was
/// accepted (caps and address filter already passed); `accepted_at` is the instant the 5 s authentication deadline
/// counts from.
pub async fn run(
    socket: WebSocket,
    ctx: Arc<LinkContext>,
    ip: IpAddr,
    admission: Admission,
    accepted_at: Instant,
) {
    let mut conn = Conn {
        ws: socket,
        ctx,
        ip,
    };
    conn.serve(admission, accepted_at).await;
}

impl Conn {
    // -----------------------------------------------------------------------------------------------------------------
    // I/O helpers
    // -----------------------------------------------------------------------------------------------------------------

    fn now_ms(&self) -> i64 {
        self.ctx.clock.now_ms()
    }

    fn frame_text(&self, seq: Option<i64>, message: Message) -> Option<String> {
        Frame::new(
            uuid::Uuid::now_v7().to_string(),
            format_ms(self.now_ms()),
            seq,
            message,
        )
        .to_json()
        .ok()
    }

    /// An envelope for a stored replayable message (the payload is already the wire payload).
    fn stream_text(&self, seq: i64, msg_type: &str, payload: &Value) -> String {
        json!({
            "v": 1,
            "type": msg_type,
            "id": uuid::Uuid::now_v7().to_string(),
            "ts": format_ms(self.now_ms()),
            "seq": seq,
            "payload": payload,
        })
        .to_string()
    }

    async fn send_text(&mut self, text: String) -> bool {
        if text.len() > MAX_FRAME_S2C_BYTES {
            tracing::error!(
                len = text.len(),
                "an outgoing frame exceeds the frame limit and was dropped"
            );
            return true;
        }
        self.ws.send(WsMessage::Text(text.into())).await.is_ok()
    }

    async fn send(&mut self, message: Message) -> bool {
        match self.frame_text(None, message) {
            Some(t) => self.send_text(t).await,
            None => true,
        }
    }

    async fn send_error(
        &mut self,
        code: ErrorCode,
        message: &str,
        message_ko: &str,
        in_reply_to: Option<String>,
        fatal: bool,
    ) -> bool {
        self.send(Message::Error(ErrorPayload {
            code,
            message: message.to_owned(),
            message_ko: Some(message_ko.to_owned()),
            in_reply_to,
            fatal,
        }))
        .await
    }

    async fn close(&mut self, code: u16) {
        let _ = self
            .ws
            .send(WsMessage::Close(Some(CloseFrame {
                code,
                reason: "".into(),
            })))
            .await;
    }

    async fn recv(&mut self, deadline: Option<Instant>) -> Recv {
        loop {
            let next = match deadline {
                Some(d) => match tokio::time::timeout_at(d, self.ws.recv()).await {
                    Ok(n) => n,
                    Err(_) => return Recv::Timeout,
                },
                None => self.ws.recv().await,
            };
            match next {
                None => return Recv::Closed,
                Some(Err(_)) => return Recv::TooBig,
                Some(Ok(WsMessage::Text(t))) => {
                    if t.len() > MAX_FRAME_C2S_BYTES {
                        return Recv::TooBig;
                    }
                    return Recv::Text(t.as_str().to_owned());
                }
                Some(Ok(WsMessage::Binary(_))) => return Recv::Binary,
                Some(Ok(WsMessage::Close(_))) => return Recv::Closed,
                // ping/pong frames are answered by the transport; they carry no application data
                Some(Ok(_)) => continue,
            }
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    // PreAuth
    // -----------------------------------------------------------------------------------------------------------------

    async fn serve(&mut self, mut admission: Admission, accepted_at: Instant) {
        let Some(challenge) = Challenge::generate() else {
            self.close(1011).await;
            return;
        };
        let pc = self.ctx.pc_info();
        // the ONLY frame the server sends before the phone proved anything
        let challenge_frame = self.frame_text(
            None,
            Message::Challenge(ChallengePayload {
                challenge_b64: challenge.to_b64(),
                pc_id: pc.pc_id.clone(),
                server_time: format_ms(self.now_ms()),
                expires_in_ms: u32::try_from(self.ctx.timing.preauth_ms).unwrap_or(5_000),
            }),
        );
        let Some(text) = challenge_frame else {
            self.close(1011).await;
            return;
        };
        if !self.send_text(text).await {
            return;
        }
        let deadline = accepted_at + Duration::from_millis(self.ctx.timing.preauth_ms);
        let first = match self.recv(Some(deadline)).await {
            Recv::Text(t) => t,
            Recv::Timeout => return self.close(4001).await,
            Recv::Binary => return self.close(1003).await,
            Recv::TooBig => return self.close(1009).await,
            Recv::Closed => return,
        };
        let frame = match Frame::parse(&first) {
            Ok(f) => f,
            Err(ProtocolError::VersionMismatch(_)) => return self.close(4010).await,
            // not a valid frame: nothing is sent, the connection closes (I1)
            Err(_) => return self.close(4001).await,
        };
        let entry = match frame.message {
            Message::Hello(hello) => self.handle_hello(&mut admission, &challenge, hello).await,
            Message::Pair(pair) => self.handle_pair(&mut admission, &challenge, pair).await,
            // `ping`, `ack`, `decision`, unknown types, server types: all forbidden before authentication
            _ => return self.close(4001).await,
        };
        let Some(entry) = entry else { return };
        admission.authenticated();
        self.run_authenticated(entry).await;
    }

    async fn fail_auth(&mut self, admission: &Admission, in_reply_to: Option<String>) {
        admission.record_failure();
        tokio::time::sleep(Duration::from_millis(self.ctx.timing.auth_fail_delay_ms)).await;
        // the reason is never revealed: unknown device, wrong token and wrong challenge look the same
        self.send_error(
            ErrorCode::AuthFailed,
            "authentication failed",
            "인증하지 못했어요.",
            in_reply_to,
            true,
        )
        .await;
        self.close(4002).await;
    }

    async fn handle_hello(
        &mut self,
        admission: &mut Admission,
        challenge: &Challenge,
        hello: HelloPayload,
    ) -> Option<EntryInfo> {
        if hello.protocol != agentnest_protocol::PROTOCOL_VERSION {
            self.send_error(
                ErrorCode::ProtoVersion,
                "unsupported protocol",
                "앱을 업데이트해 주세요.",
                None,
                true,
            )
            .await;
            self.close(4010).await;
            return None;
        }
        let devices = self.ctx.devices.clone();
        let (id, token) = (hello.device_id.clone(), hello.device_token.clone());
        let outcome =
            tokio::task::spawn_blocking(move || devices.authenticate(&id, token.expose()))
                .await
                .ok()
                .and_then(Result::ok);
        let challenge_ok = challenge.matches_b64(&hello.challenge_b64);
        match outcome {
            Some(AuthOutcome::Ok(rec)) if challenge_ok => {
                let ip_masked = mask_ip(&self.ip.to_string());
                let devices = self.ctx.devices.clone();
                let id = rec.device_id.clone();
                let _ =
                    tokio::task::spawn_blocking(move || devices.touch_seen(&id, Some(&ip_masked)))
                        .await;
                Some(EntryInfo {
                    device_id: rec.device_id,
                    last_seq: hello.last_seq,
                    wants_snapshot: hello.wants_snapshot,
                    from_pairing: false,
                })
            }
            Some(AuthOutcome::Revoked) if challenge_ok => {
                // valid credentials of a revoked device: the phone deletes its token
                self.send_error(
                    ErrorCode::DeviceRevoked,
                    "device revoked",
                    "PC에서 연결을 해제했어요.",
                    None,
                    true,
                )
                .await;
                self.close(4003).await;
                None
            }
            _ => {
                self.fail_auth(admission, None).await;
                None
            }
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    // pairing
    // -----------------------------------------------------------------------------------------------------------------

    async fn pair_fail(&mut self, code: ErrorCode, delay: bool) {
        if delay {
            tokio::time::sleep(Duration::from_millis(self.ctx.timing.auth_fail_delay_ms)).await;
        }
        self.send(Message::PairResult(PairResultPayload {
            ok: false,
            device_id: None,
            device_token: None,
            pc: None,
            error_code: Some(code),
        }))
        .await;
        self.close(4002).await;
    }

    async fn handle_pair(
        &mut self,
        admission: &mut Admission,
        challenge: &Challenge,
        pair: PairPayload,
    ) -> Option<EntryInfo> {
        let pc = self.ctx.pc_info();
        let mut pending: PendingConfirmation =
            match self.ctx.pairing.begin(&pc.pc_id, &pair, challenge) {
                Ok(p) => p,
                Err(PairFailure::BadMessage) => {
                    // a malformed pair is a protocol violation, nothing is revealed
                    self.close(4004).await;
                    return None;
                }
                Err(PairFailure::Busy) => {
                    self.pair_fail(ErrorCode::PairBusy, true).await;
                    return None;
                }
                Err(PairFailure::Failed) => {
                    admission.record_failure();
                    self.pair_fail(ErrorCode::PairFailed, true).await;
                    return None;
                }
            };
        // PairPending: only pair_pending / pair_result / error may be sent from here on
        let pending_frame = Message::PairPending(PairPendingPayload {
            pairing_id: pending.pairing_id.clone(),
            sas: pending.sas.clone(),
            confirm_timeout_ms: u32::try_from(self.ctx.timing.pair_confirm_ms).unwrap_or(60_000),
        });
        if !self.send(pending_frame).await {
            self.ctx.pairing.abort(pending, "failed").await;
            return None;
        }
        let Some(mut decision_rx) = pending.decision.take() else {
            self.ctx.pairing.abort(pending, "failed").await;
            return None;
        };
        let deadline = Instant::now() + Duration::from_millis(self.ctx.timing.pair_confirm_ms);
        #[allow(clippy::never_loop)]
        let verdict = loop {
            tokio::select! {
                d = &mut decision_rx => {
                    break match d {
                        Ok(ConfirmDecision::Approve) => Verdict::Approve,
                        Ok(ConfirmDecision::Reject) | Err(_) => Verdict::Reject,
                    };
                }
                _ = tokio::time::sleep_until(deadline) => break Verdict::Timeout,
                msg = self.recv(None) => {
                    match msg {
                        Recv::Text(t) => {
                            match Frame::parse(&t).map(|f| f.message) {
                                Ok(Message::Unpair(UnpairPayload { pairing_id: Some(p), .. })) if p == pending.pairing_id => {
                                    break Verdict::Aborted;
                                }
                                // anything else from the phone while the PC user decides: 4001
                                _ => break Verdict::Violation,
                            }
                        }
                        Recv::Binary | Recv::TooBig => break Verdict::Violation,
                        Recv::Closed | Recv::Timeout => break Verdict::Aborted,
                    }
                }
            }
        };
        match verdict {
            Verdict::Approve => match self.ctx.pairing.finalize(pending).await {
                Ok(issued) => self.complete_pairing(issued).await,
                Err(_) => {
                    self.pair_fail(ErrorCode::PairFailed, false).await;
                    None
                }
            },
            Verdict::Reject | Verdict::Timeout => {
                self.ctx.pairing.abort(pending, "rejected").await;
                self.pair_fail(ErrorCode::PairRejected, true).await;
                None
            }
            Verdict::Aborted => {
                self.ctx.pairing.abort(pending, "failed").await;
                self.close(1000).await;
                None
            }
            Verdict::Violation => {
                self.ctx.pairing.abort(pending, "failed").await;
                self.close(4001).await;
                None
            }
        }
    }

    /// Sends the one-time `pair_result` with the device token. If it cannot be written, nobody will ever hold that token:
    /// the freshly created device is revoked again (`pairing_result_not_delivered`) so that no active device without an
    /// owner stays behind, and the connection ends.
    async fn complete_pairing(&mut self, issued: IssuedDevice) -> Option<EntryInfo> {
        let pc = self.ctx.pc_info();
        let delivered = self
            .send(Message::PairResult(PairResultPayload {
                ok: true,
                device_id: Some(issued.device_id.clone()),
                // the only time the token travels
                device_token: Some(agentnest_protocol::Secret::new(issued.token.expose())),
                pc: Some(PcInfo {
                    pc_id: pc.pc_id,
                    name: pc.name,
                    app_version: env!("CARGO_PKG_VERSION").to_owned(),
                    os: None,
                }),
                error_code: None,
            }))
            .await;
        if !delivered {
            let devices = self.ctx.devices.clone();
            let id = issued.device_id.clone();
            let revoked = tokio::task::spawn_blocking(move || {
                devices.revoke(&id, "pairing_result_not_delivered")
            })
            .await;
            tracing::warn!(
                revoked = matches!(revoked, Ok(Ok(true))),
                "pair_result could not be delivered; the new device was revoked"
            );
            self.ctx
                .audit
                .log(
                    crate::audit::ACTOR_SYSTEM,
                    actions::DEVICE_REVOKED,
                    Some(issued.device_id.clone()),
                    Some(json!({"reason": "pairing_result_not_delivered"})),
                )
                .await;
            self.ctx
                .bus
                .emit(DaemonEvent::Device(DeviceUiEvent::Revoked {
                    device_id: issued.device_id,
                }));
            return None;
        }
        Some(EntryInfo {
            device_id: issued.device_id,
            last_seq: 0,
            wants_snapshot: true,
            from_pairing: true,
        })
    }

    // -----------------------------------------------------------------------------------------------------------------
    // Authenticated
    // -----------------------------------------------------------------------------------------------------------------

    fn welcome(&self, resync: Resync) -> Message {
        let pc = self.ctx.pc_info();
        let policy = &self.ctx.policy;
        let mut capabilities: Vec<String> = [
            "events",
            "approvals",
            "snapshot",
            "resync",
            "events_history",
            "claude_code",
            "codex_observe",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        if cfg!(feature = "codex-hooks-approval") {
            capabilities.push("codex_approve_hooks".to_owned());
        }
        Message::Welcome(Box::new(WelcomePayload {
            pc: PcInfo {
                pc_id: pc.pc_id,
                name: pc.name,
                app_version: env!("CARGO_PKG_VERSION").to_owned(),
                os: Some(std::env::consts::OS.to_owned()),
            },
            protocol: ProtocolInfo {
                version: 1,
                minor: 0,
                min_client_version: "0.1.0".to_owned(),
            },
            hosts: Hosts {
                addresses: pc.hosts,
                port: pc.port,
            },
            capabilities,
            server_time: format_ms(self.now_ms()),
            heartbeat: Heartbeat {
                client_ping_interval_s: 30,
                server_idle_close_s: u32::try_from(self.ctx.timing.idle_close_ms / 1000)
                    .unwrap_or(90),
            },
            resync,
            limits: Limits {
                approval_ttl_s: policy.effective_ttl_s.load(Ordering::Relaxed),
                max_frame_bytes: MAX_FRAME_S2C_BYTES as u32,
                snapshot_max_bytes: SNAPSHOT_MAX_BYTES as u32,
                events_page_max_bytes: EVENTS_PAGE_MAX_BYTES as u32,
            },
            policy: Policy {
                remote_approval: RemoteApprovalPolicy {
                    critical: if policy.critical_local_only.load(Ordering::Relaxed) {
                        "local_only"
                    } else {
                        "extra_confirmation"
                    }
                    .to_owned(),
                    high: "hold".to_owned(),
                },
                deny_requires_auth: policy.deny_requires_auth.load(Ordering::Relaxed),
            },
        }))
    }

    async fn run_authenticated(&mut self, entry: EntryInfo) {
        let ctx = self.ctx.clone();
        let device_id = entry.device_id.clone();
        // subscribe BEFORE the resync plan so no message published in between can be missed
        let live = ctx.registry.subscribe();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        if ctx.timing.post_auth_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(ctx.timing.post_auth_delay_ms)).await;
        }
        let conn_id = ctx.registry.register(&device_id, cmd_tx);
        // I6: a revocation that happened after the authentication but before this registration kicked nobody (the
        // connection was not in the registry yet). Look again now that it is registered: a revoked device never
        // becomes online.
        let devices = ctx.devices.clone();
        let id = device_id.clone();
        let active = tokio::task::spawn_blocking(move || devices.is_active(&id))
            .await
            .unwrap_or(false);
        if !active {
            let was_current = ctx.registry.unregister(&device_id, conn_id);
            self.send(Message::Bye(ByePayload {
                reason: ByeReason::DeviceRevoked,
                reconnect: false,
                message_ko: Some("PC에서 이 기기의 연결을 해제했어요.".to_owned()),
            }))
            .await;
            self.close(4003).await;
            if was_current {
                ctx.broker.device_disconnected().await;
            }
            return;
        }
        ctx.broker.device_connected().await;
        ctx.bus.emit(DaemonEvent::Device(DeviceUiEvent::Online {
            device_id: device_id.clone(),
        }));
        let mut st = AuthState {
            device_id: device_id.clone(),
            conn_id,
            cmd_rx,
            live,
            sent_up_to: entry.last_seq.max(0),
            acks: HashMap::new(),
            limits: ctx.registry.limiter(&device_id),
            last_acked_written: 0,
            bad_messages: 0,
            last_rx: Instant::now(),
        };
        let ok = self.start_authenticated(&mut st, &entry).await;
        if ok {
            self.main_loop(&mut st).await;
        }
        // leave: the registry entry first, then the broker (grace period / hand-off)
        let went_offline = ctx.registry.unregister(&device_id, st.conn_id);
        if went_offline {
            ctx.bus.emit(DaemonEvent::Device(DeviceUiEvent::Offline {
                device_id: device_id.clone(),
            }));
            ctx.broker.device_disconnected().await;
        }
    }

    /// `welcome` and the resync. Returns `false` if the socket is gone.
    async fn start_authenticated(&mut self, st: &mut AuthState, entry: &EntryInfo) -> bool {
        let store = self.ctx.store.clone();
        let last_seq = entry.last_seq;
        let plan = if entry.wants_snapshot || entry.from_pairing {
            ResyncPlan::Snapshot
        } else {
            match tokio::task::spawn_blocking(move || store.plan_resync(last_seq)).await {
                Ok(Ok(p)) => p,
                _ => ResyncPlan::Snapshot,
            }
        };
        let resync = match plan {
            ResyncPlan::None => Resync {
                mode: ResyncMode::None,
                from_seq: None,
                to_seq: None,
            },
            ResyncPlan::Replay { from, to } => Resync {
                mode: ResyncMode::Replay,
                from_seq: Some(from),
                to_seq: Some(to),
            },
            ResyncPlan::Snapshot => Resync {
                mode: ResyncMode::Snapshot,
                from_seq: None,
                to_seq: None,
            },
        };
        let welcome = self.welcome(resync);
        if !self.send(welcome).await {
            return false;
        }
        match plan {
            ResyncPlan::None => true,
            ResyncPlan::Replay { from, .. } => self.replay(st, from - 1).await,
            ResyncPlan::Snapshot => self.send_snapshot(st).await,
        }
    }

    async fn main_loop(&mut self, st: &mut AuthState) {
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let idle = Duration::from_millis(self.ctx.timing.idle_close_ms);
        loop {
            let idle_at = st.last_rx + idle;
            tokio::select! {
                msg = self.recv(None) => {
                    st.last_rx = Instant::now();
                    match msg {
                        Recv::Text(t) => {
                            if let Flow::End = self.handle_text(st, &t).await { return; }
                        }
                        Recv::Binary => return self.close(1003).await,
                        Recv::TooBig => return self.close(1009).await,
                        Recv::Closed | Recv::Timeout => return,
                    }
                }
                cmd = st.cmd_rx.recv() => {
                    match cmd {
                        Some(ConnCommand::Send(m)) => { if !self.send(m).await { return; } }
                        Some(ConnCommand::Bye { reason, reconnect, message_ko, close_code }) => {
                            self.send(Message::Bye(ByePayload { reason, reconnect, message_ko: Some(message_ko) })).await;
                            return self.close(close_code).await;
                        }
                        Some(ConnCommand::Close { code }) => return self.close(code).await,
                        None => return,
                    }
                }
                live = st.live.recv() => {
                    match live {
                        Ok(p) => { if !self.forward(st, &p).await { return; } }
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            // missed live messages: catch up from the stored stream (or a snapshot)
                            if !self.catch_up(st).await { return; }
                        }
                        Err(broadcast::error::RecvError::Closed) => return,
                    }
                }
                _ = tokio::time::sleep_until(idle_at) => {
                    return self.close(4008).await;
                }
                _ = tick.tick() => {
                    if !self.resend_unacked(st).await { return; }
                }
            }
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    // outgoing replayable messages
    // -----------------------------------------------------------------------------------------------------------------

    /// Sends one live message (if it is newer than what the phone already has).
    async fn forward(&mut self, st: &mut AuthState, p: &Published) -> bool {
        if p.seq <= st.sent_up_to {
            return true;
        }
        st.sent_up_to = p.seq;
        let text = self.stream_text(p.seq, &p.msg_type, &p.payload);
        if p.msg_type == "approval_request" {
            let request_id = p
                .payload
                .get("request_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            if !self.send_text(text.clone()).await {
                return false;
            }
            self.track_card(st, &request_id, text).await;
            return true;
        }
        if p.msg_type == "approval_resolved" {
            // the card is dead (resolved, expired, handed off, superseded): it must never be re-sent
            Self::forget_card(st, p.payload.get("request_id").and_then(Value::as_str));
        }
        self.send_text(text).await
    }

    /// Stops the un-acked tracking of a card: a request that ended needs no more re-sends (protocol.md 8.4: a dead card
    /// is never revived).
    fn forget_card(st: &mut AuthState, request_id: Option<&str>) {
        if let Some(id) = request_id {
            st.acks.remove(id);
        }
    }

    async fn track_card(&mut self, st: &mut AuthState, request_id: &str, text: String) {
        if request_id.is_empty() {
            return;
        }
        st.acks.insert(
            request_id.to_owned(),
            AckTrack {
                text,
                last_sent: Instant::now(),
                retries: 0,
            },
        );
        self.ctx.broker.mark_sent(request_id, &st.device_id).await;
    }

    async fn resend_unacked(&mut self, st: &mut AuthState) -> bool {
        let wait = Duration::from_millis(self.ctx.timing.ack_retry_ms);
        let max = self.ctx.timing.ack_retries;
        let due: Vec<String> = st
            .acks
            .iter()
            .filter(|(_, a)| a.last_sent.elapsed() >= wait)
            .map(|(id, _)| id.clone())
            .collect();
        for id in due {
            // a request that is no longer pending is not re-sent, whatever its `approval_resolved` did or did not clear
            if self.ctx.broker.pending_card(&id).await.is_none() {
                st.acks.remove(&id);
                continue;
            }
            let Some(a) = st.acks.get_mut(&id) else {
                continue;
            };
            if a.retries >= max {
                st.acks.remove(&id);
                self.ctx.broker.delivery_failed(&id);
                continue;
            }
            a.retries += 1;
            a.last_sent = Instant::now();
            let text = a.text.clone();
            if !self.send_text(text).await {
                return false;
            }
        }
        true
    }

    /// Sends the stored messages after `after_seq` (replay), replacing expired or closed approval cards by
    /// `approval_resolved` (protocol.md 8.4: a dead card is never revived).
    async fn replay(&mut self, st: &mut AuthState, after_seq: i64) -> bool {
        let store = self.ctx.store.clone();
        let now = format_ms(self.now_ms());
        let items = match tokio::task::spawn_blocking(move || {
            store.stream_replay_since(after_seq, REPLAY_LIMIT, &now)
        })
        .await
        {
            Ok(Ok(v)) => v,
            _ => return self.send_snapshot(st).await,
        };
        for item in items {
            let row = item.row;
            st.sent_up_to = st.sent_up_to.max(row.seq);
            match (row.msg_type.as_str(), item.approval) {
                ("approval_request", Some(ApprovalReplayState::Pending)) => {
                    let request_id = row.ref_id.clone().unwrap_or_default();
                    let text = self.stream_text(row.seq, "approval_request", &row.payload);
                    if !self.send_text(text.clone()).await {
                        return false;
                    }
                    self.track_card(st, &request_id, text).await;
                }
                ("approval_request", Some(state)) => {
                    let request_id = row.ref_id.clone().unwrap_or_default();
                    let session_key = row
                        .session_key
                        .clone()
                        .or_else(|| {
                            row.payload
                                .get("session_key")
                                .and_then(Value::as_str)
                                .map(str::to_owned)
                        })
                        .unwrap_or_default();
                    let payload =
                        resolved_replacement(&request_id, &session_key, state, self.now_ms());
                    let text = self.stream_text(row.seq, "approval_resolved", &payload);
                    Self::forget_card(st, Some(&request_id));
                    if !self.send_text(text).await {
                        return false;
                    }
                }
                (t, _) => {
                    if t == "approval_resolved" {
                        Self::forget_card(
                            st,
                            row.payload.get("request_id").and_then(Value::as_str),
                        );
                    }
                    let text = self.stream_text(row.seq, t, &row.payload);
                    if !self.send_text(text).await {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// After a lag: replay from the last sent `seq`, or a snapshot if the window is gone.
    async fn catch_up(&mut self, st: &mut AuthState) -> bool {
        let store = self.ctx.store.clone();
        let last = st.sent_up_to;
        match tokio::task::spawn_blocking(move || store.plan_resync(last)).await {
            Ok(Ok(ResyncPlan::None)) => true,
            Ok(Ok(ResyncPlan::Replay { from, .. })) => self.replay(st, from - 1).await,
            _ => self.send_snapshot(st).await,
        }
    }

    async fn build_snapshot(
        ctx: Arc<LinkContext>,
    ) -> Option<(
        i64,
        SnapshotPayload,
        Vec<agentnest_protocol::ApprovalRequest>,
    )> {
        let store = ctx.store.clone();
        // 1. the sequence the snapshot stands for is read FIRST: everything read afterwards is at least as new, and the
        //    live stream (seq > snapshot.seq) repairs the difference
        let seq0 = {
            let s = store.clone();
            tokio::task::spawn_blocking(move || s.stream_bounds())
                .await
                .ok()?
                .ok()?
                .max_seq
        };
        let pending = ctx.broker.pending_cards().await;
        let sessions = ctx.pipeline.snapshot_sessions(snapshot::MAX_SESSIONS).await;
        let adapters = ctx.pipeline.adapters().await;
        let focus = ctx
            .pipeline
            .focus()
            .await
            .map(|(session_key, state)| Focus { session_key, state });
        let (mut recent_events, recent_errors) = {
            let s = store.clone();
            tokio::task::spawn_blocking(move || {
                Ok::<_, crate::store::StoreError>((s.recent_events(50)?, s.recent_errors(5)?))
            })
            .await
            .ok()?
            .ok()?
        };
        recent_events.retain(|e| e.seq.is_none_or(|s| s <= seq0));
        let mut recent_errors = recent_errors;
        recent_errors.retain(|e| e.seq.is_none_or(|s| s <= seq0));
        let (payload, followups) = snapshot::build(
            SnapshotInputs {
                sessions,
                pending,
                recent_errors,
                recent_events,
                adapters,
                focus,
            },
            SNAPSHOT_MAX_BYTES,
        );
        Some((seq0, payload, followups))
    }

    async fn send_snapshot(&mut self, st: &mut AuthState) -> bool {
        let Some((seq0, payload, followups)) = Self::build_snapshot(self.ctx.clone()).await else {
            self.send_error(
                ErrorCode::Internal,
                "snapshot unavailable",
                "잠시 후 다시 시도해 주세요.",
                None,
                false,
            )
            .await;
            return true;
        };
        let ids: Vec<String> = payload
            .pending_approvals
            .iter()
            .map(|c| c.request_id.clone())
            .collect();
        let Some(text) = self.frame_text(Some(seq0), Message::Snapshot(Box::new(payload))) else {
            return true;
        };
        if !self.send_text(text).await {
            return false;
        }
        st.sent_up_to = st.sent_up_to.max(seq0);
        for id in ids {
            self.ctx.broker.mark_sent(&id, &st.device_id).await;
        }
        // cards that did not fit follow as their own frames (original seq: the stored approval_request row)
        for card in followups {
            let rid = card.request_id.clone();
            let store = self.ctx.store.clone();
            let rid2 = rid.clone();
            let seq = tokio::task::spawn_blocking(move || {
                store.read(move |c| {
                    use rusqlite::OptionalExtension;
                    Ok(c.query_row(
                        "SELECT seq FROM stream WHERE msg_type='approval_request' AND ref_id=?1 ORDER BY seq DESC LIMIT 1",
                        [rid2],
                        |r| r.get::<_, i64>(0),
                    )
                    .optional()?)
                })
            })
            .await
            .ok()
            .and_then(Result::ok)
            .flatten()
            .unwrap_or(seq0);
            let Ok(payload) = serde_json::to_value(&card) else {
                continue;
            };
            let text = self.stream_text(seq, "approval_request", &payload);
            if !self.send_text(text.clone()).await {
                return false;
            }
            self.track_card(st, &rid, text).await;
        }
        true
    }

    // -----------------------------------------------------------------------------------------------------------------
    // incoming messages
    // -----------------------------------------------------------------------------------------------------------------

    async fn strike(&mut self, st: &mut AuthState, in_reply_to: Option<String>) -> Flow {
        let now = self.now_ms();
        if st.limit(|l| l.strike(now)) >= MAX_RATE_STRIKES {
            self.send_error(
                ErrorCode::RateLimited,
                "too many requests",
                "요청이 너무 많아요.",
                in_reply_to,
                true,
            )
            .await;
            self.close(4005).await;
            return Flow::End;
        }
        if !self
            .send_error(
                ErrorCode::RateLimited,
                "rate limited",
                "잠시 후 다시 시도해 주세요.",
                in_reply_to,
                false,
            )
            .await
        {
            return Flow::End;
        }
        Flow::Continue
    }

    async fn handle_text(&mut self, st: &mut AuthState, text: &str) -> Flow {
        let frame = match Frame::parse(text) {
            Ok(f) => f,
            Err(ProtocolError::VersionMismatch(_)) => {
                self.send_error(
                    ErrorCode::ProtoVersion,
                    "unsupported protocol",
                    "앱을 업데이트해 주세요.",
                    None,
                    true,
                )
                .await;
                self.close(4010).await;
                return Flow::End;
            }
            Err(_) => {
                st.bad_messages += 1;
                if st.bad_messages >= MAX_BAD_MESSAGES {
                    self.send_error(
                        ErrorCode::BadMessage,
                        "too many malformed messages",
                        "잘못된 메시지가 너무 많아요.",
                        None,
                        true,
                    )
                    .await;
                    self.close(4004).await;
                    return Flow::End;
                }
                // a schema violation (for example a decision with a value that does not exist) changes nothing
                if !self
                    .send_error(
                        ErrorCode::BadMessage,
                        "malformed message",
                        "메시지 형식이 올바르지 않아요.",
                        None,
                        false,
                    )
                    .await
                {
                    return Flow::End;
                }
                return Flow::Continue;
            }
        };
        let frame_id = frame.id.clone();
        let now = self.now_ms();
        match frame.message {
            Message::Ack(ack) => {
                // the database write is monotonic and rate limited; the ack itself is always honoured
                let write_ack = ack
                    .through_seq
                    .filter(|seq| *seq > st.last_acked_written)
                    .filter(|_| st.limit(|l| l.ack_writes.try_acquire(now)));
                if let Some(seq) = write_ack {
                    st.last_acked_written = seq;
                    let devices = self.ctx.devices.clone();
                    let id = st.device_id.clone();
                    let _ =
                        tokio::task::spawn_blocking(move || devices.set_last_acked(&id, seq)).await;
                }
                if !ack.approval_ids.is_empty() {
                    for id in &ack.approval_ids {
                        st.acks.remove(id);
                    }
                    self.ctx
                        .broker
                        .mark_acked(&ack.approval_ids, &st.device_id)
                        .await;
                }
                Flow::Continue
            }
            Message::Ping(_) => {
                if !st.limit(|l| l.ping.try_acquire(now)) {
                    return self.strike(st, Some(frame_id)).await;
                }
                let pong = Message::Pong(PongPayload {
                    in_reply_to: frame_id,
                    server_time: format_ms(now),
                });
                if self.send(pong).await {
                    Flow::Continue
                } else {
                    Flow::End
                }
            }
            Message::SnapshotRequest(_) => {
                if !st.limit(|l| l.snapshot.try_acquire(now)) {
                    return self.strike(st, Some(frame_id)).await;
                }
                if self.send_snapshot(st).await {
                    Flow::Continue
                } else {
                    Flow::End
                }
            }
            Message::EventsRequest(req) => {
                if !st.limit(|l| l.events.try_acquire(now)) {
                    return self.strike(st, Some(frame_id)).await;
                }
                if self.handle_events_request(&frame_id, req).await {
                    Flow::Continue
                } else {
                    Flow::End
                }
            }
            Message::Decision(d) => {
                if !st.limit(|l| l.decision.try_acquire(now)) {
                    return self.strike(st, Some(frame_id)).await;
                }
                if self.handle_decision(st, &frame_id, d).await {
                    Flow::Continue
                } else {
                    Flow::End
                }
            }
            Message::ApprovalSeen(s) => {
                self.ctx
                    .broker
                    .mark_seen(&s.request_id, &st.device_id)
                    .await;
                Flow::Continue
            }
            Message::Unpair(u) => self.handle_unpair(st, u).await,
            // messages the phone must not send, and anything unknown: server types count as malformed, unknown types are
            // ignored (forward compatibility)
            Message::Unknown { .. } => Flow::Continue,
            Message::Hello(_) | Message::Pair(_) => Flow::Continue,
            _ => {
                st.bad_messages += 1;
                if st.bad_messages >= MAX_BAD_MESSAGES {
                    self.close(4004).await;
                    return Flow::End;
                }
                Flow::Continue
            }
        }
    }

    async fn handle_events_request(&mut self, frame_id: &str, req: EventsRequestPayload) -> bool {
        let store = self.ctx.store.clone();
        let q = EventsQuery {
            session_key: req.session_key,
            before_seq: req.before_seq,
            limit: req.limit,
            kinds: req.kinds.unwrap_or_default(),
            max_bytes: EVENTS_PAGE_MAX_BYTES,
        };
        let page = match tokio::task::spawn_blocking(move || store.events_page(&q)).await {
            Ok(Ok(p)) => p,
            _ => {
                return self
                    .send_error(
                        ErrorCode::Internal,
                        "events unavailable",
                        "잠시 후 다시 시도해 주세요.",
                        Some(frame_id.to_owned()),
                        false,
                    )
                    .await;
            }
        };
        self.send(Message::EventsPage(Box::new(EventsPagePayload {
            in_reply_to: frame_id.to_owned(),
            events: page.events,
            has_more: page.has_more,
            next_before_seq: page.next_before_seq,
            detail_omitted: page.detail_omitted,
        })))
        .await
    }

    async fn handle_decision(
        &mut self,
        st: &mut AuthState,
        frame_id: &str,
        d: DecisionPayload,
    ) -> bool {
        let outcome: DecisionOutcome = self
            .ctx
            .broker
            .apply_decision(DecisionInput {
                source: DecisionSource::Phone {
                    device_id: st.device_id.clone(),
                },
                decision_id: frame_id.to_owned(),
                request_id: d.request_id.clone(),
                session_key: Some(d.session_key),
                nonce_b64: Some(d.nonce_b64),
                tool_input_sha256: d.tool_input_sha256,
                decision: d.decision,
                reason: d.reason,
                decided_at: Some(d.decided_at),
                auth: d.auth,
                extra_confirmation: d.extra_confirmation,
                confirm_ack: false,
            })
            .await;
        // a decided request needs no more card re-sends
        if outcome.accepted {
            st.acks.remove(&outcome.request_id);
        }
        self.send(Message::DecisionResult(DecisionResultPayload {
            request_id: outcome.request_id,
            in_reply_to: frame_id.to_owned(),
            accepted: outcome.accepted,
            reason: outcome.reason,
            message_ko: Some(outcome.message_ko),
        }))
        .await
    }

    async fn handle_unpair(&mut self, st: &mut AuthState, u: UnpairPayload) -> Flow {
        // only the phone's own registration can be removed; `pairing_id` is meaningless after authentication
        if u.device_id.as_deref() != Some(st.device_id.as_str()) {
            return Flow::Continue;
        }
        let devices = self.ctx.devices.clone();
        let id = st.device_id.clone();
        let revoked = tokio::task::spawn_blocking(move || devices.revoke(&id, "user_phone"))
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false);
        if revoked {
            self.ctx
                .audit
                .log(
                    device_actor(&st.device_id),
                    actions::DEVICE_REVOKED,
                    Some(st.device_id.clone()),
                    Some(json!({"reason": "user_phone"})),
                )
                .await;
            self.ctx
                .bus
                .emit(DaemonEvent::Device(DeviceUiEvent::Revoked {
                    device_id: st.device_id.clone(),
                }));
        }
        self.send(Message::Bye(ByePayload {
            reason: ByeReason::Unpaired,
            reconnect: false,
            message_ko: Some("연결을 해제했어요.".to_owned()),
        }))
        .await;
        self.close(1000).await;
        // the registry entry is removed by the caller; with no phone left the broker hands pending requests off
        Flow::End
    }
}

struct EntryInfo {
    device_id: String,
    last_seq: i64,
    wants_snapshot: bool,
    from_pairing: bool,
}

enum Verdict {
    Approve,
    Reject,
    Timeout,
    Aborted,
    Violation,
}

/// The `approval_resolved` payload that replaces an `approval_request` during replay.
fn resolved_replacement(
    request_id: &str,
    session_key: &str,
    state: ApprovalReplayState,
    now_ms: i64,
) -> Value {
    let (outcome, resolved_by, resolved_at, delivery, observed) = match state {
        ApprovalReplayState::Resolved {
            outcome,
            resolved_by,
            resolved_at,
            delivery,
            observed_result,
            ..
        } => (
            outcome
                .map(|o| ApprovalOutcome::from_wire(&o))
                .unwrap_or(ApprovalOutcome::Expired),
            resolved_by
                .map(|r| ResolvedBy::from_wire(&r))
                .unwrap_or(ResolvedBy::System),
            resolved_at.unwrap_or_else(|| format_ms(now_ms)),
            delivery
                .map(|d| Delivery::from_wire(&d))
                .unwrap_or(Delivery::NotDelivered),
            ObservedResult::from_wire(&observed_result),
        ),
        // expired while pending, or the row is gone
        ApprovalReplayState::Pending | ApprovalReplayState::Expired | ApprovalReplayState::Gone => {
            (
                ApprovalOutcome::Expired,
                ResolvedBy::Timeout,
                format_ms(now_ms),
                Delivery::NotDelivered,
                ObservedResult::Undetermined,
            )
        }
    };
    let message_ko =
        crate::approvals::card::resolved_message_ko(&outcome, agentnest_protocol::AgentKind::Other);
    serde_json::to_value(ApprovalResolvedPayload {
        request_id: request_id.to_owned(),
        session_key: session_key.to_owned(),
        outcome,
        resolved_by,
        resolved_device_id: None,
        resolved_at,
        delivery,
        observed_result: observed,
        message_ko,
    })
    .unwrap_or(Value::Null)
}
