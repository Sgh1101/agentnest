//! `DaemonEvent` to the front end's `daemon-event {kind, payload}` envelope (docs/desktop.md 3.1), plus the side effects
//! the shell derives from an event (show the window for the SAS modal, toasts, tray refresh).
//!
//! [`EventMapper`] is pure and synchronous. Two things need more than the event itself and are returned as requests for
//! [`crate::ShellApi::process`] to fulfil: the `device` payload carries the whole device row ([`Mapped::DeviceLookup`])
//! and `pairing`/`completed` needs the device id, which the daemon emits in the *following* `Device::Paired` event (the
//! mapper pairs the two).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use agentnest_core::events::{
    ApprovalChannel, ApprovalUiEvent, DaemonEvent, DeviceUiEvent, LinkUiEvent, PairingUiEvent,
};
use agentnest_core::redact::{clip, sanitize_display_text};
use agentnest_core::state::timers::{format_ms, Clock};
use agentnest_protocol::{ApprovalOutcome, ResolvedBy};
use serde::Serialize;
use serde_json::{json, Value};

use crate::dto::{agent_event_value, approval_pending_value};

/// The `daemon-event` message.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Envelope {
    /// `event | session_state | approval | device | pairing | adapter | link`.
    pub kind: &'static str,
    /// Kind specific payload.
    pub payload: Value,
}

impl Envelope {
    /// Builds an envelope.
    pub fn new(kind: &'static str, payload: Value) -> Self {
        Self { kind, payload }
    }
}

/// A desktop toast (docs/desktop.md 4). The body never contains a command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notification {
    /// Title.
    pub title: String,
    /// Body.
    pub body: String,
}

impl Notification {
    fn new(title: &str, body: &str) -> Self {
        Self {
            title: title.to_owned(),
            body: clip(&sanitize_display_text(body), 80),
        }
    }
}

/// What the glue has to do after an event.
#[derive(Clone, Debug, PartialEq)]
pub enum ShellAction {
    /// Forward to the webview (`Emitter::emit("daemon-event", ..)`).
    Emit(Envelope),
    /// `show()` + `set_focus()` on the main window (the SAS modal needs a visible window).
    ShowWindow,
    /// A toast (only shown when `app.notifications` is on).
    Notify(Notification),
    /// The tray icon / menu may have changed.
    RefreshTray,
}

/// The raw result of mapping one event.
#[derive(Clone, Debug, PartialEq)]
pub enum Mapped {
    /// Ready to forward.
    Emit(Envelope),
    /// The `device` payload needs the full device row for `device_id`.
    DeviceLookup {
        /// `paired | online | offline | revoked | updated`.
        op: &'static str,
        /// Device id.
        device_id: String,
        /// Toast title, if this change deserves one.
        toast: Option<&'static str>,
    },
    /// Show and focus the main window.
    ShowWindow,
    /// A toast.
    Notify(Notification),
    /// Refresh the tray.
    RefreshTray,
    /// An unauthenticated connection attempt (feeds the diagnostics report).
    PreAuth {
        /// Time (RFC 3339).
        at: String,
        /// Masked address.
        ip_masked: String,
    },
    /// The daemon reported an error (the tray turns red for a while).
    DaemonError,
}

/// Maps daemon events. Keep one per event pump.
pub struct EventMapper {
    clock: Arc<dyn Clock>,
    paused: Arc<AtomicBool>,
    pairing_waiting_for_device: Option<String>,
    local_notified: VecDeque<String>,
}

const LOCAL_NOTIFIED_CAP: usize = 64;

impl EventMapper {
    /// A mapper. `paused` is the shared "remote approval paused" flag the `link` payload reports.
    pub fn new(clock: Arc<dyn Clock>, paused: Arc<AtomicBool>) -> Self {
        Self {
            clock,
            paused,
            pairing_waiting_for_device: None,
            local_notified: VecDeque::new(),
        }
    }

    fn remember_local(&mut self, request_id: &str) {
        if self.local_notified.len() >= LOCAL_NOTIFIED_CAP {
            self.local_notified.pop_front();
        }
        self.local_notified.push_back(request_id.to_owned());
    }

    /// Maps one event to zero or more results, in the order they must be applied.
    pub fn map(&mut self, ev: &DaemonEvent) -> Vec<Mapped> {
        match ev {
            DaemonEvent::Event(e) => vec![Mapped::Emit(Envelope::new(
                "event",
                json!([agent_event_value(e)]),
            ))],
            DaemonEvent::SessionState(s) => vec![
                Mapped::Emit(Envelope::new(
                    "session_state",
                    serde_json::to_value(s.as_ref()).unwrap_or(Value::Null),
                )),
                Mapped::RefreshTray,
            ],
            DaemonEvent::Approval(a) => self.map_approval(a),
            DaemonEvent::Device(d) => self.map_device(d),
            DaemonEvent::Pairing(p) => self.map_pairing(p),
            DaemonEvent::Adapter(a) => vec![
                Mapped::Emit(Envelope::new(
                    "adapter",
                    serde_json::to_value(a).unwrap_or(Value::Null),
                )),
                Mapped::RefreshTray,
            ],
            DaemonEvent::Link(l) => self.map_link(l),
            DaemonEvent::Error { .. } => vec![Mapped::DaemonError, Mapped::RefreshTray],
        }
    }

    fn map_approval(&mut self, a: &ApprovalUiEvent) -> Vec<Mapped> {
        match a {
            ApprovalUiEvent::Opened { request, channel } => {
                let (title, body) = match channel {
                    ApprovalChannel::Remote => ("승인 요청이 도착했어요", request.title.as_str()),
                    ApprovalChannel::LocalOnly | ApprovalChannel::NoDevice => {
                        self.remember_local(&request.request_id);
                        ("PC에서 처리해야 하는 요청", request.title.as_str())
                    }
                };
                vec![
                    Mapped::Emit(Envelope::new(
                        "approval",
                        json!({
                            "op": "requested",
                            "approval": approval_pending_value(request, &[], false, false),
                        }),
                    )),
                    Mapped::Notify(Notification::new(title, body)),
                    Mapped::RefreshTray,
                ]
            }
            ApprovalUiEvent::Resolved {
                request_id,
                session_key,
                outcome,
                resolved_by,
                message_ko,
                ..
            } => {
                let mut out = vec![Mapped::Emit(Envelope::new(
                    "approval",
                    json!({
                        "op": "resolved",
                        "resolved": {
                            "request_id": request_id,
                            "session_key": session_key,
                            "outcome": outcome.as_str(),
                            "resolved_by": resolved_by.as_str(),
                            "resolved_device_id": Value::Null,
                            "resolved_at": format_ms(self.clock.now_ms()),
                            "message_ko": message_ko,
                        },
                    }),
                ))];
                // A request that fell back to the local prompt without the user doing it needs the user at the PC.
                let fell_back = matches!(
                    outcome,
                    ApprovalOutcome::Expired | ApprovalOutcome::HandedOffLocal
                ) && matches!(resolved_by, ResolvedBy::Timeout | ResolvedBy::System);
                if fell_back && !self.local_notified.iter().any(|r| r == request_id) {
                    self.remember_local(request_id);
                    out.push(Mapped::Notify(Notification::new(
                        "PC에서 처리해야 하는 요청",
                        "휴대폰에서 처리되지 않아 PC로 넘겼어요",
                    )));
                }
                out.push(Mapped::RefreshTray);
                out
            }
            ApprovalUiEvent::Delivery {
                request_id,
                sent_to,
                acked,
                seen,
            } => vec![Mapped::Emit(Envelope::new(
                "approval",
                json!({
                    "op": "delivery",
                    "request_id": request_id,
                    "delivery": {"sent_to": sent_to, "acked": acked, "seen": seen},
                }),
            ))],
            // Neither has a front-end payload: the card stays pending until it resolves.
            ApprovalUiEvent::DeliveryFailed { .. } | ApprovalUiEvent::DecisionRejected { .. } => {
                Vec::new()
            }
        }
    }

    fn map_device(&mut self, d: &DeviceUiEvent) -> Vec<Mapped> {
        let (op, device_id, toast) = match d {
            DeviceUiEvent::Paired { device_id, .. } => {
                (
                    "paired",
                    device_id,
                    Some("기기를 추가했어요"),
                )
            }
            DeviceUiEvent::Revoked { device_id } => ("revoked", device_id, Some("기기를 폐기했어요")),
            DeviceUiEvent::Online { device_id } => {
                ("online", device_id, Some("휴대폰이 연결됐어요"))
            }
            DeviceUiEvent::Offline { device_id } => {
                ("offline", device_id, Some("휴대폰 연결이 끊겼어요"))
            }
        };
        let mut out = Vec::new();
        if op == "paired" {
            if let Some(pairing_id) = self.pairing_waiting_for_device.take() {
                out.push(Mapped::Emit(Envelope::new(
                    "pairing",
                    json!({"op": "completed", "pairing_id": pairing_id, "device_id": device_id}),
                )));
            }
        }
        out.push(Mapped::DeviceLookup {
            op,
            device_id: device_id.clone(),
            toast,
        });
        out.push(Mapped::RefreshTray);
        out
    }

    fn map_pairing(&mut self, p: &PairingUiEvent) -> Vec<Mapped> {
        match p {
            // `pairing_start` already returned the QR to the caller.
            PairingUiEvent::Started { .. } => Vec::new(),
            PairingUiEvent::ConfirmRequested {
                pairing_id,
                sas,
                device_name,
                device_model,
                timeout_ms,
            } => vec![
                Mapped::Emit(Envelope::new(
                    "pairing",
                    json!({
                        "op": "pending_sas",
                        "pairing_id": pairing_id,
                        "sas": sas,
                        // the daemon event carries no platform; the UI shows name and model
                        "device": {
                            "name": device_name,
                            "platform": "",
                            "model": device_model,
                        },
                        "confirm_timeout_ms": timeout_ms,
                    }),
                )),
                // The SAS modal only means something in a visible window.
                Mapped::ShowWindow,
            ],
            PairingUiEvent::Ended {
                pairing_id,
                outcome,
            } => {
                if outcome == "paired" {
                    // `completed` needs the device id: it follows with `Device::Paired`.
                    self.pairing_waiting_for_device = Some(pairing_id.clone());
                    return Vec::new();
                }
                let reason = match outcome.as_str() {
                    "expired" | "cancelled" | "rejected" | "failed" | "timeout"
                    | "link_disabled" => outcome.as_str(),
                    _ => "failed",
                };
                vec![Mapped::Emit(Envelope::new(
                    "pairing",
                    json!({"op": "ended", "pairing_id": pairing_id, "reason": reason}),
                ))]
            }
        }
    }

    fn map_link(&mut self, l: &LinkUiEvent) -> Vec<Mapped> {
        match l {
            LinkUiEvent::Enabled { enabled } => vec![
                Mapped::Emit(Envelope::new(
                    "link",
                    json!({
                        "enabled": enabled,
                        "remote_approval_paused": self.paused.load(Ordering::Relaxed),
                    }),
                )),
                Mapped::RefreshTray,
            ],
            LinkUiEvent::PreAuthAttempt { ip_masked, at } => vec![Mapped::PreAuth {
                at: at.clone(),
                ip_masked: ip_masked.clone(),
            }],
            LinkUiEvent::Listening { .. } | LinkUiEvent::HostsChanged { .. } => {
                vec![Mapped::RefreshTray]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentnest_core::state::timers::ManualClock;
    use agentnest_protocol::{
        AdapterMode, AdapterStatus, AdapterStatusKind, AgentKind, ApprovalRequest, Delivery,
        ObservedResult,
    };

    fn mapper() -> (EventMapper, Arc<AtomicBool>) {
        let paused = Arc::new(AtomicBool::new(false));
        (
            EventMapper::new(Arc::new(ManualClock::new(1_792_055_553_120)), paused.clone()),
            paused,
        )
    }

    fn card(request_id: &str, title: &str) -> ApprovalRequest {
        serde_json::from_value(json!({
            "request_id": request_id,
            "nonce_b64": "TOP-SECRET-NONCE",
            "session_key": "claude_code:s1",
            "agent_kind": "claude_code",
            "agent_label": "Claude Code",
            "project": {"project_key": "p", "name": "proj"},
            "origin": "claude_code.hook.http",
            "created_at": "2026-10-15T09:00:00.000Z",
            "expires_at": "2026-10-15T09:02:00.000Z",
            "ttl_seconds": 120,
            "tool_name": "Bash",
            "title": title,
            "details": {"kind": "command", "command": "rm -rf /secret", "truncated": false},
            "tool_input_sha256": "a".repeat(64),
            "risk": {"level": "low", "reasons": [], "reasons_ko": [], "extra_confirmation": "none"},
            "allowed_decisions": ["allow", "deny"],
            "auth_required_for": [],
            "local_prompt": "unknown"
        }))
        .unwrap()
    }

    fn envelopes(m: &[Mapped]) -> Vec<&Envelope> {
        m.iter()
            .filter_map(|x| match x {
                Mapped::Emit(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn an_opened_approval_loses_its_nonce_and_gets_an_empty_delivery() {
        let (mut m, _) = mapper();
        let out = m.map(&DaemonEvent::Approval(ApprovalUiEvent::Opened {
            request: Box::new(card("ar_1", "명령 실행")),
            channel: ApprovalChannel::Remote,
        }));
        let env = envelopes(&out)[0];
        assert_eq!(env.kind, "approval");
        assert_eq!(env.payload["op"], "requested");
        let text = env.payload.to_string();
        assert!(!text.contains("TOP-SECRET-NONCE"));
        assert!(!text.contains("nonce_b64"));
        assert_eq!(
            env.payload["approval"]["delivery"],
            json!({"sent_to": [], "acked": false, "seen": false})
        );
        assert_eq!(env.payload["approval"]["request_id"], "ar_1");
        // the toast carries the title only, never the command
        let toast = out
            .iter()
            .find_map(|x| match x {
                Mapped::Notify(n) => Some(n),
                _ => None,
            })
            .unwrap();
        assert_eq!(toast.title, "승인 요청이 도착했어요");
        assert_eq!(toast.body, "명령 실행");
        assert!(!format!("{toast:?}").contains("secret"));
    }

    #[test]
    fn a_request_that_never_left_the_pc_says_so() {
        let (mut m, _) = mapper();
        for ch in [ApprovalChannel::LocalOnly, ApprovalChannel::NoDevice] {
            let out = m.map(&DaemonEvent::Approval(ApprovalUiEvent::Opened {
                request: Box::new(card("ar_2", "파일 쓰기")),
                channel: ch,
            }));
            assert!(out.iter().any(|x| matches!(x, Mapped::Notify(n) if n.title == "PC에서 처리해야 하는 요청")));
        }
        // the immediate hand-off that follows must not toast a second time
        let out = m.map(&DaemonEvent::Approval(ApprovalUiEvent::Resolved {
            request_id: "ar_2".into(),
            session_key: "claude_code:s1".into(),
            outcome: ApprovalOutcome::HandedOffLocal,
            resolved_by: ResolvedBy::System,
            delivery: Delivery::NotDelivered,
            observed_result: ObservedResult::Undetermined,
            message_ko: "PC에서 처리해 주세요".into(),
        }));
        assert!(!out.iter().any(|x| matches!(x, Mapped::Notify(_))));
    }

    #[test]
    fn a_timeout_hand_off_toasts_once_and_a_desktop_decision_does_not() {
        let (mut m, _) = mapper();
        let resolved = |id: &str, outcome: ApprovalOutcome, by: ResolvedBy| {
            DaemonEvent::Approval(ApprovalUiEvent::Resolved {
                request_id: id.into(),
                session_key: "claude_code:s1".into(),
                outcome,
                resolved_by: by,
                delivery: Delivery::Delivered,
                observed_result: ObservedResult::Undetermined,
                message_ko: "x".into(),
            })
        };
        let out = m.map(&resolved("ar_3", ApprovalOutcome::Expired, ResolvedBy::Timeout));
        assert!(out.iter().any(|x| matches!(x, Mapped::Notify(_))));
        let again = m.map(&resolved("ar_3", ApprovalOutcome::Expired, ResolvedBy::Timeout));
        assert!(!again.iter().any(|x| matches!(x, Mapped::Notify(_))));
        let user = m.map(&resolved("ar_4", ApprovalOutcome::Allowed, ResolvedBy::Desktop));
        assert!(!user.iter().any(|x| matches!(x, Mapped::Notify(_))));
        let env = envelopes(&user)[0];
        assert_eq!(env.payload["op"], "resolved");
        assert_eq!(env.payload["resolved"]["outcome"], "allowed");
        assert_eq!(env.payload["resolved"]["resolved_by"], "desktop");
        assert_eq!(env.payload["resolved"]["resolved_at"], "2026-10-15T09:12:33.120Z");
        assert!(env.payload["resolved"]["resolved_device_id"].is_null());
    }

    #[test]
    fn delivery_events_keep_their_fields() {
        let (mut m, _) = mapper();
        let out = m.map(&DaemonEvent::Approval(ApprovalUiEvent::Delivery {
            request_id: "ar_1".into(),
            sent_to: vec!["dev_1".into()],
            acked: true,
            seen: false,
        }));
        assert_eq!(
            envelopes(&out)[0].payload,
            json!({"op": "delivery", "request_id": "ar_1", "delivery": {"sent_to": ["dev_1"], "acked": true, "seen": false}})
        );
        assert!(m
            .map(&DaemonEvent::Approval(ApprovalUiEvent::DeliveryFailed {
                request_id: "ar_1".into()
            }))
            .is_empty());
        assert!(m
            .map(&DaemonEvent::Approval(ApprovalUiEvent::DecisionRejected {
                request_id: "ar_1".into(),
                reason: "EXPIRED".into()
            }))
            .is_empty());
    }

    #[test]
    fn the_sas_event_shows_the_window_and_carries_the_documented_fields() {
        let (mut m, _) = mapper();
        let out = m.map(&DaemonEvent::Pairing(PairingUiEvent::ConfirmRequested {
            pairing_id: "p_1".into(),
            sas: "482915".into(),
            device_name: "Pixel 9".into(),
            device_model: Some("Pixel 9".into()),
            timeout_ms: 60_000,
        }));
        assert!(out.contains(&Mapped::ShowWindow));
        let env = envelopes(&out)[0];
        assert_eq!(env.kind, "pairing");
        assert_eq!(
            env.payload,
            json!({
                "op": "pending_sas", "pairing_id": "p_1", "sas": "482915",
                "device": {"name": "Pixel 9", "platform": "", "model": "Pixel 9"},
                "confirm_timeout_ms": 60000
            })
        );
    }

    #[test]
    fn pairing_completion_waits_for_the_device_id() {
        let (mut m, _) = mapper();
        let ended = m.map(&DaemonEvent::Pairing(PairingUiEvent::Ended {
            pairing_id: "p_1".into(),
            outcome: "paired".into(),
        }));
        assert!(ended.is_empty(), "no `ended` for a successful pairing");
        let paired = m.map(&DaemonEvent::Device(DeviceUiEvent::Paired {
            device_id: "dev_9".into(),
            name: "Pixel".into(),
        }));
        let env = envelopes(&paired)[0];
        assert_eq!(
            env.payload,
            json!({"op": "completed", "pairing_id": "p_1", "device_id": "dev_9"})
        );
        assert!(paired.iter().any(|x| matches!(
            x,
            Mapped::DeviceLookup { op: "paired", device_id, toast: Some(_) } if device_id == "dev_9"
        )));
        // a later device event without a waiting pairing emits no `completed`
        let online = m.map(&DaemonEvent::Device(DeviceUiEvent::Online {
            device_id: "dev_9".into(),
        }));
        assert!(envelopes(&online).is_empty());
    }

    #[test]
    fn failed_pairings_map_to_documented_reasons() {
        let (mut m, _) = mapper();
        for (outcome, reason) in [
            ("expired", "expired"),
            ("cancelled", "cancelled"),
            ("rejected", "rejected"),
            ("failed", "failed"),
            ("something-new", "failed"),
        ] {
            let out = m.map(&DaemonEvent::Pairing(PairingUiEvent::Ended {
                pairing_id: "p_2".into(),
                outcome: outcome.into(),
            }));
            assert_eq!(
                envelopes(&out)[0].payload,
                json!({"op": "ended", "pairing_id": "p_2", "reason": reason})
            );
        }
        assert!(m
            .map(&DaemonEvent::Pairing(PairingUiEvent::Started {
                pairing_id: "p_3".into(),
                expires_at: "x".into()
            }))
            .is_empty());
    }

    #[test]
    fn device_events_request_a_lookup_with_a_toast() {
        let (mut m, _) = mapper();
        let table = [
            (DeviceUiEvent::Revoked { device_id: "d".into() }, "revoked"),
            (DeviceUiEvent::Online { device_id: "d".into() }, "online"),
            (DeviceUiEvent::Offline { device_id: "d".into() }, "offline"),
        ];
        for (ev, op) in table {
            let out = m.map(&DaemonEvent::Device(ev));
            assert!(
                out.iter().any(|x| matches!(x, Mapped::DeviceLookup { op: o, toast: Some(_), .. } if *o == op)),
                "{op}"
            );
        }
    }

    #[test]
    fn the_link_event_reports_the_shared_pause_flag() {
        let (mut m, paused) = mapper();
        let out = m.map(&DaemonEvent::Link(LinkUiEvent::Enabled { enabled: false }));
        assert_eq!(
            envelopes(&out)[0].payload,
            json!({"enabled": false, "remote_approval_paused": false})
        );
        paused.store(true, Ordering::Relaxed);
        let out = m.map(&DaemonEvent::Link(LinkUiEvent::Enabled { enabled: true }));
        assert_eq!(
            envelopes(&out)[0].payload,
            json!({"enabled": true, "remote_approval_paused": true})
        );
        assert_eq!(envelopes(&out)[0].kind, "link");
    }

    #[test]
    fn pre_auth_attempts_and_errors_are_not_forwarded() {
        let (mut m, _) = mapper();
        let out = m.map(&DaemonEvent::Link(LinkUiEvent::PreAuthAttempt {
            ip_masked: "192.168.0.x".into(),
            at: "2026-10-15T09:00:00.000Z".into(),
        }));
        assert_eq!(
            out,
            vec![Mapped::PreAuth {
                at: "2026-10-15T09:00:00.000Z".into(),
                ip_masked: "192.168.0.x".into()
            }]
        );
        let out = m.map(&DaemonEvent::Error {
            message: "token=abc".into(),
        });
        assert!(envelopes(&out).is_empty());
        assert!(out.contains(&Mapped::DaemonError));
        assert!(!format!("{out:?}").contains("token=abc"));
    }

    #[test]
    fn adapter_status_is_forwarded_as_is() {
        let (mut m, _) = mapper();
        let st = AdapterStatus {
            agent_kind: AgentKind::ClaudeCode,
            status: AdapterStatusKind::Connected,
            mode: AdapterMode::HooksHttp,
            detail: None,
            updated_at: "2026-10-15T09:00:00.000Z".into(),
        };
        let out = m.map(&DaemonEvent::Adapter(st));
        let env = envelopes(&out)[0];
        assert_eq!(env.kind, "adapter");
        assert_eq!(env.payload["agent_kind"], "claude_code");
        assert_eq!(env.payload["status"], "connected");
        assert_eq!(env.payload["mode"], "hooks_http");
    }
}
