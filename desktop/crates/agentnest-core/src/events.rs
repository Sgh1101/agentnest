//! What the daemon tells its host (the Tauri shell) about: the [`DaemonEvent`] stream (docs/desktop.md 3,
//! `daemon-event{kind, payload}`).
//!
//! The variants map 1:1 to the `kind` values `event | session_state | approval | device | pairing | adapter | link`.
//! Payloads never contain secrets: no tokens, no pairing secrets, no nonces. A pairing SAS **is** included in
//! [`PairingUiEvent::ConfirmRequested`] because the PC user must compare it with the phone (it is useless without the
//! QR secret).

use agentnest_protocol::{
    AdapterStatus, AgentEvent, ApprovalOutcome, ApprovalRequest, Delivery, ObservedResult,
    ResolvedBy, SessionState,
};
use tokio::sync::broadcast;

/// How a new approval request is going to be answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalChannel {
    /// Sent to the paired phone(s) and waiting for a decision (the desktop can also decide or hand off).
    Remote,
    /// Never sent to a phone (critical + `local_only`, remote approval paused): already handed to the local prompt.
    LocalOnly,
    /// No authenticated phone is online: already handed to the local prompt.
    NoDevice,
}

/// Approval related events for the desktop UI and tray.
#[derive(Clone, Debug)]
pub enum ApprovalUiEvent {
    /// A request was opened. `request` is the card exactly as the phone receives it.
    Opened {
        /// The card.
        request: Box<ApprovalRequest>,
        /// Whether it is waiting for a decision.
        channel: ApprovalChannel,
    },
    /// A request ended (or its observed result changed).
    Resolved {
        /// Request id.
        request_id: String,
        /// Session key.
        session_key: String,
        /// Outcome.
        outcome: ApprovalOutcome,
        /// Who resolved it.
        resolved_by: ResolvedBy,
        /// Whether the reply reached the agent.
        delivery: Delivery,
        /// Later observation.
        observed_result: ObservedResult,
        /// Korean one-liner.
        message_ko: String,
    },
    /// Delivery progress of a card to the phones ("sent / received / opened").
    Delivery {
        /// Request id.
        request_id: String,
        /// Device ids the card was sent to.
        sent_to: Vec<String>,
        /// A phone acknowledged the card.
        acked: bool,
        /// A phone opened the card.
        seen: bool,
    },
    /// The card could not be delivered to any phone after the retries.
    DeliveryFailed {
        /// Request id.
        request_id: String,
    },
    /// A decision attempt was refused (`decision_result.reason` spelling).
    DecisionRejected {
        /// Request id.
        request_id: String,
        /// Reason code.
        reason: String,
    },
}

/// Device events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceUiEvent {
    /// A device finished pairing.
    Paired {
        /// Device id.
        device_id: String,
        /// Device name.
        name: String,
    },
    /// A device was revoked.
    Revoked {
        /// Device id.
        device_id: String,
    },
    /// A device authenticated and is online.
    Online {
        /// Device id.
        device_id: String,
    },
    /// A device disconnected.
    Offline {
        /// Device id.
        device_id: String,
    },
}

/// Pairing events (QR / SAS modal).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairingUiEvent {
    /// Pairing mode started; the QR is valid until `expires_at`.
    Started {
        /// Pairing id.
        pairing_id: String,
        /// Expiry (RFC 3339).
        expires_at: String,
    },
    /// A phone proved possession of the QR secret and waits for the PC user (show the SAS modal).
    ConfirmRequested {
        /// Pairing id.
        pairing_id: String,
        /// The 6-digit SAS.
        sas: String,
        /// Phone name.
        device_name: String,
        /// Phone model.
        device_model: Option<String>,
        /// Time the user has, in milliseconds.
        timeout_ms: u32,
    },
    /// Pairing mode ended.
    Ended {
        /// Pairing id.
        pairing_id: String,
        /// `paired`, `expired`, `rejected`, `failed` or `cancelled`.
        outcome: String,
    },
}

/// Link (WSS listener) events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkUiEvent {
    /// The listener is bound.
    Listening {
        /// Address.
        addr: String,
    },
    /// `link.enabled` changed.
    Enabled {
        /// New state.
        enabled: bool,
    },
    /// The advertised addresses changed (certificate re-issued with the same key, phones notified).
    HostsChanged {
        /// Addresses.
        addresses: Vec<String>,
    },
    /// An unauthenticated connection attempt (diagnostics view; address masked).
    PreAuthAttempt {
        /// Masked source address.
        ip_masked: String,
        /// When (RFC 3339).
        at: String,
    },
}

/// Everything the host may want to show.
#[derive(Clone, Debug)]
pub enum DaemonEvent {
    /// A normalised agent event.
    Event(Box<AgentEvent>),
    /// A session changed.
    SessionState(Box<SessionState>),
    /// Approval lifecycle.
    Approval(ApprovalUiEvent),
    /// Device lifecycle.
    Device(DeviceUiEvent),
    /// Pairing lifecycle.
    Pairing(PairingUiEvent),
    /// Adapter health.
    Adapter(AdapterStatus),
    /// Link state.
    Link(LinkUiEvent),
    /// The daemon hit an error that the user should see (never contains secrets).
    Error {
        /// English message for logs.
        message: String,
    },
}

impl DaemonEvent {
    /// The `kind` string of the Tauri `daemon-event` (docs/desktop.md 3).
    pub fn kind(&self) -> &'static str {
        match self {
            DaemonEvent::Event(_) => "event",
            DaemonEvent::SessionState(_) => "session_state",
            DaemonEvent::Approval(_) => "approval",
            DaemonEvent::Device(_) => "device",
            DaemonEvent::Pairing(_) => "pairing",
            DaemonEvent::Adapter(_) => "adapter",
            DaemonEvent::Link(_) => "link",
            DaemonEvent::Error { .. } => "link",
        }
    }
}

/// The sending side of the event stream. Sending never fails the caller (nobody listening is fine).
#[derive(Clone, Debug)]
pub struct EventBus {
    tx: broadcast::Sender<DaemonEvent>,
}

impl EventBus {
    /// A bus buffering `capacity` events per receiver.
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Publishes an event.
    pub fn emit(&self, event: DaemonEvent) {
        let _ = self.tx.send(event);
    }

    /// A new receiver.
    pub fn subscribe(&self) -> broadcast::Receiver<DaemonEvent> {
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_without_receivers_is_fine_and_receivers_get_events() {
        let bus = EventBus::new(8);
        bus.emit(DaemonEvent::Device(DeviceUiEvent::Online {
            device_id: "dev_1".into(),
        }));
        let mut rx = bus.subscribe();
        bus.emit(DaemonEvent::Pairing(PairingUiEvent::Ended {
            pairing_id: "p_1".into(),
            outcome: "paired".into(),
        }));
        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.kind(), "pairing");
    }
}
