//! Envelope parsing and serialisation (protocol.md 2, 3).

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::error::ProtocolError;
use crate::messages::*;
use crate::model::{AgentEvent, ApprovalRequest, SessionState};
use crate::PROTOCOL_VERSION;

/// Which side sends a message type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Phone to PC.
    ClientToServer,
    /// PC to phone.
    ServerToClient,
    /// Unknown message type.
    Unknown,
}

/// A typed wire message. Unknown `type`s are preserved as [`Message::Unknown`] and must be ignored silently.
#[derive(Clone, Debug, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Message {
    /// phone -> PC
    Pair(PairPayload),
    /// phone -> PC
    Hello(HelloPayload),
    /// phone -> PC
    Ack(AckPayload),
    /// phone -> PC
    Ping(PingPayload),
    /// phone -> PC
    SnapshotRequest(SnapshotRequestPayload),
    /// phone -> PC
    EventsRequest(EventsRequestPayload),
    /// phone -> PC
    Decision(DecisionPayload),
    /// phone -> PC
    ApprovalSeen(ApprovalSeenPayload),
    /// phone -> PC
    Unpair(UnpairPayload),
    /// PC -> phone
    Challenge(ChallengePayload),
    /// PC -> phone
    PairPending(PairPendingPayload),
    /// PC -> phone
    PairResult(PairResultPayload),
    /// PC -> phone
    Welcome(Box<WelcomePayload>),
    /// PC -> phone (replayable)
    Snapshot(Box<SnapshotPayload>),
    /// PC -> phone (replayable)
    Event(Box<AgentEvent>),
    /// PC -> phone (replayable)
    SessionState(Box<SessionState>),
    /// PC -> phone (replayable)
    ApprovalRequest(Box<ApprovalRequest>),
    /// PC -> phone (replayable)
    ApprovalResolved(ApprovalResolvedPayload),
    /// PC -> phone
    DecisionResult(DecisionResultPayload),
    /// PC -> phone
    EventsPage(Box<EventsPagePayload>),
    /// PC -> phone
    HostsUpdate(HostsUpdatePayload),
    /// PC -> phone (replayable)
    AdapterStatus(AdapterStatus),
    /// PC -> phone
    Pong(PongPayload),
    /// PC -> phone
    Error(ErrorPayload),
    /// PC -> phone
    Bye(ByePayload),
    /// A type this version does not know; ignore it (forward compatibility).
    Unknown {
        /// The `type` string.
        type_name: String,
        /// The untouched payload.
        payload: Value,
    },
}

impl Message {
    /// The wire `type` string.
    pub fn type_name(&self) -> &str {
        match self {
            Message::Pair(_) => "pair",
            Message::Hello(_) => "hello",
            Message::Ack(_) => "ack",
            Message::Ping(_) => "ping",
            Message::SnapshotRequest(_) => "snapshot_request",
            Message::EventsRequest(_) => "events_request",
            Message::Decision(_) => "decision",
            Message::ApprovalSeen(_) => "approval_seen",
            Message::Unpair(_) => "unpair",
            Message::Challenge(_) => "challenge",
            Message::PairPending(_) => "pair_pending",
            Message::PairResult(_) => "pair_result",
            Message::Welcome(_) => "welcome",
            Message::Snapshot(_) => "snapshot",
            Message::Event(_) => "event",
            Message::SessionState(_) => "session_state",
            Message::ApprovalRequest(_) => "approval_request",
            Message::ApprovalResolved(_) => "approval_resolved",
            Message::DecisionResult(_) => "decision_result",
            Message::EventsPage(_) => "events_page",
            Message::HostsUpdate(_) => "hosts_update",
            Message::AdapterStatus(_) => "adapter_status",
            Message::Pong(_) => "pong",
            Message::Error(_) => "error",
            Message::Bye(_) => "bye",
            Message::Unknown { type_name, .. } => type_name.as_str(),
        }
    }

    /// Sender of this message type.
    pub fn direction(&self) -> Direction {
        direction_of(self.type_name())
    }

    /// `true` for the types that carry a PC-global `seq` and are stored in the replay stream.
    pub fn is_replayable(&self) -> bool {
        is_replayable_type(self.type_name())
    }
}

/// Sender of a message `type` string.
pub fn direction_of(type_name: &str) -> Direction {
    match type_name {
        "pair" | "hello" | "ack" | "ping" | "snapshot_request" | "events_request" | "decision"
        | "approval_seen" | "unpair" => Direction::ClientToServer,
        "challenge" | "pair_pending" | "pair_result" | "welcome" | "snapshot" | "event"
        | "session_state" | "approval_request" | "approval_resolved" | "decision_result"
        | "events_page" | "hosts_update" | "adapter_status" | "pong" | "error" | "bye" => {
            Direction::ServerToClient
        }
        _ => Direction::Unknown,
    }
}

/// `true` for the message types that must carry `seq` (protocol.md 2).
pub fn is_replayable_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "snapshot"
            | "event"
            | "session_state"
            | "approval_request"
            | "approval_resolved"
            | "adapter_status"
    )
}

/// One envelope with its typed message.
#[derive(Clone, Debug, PartialEq)]
pub struct Frame {
    /// Protocol major version (always [`PROTOCOL_VERSION`] for frames built by this crate).
    pub v: u32,
    /// Sender-issued UUIDv7.
    pub id: String,
    /// Send time (RFC 3339 UTC).
    pub ts: String,
    /// PC-global sequence number for replayable messages.
    pub seq: Option<i64>,
    /// Typed payload.
    pub message: Message,
}

fn bad(msg: impl Into<String>) -> ProtocolError {
    ProtocolError::BadMessage(msg.into())
}

/// Lowercase UUID in 8-4-4-4-12 form with version nibble 7 and RFC 4122 variant.
pub fn is_uuid7(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if *c != b'-' {
                    return false;
                }
            }
            _ => {
                if !(c.is_ascii_digit() || (b'a'..=b'f').contains(c)) {
                    return false;
                }
            }
        }
    }
    b[14] == b'7' && matches!(b[19], b'8' | b'9' | b'a' | b'b')
}

fn typed<T: DeserializeOwned>(type_name: &str, payload: Value) -> Result<T, ProtocolError> {
    serde_json::from_value(payload).map_err(|e| bad(format!("{type_name} payload: {e}")))
}

fn decode_message(type_name: &str, payload: Value) -> Result<Message, ProtocolError> {
    Ok(match type_name {
        "pair" => Message::Pair(typed(type_name, payload)?),
        "hello" => Message::Hello(typed(type_name, payload)?),
        "ack" => Message::Ack(typed(type_name, payload)?),
        "ping" => Message::Ping(typed(type_name, payload)?),
        "snapshot_request" => Message::SnapshotRequest(typed(type_name, payload)?),
        "events_request" => Message::EventsRequest(typed(type_name, payload)?),
        "decision" => Message::Decision(typed(type_name, payload)?),
        "approval_seen" => Message::ApprovalSeen(typed(type_name, payload)?),
        "unpair" => Message::Unpair(typed(type_name, payload)?),
        "challenge" => Message::Challenge(typed(type_name, payload)?),
        "pair_pending" => Message::PairPending(typed(type_name, payload)?),
        "pair_result" => Message::PairResult(typed(type_name, payload)?),
        "welcome" => Message::Welcome(Box::new(typed(type_name, payload)?)),
        "snapshot" => Message::Snapshot(Box::new(typed(type_name, payload)?)),
        "event" => Message::Event(Box::new(typed(type_name, payload)?)),
        "session_state" => Message::SessionState(Box::new(typed(type_name, payload)?)),
        "approval_request" => Message::ApprovalRequest(Box::new(typed(type_name, payload)?)),
        "approval_resolved" => Message::ApprovalResolved(typed(type_name, payload)?),
        "decision_result" => Message::DecisionResult(typed(type_name, payload)?),
        "events_page" => Message::EventsPage(Box::new(typed(type_name, payload)?)),
        "hosts_update" => Message::HostsUpdate(typed(type_name, payload)?),
        "adapter_status" => Message::AdapterStatus(typed(type_name, payload)?),
        "pong" => Message::Pong(typed(type_name, payload)?),
        "error" => Message::Error(typed(type_name, payload)?),
        "bye" => Message::Bye(typed(type_name, payload)?),
        other => Message::Unknown {
            type_name: other.to_owned(),
            payload,
        },
    })
}

fn to_value<T: Serialize>(payload: &T) -> Result<Value, ProtocolError> {
    Ok(serde_json::to_value(payload)?)
}

fn encode_payload(message: &Message) -> Result<Value, ProtocolError> {
    match message {
        Message::Pair(p) => to_value(p),
        Message::Hello(p) => to_value(p),
        Message::Ack(p) => to_value(p),
        Message::Ping(p) => to_value(p),
        Message::SnapshotRequest(p) => to_value(p),
        Message::EventsRequest(p) => to_value(p),
        Message::Decision(p) => to_value(p),
        Message::ApprovalSeen(p) => to_value(p),
        Message::Unpair(p) => to_value(p),
        Message::Challenge(p) => to_value(p),
        Message::PairPending(p) => to_value(p),
        Message::PairResult(p) => to_value(p),
        Message::Welcome(p) => to_value(p.as_ref()),
        Message::Snapshot(p) => to_value(p.as_ref()),
        Message::Event(p) => to_value(p.as_ref()),
        Message::SessionState(p) => to_value(p.as_ref()),
        Message::ApprovalRequest(p) => to_value(p.as_ref()),
        Message::ApprovalResolved(p) => to_value(p),
        Message::DecisionResult(p) => to_value(p),
        Message::EventsPage(p) => to_value(p.as_ref()),
        Message::HostsUpdate(p) => to_value(p),
        Message::AdapterStatus(p) => to_value(p),
        Message::Pong(p) => to_value(p),
        Message::Error(p) => to_value(p),
        Message::Bye(p) => to_value(p),
        Message::Unknown { payload, .. } => Ok(payload.clone()),
    }
}

impl Frame {
    /// Builds a frame with protocol version 1.
    pub fn new(
        id: impl Into<String>,
        ts: impl Into<String>,
        seq: Option<i64>,
        message: Message,
    ) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: id.into(),
            ts: ts.into(),
            seq,
            message,
        }
    }

    /// Parses one text frame.
    ///
    /// Checks, in order: JSON object, `v == 1` ([`ProtocolError::VersionMismatch`]), `type` string, `id` UUIDv7,
    /// `ts` string, `seq` (non-negative integer; required for replayable types), `payload` object, then the typed
    /// payload. Unknown `type`s yield [`Message::Unknown`]. Unknown payload fields are ignored.
    /// This does not enforce the size limits or the string length limits of the JSON Schema; the transport
    /// enforces frame size and the schema tests pin the remaining limits.
    pub fn parse(text: &str) -> Result<Frame, ProtocolError> {
        let value: Value = serde_json::from_str(text)?;
        let Value::Object(mut obj) = value else {
            return Err(bad("frame is not a JSON object"));
        };
        let v = match obj.get("v") {
            None => return Err(bad("missing v")),
            Some(v) => v.as_i64().ok_or_else(|| bad("v is not an integer"))?,
        };
        if v != i64::from(PROTOCOL_VERSION) {
            return Err(ProtocolError::VersionMismatch(v));
        }
        let type_name = match obj.remove("type") {
            Some(Value::String(s)) if !s.is_empty() => s,
            _ => return Err(bad("missing or invalid type")),
        };
        let id = match obj.remove("id") {
            Some(Value::String(s)) if is_uuid7(&s) => s,
            _ => return Err(bad("missing or invalid id")),
        };
        let ts = match obj.remove("ts") {
            Some(Value::String(s)) if !s.is_empty() => s,
            _ => return Err(bad("missing or invalid ts")),
        };
        let seq = match obj.remove("seq") {
            None | Some(Value::Null) => None,
            Some(v) => match v.as_i64() {
                Some(n) if n >= 0 => Some(n),
                _ => return Err(bad("seq must be a non-negative integer")),
            },
        };
        if seq.is_none() && is_replayable_type(&type_name) {
            return Err(bad(format!("{type_name} requires seq")));
        }
        let payload = match obj.remove("payload") {
            Some(p @ Value::Object(_)) => p,
            _ => return Err(bad("payload must be an object")),
        };
        let message = decode_message(&type_name, payload)?;
        Ok(Frame {
            v: PROTOCOL_VERSION,
            id,
            ts,
            seq,
            message,
        })
    }

    /// The envelope as a JSON value.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        let mut obj = Map::new();
        obj.insert("v".into(), Value::from(self.v));
        obj.insert("type".into(), Value::from(self.message.type_name()));
        obj.insert("id".into(), Value::from(self.id.clone()));
        obj.insert("ts".into(), Value::from(self.ts.clone()));
        if let Some(seq) = self.seq {
            obj.insert("seq".into(), Value::from(seq));
        }
        obj.insert("payload".into(), encode_payload(&self.message)?);
        Ok(Value::Object(obj))
    }

    /// Serialises to the compact JSON text frame.
    pub fn to_json(&self) -> Result<String, ProtocolError> {
        Ok(serde_json::to_string(&self.to_value()?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid7_shape() {
        assert!(is_uuid7("01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e5f"));
        assert!(!is_uuid7("01929f1a-6c2e-4b3c-9e4d-2a7b1c3d4e5f"));
        assert!(!is_uuid7("01929F1A-6c2e-7b3c-9e4d-2a7b1c3d4e5f"));
        assert!(!is_uuid7("not-a-uuid"));
    }

    #[test]
    fn rejects_wrong_version_and_negative_seq() {
        let base = |extra: &str| {
            format!(
                r#"{{{extra}"type":"ping","id":"01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e5f","ts":"2026-10-15T09:12:33.120Z","payload":{{"sent_at":"2026-10-15T09:12:33.120Z"}}}}"#
            )
        };
        assert!(matches!(
            Frame::parse(&base(r#""v":2,"#)),
            Err(ProtocolError::VersionMismatch(2))
        ));
        assert!(matches!(
            Frame::parse(&base("")),
            Err(ProtocolError::BadMessage(_))
        ));
        assert!(matches!(
            Frame::parse(&base(r#""v":1,"seq":-1,"#)),
            Err(ProtocolError::BadMessage(_))
        ));
        assert!(Frame::parse(&base(r#""v":1,"#)).is_ok());
    }

    #[test]
    fn unknown_type_is_preserved() {
        let text = r#"{"v":1,"type":"future","id":"01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e5f","ts":"2026-10-15T09:12:33.120Z","payload":{"x":1}}"#;
        let frame = Frame::parse(text).unwrap();
        assert!(matches!(frame.message, Message::Unknown { .. }));
        assert_eq!(frame.message.direction(), Direction::Unknown);
        let again: Value = serde_json::from_str(&frame.to_json().unwrap()).unwrap();
        assert_eq!(again, serde_json::from_str::<Value>(text).unwrap());
    }
}
