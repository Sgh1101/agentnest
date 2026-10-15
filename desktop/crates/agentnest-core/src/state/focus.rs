//! Multi-session focus and mood, golden file `protocol/fixtures/mood_priority.json` (shared with the Kotlin
//! `MoodResolver`; docs/protocol.md 5.5, docs/character.md 2.1).
//!
//! The focus session is the live (not ended) session with the lowest [`AgentState::focus_rank`]; ties go to the newest
//! `last_event_at`. The mood follows the focus state. A link that is not `Connected` overrides everything. The
//! hysteresis of the phone (1.5 s minimum hold, upgrade immediately) needs a clock and is *not* part of this function;
//! the desktop tray uses the same resolution for its four-colour icon (docs/character.md 4).

use agentnest_protocol::AgentState;

/// How long `celebrate` is shown after a session completed (milliseconds).
pub const CELEBRATE_MS: i64 = 4_000;

/// State of the phone-PC link as far as the mood is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    /// Connected and authenticated.
    Connected,
    /// Offline (no network, link disabled).
    Offline,
    /// Reconnecting.
    Reconnecting,
    /// The PC cannot be reached.
    PcUnreachable,
    /// Suspended by the system.
    Suspended,
}

impl LinkState {
    /// Parses the fixture / wire spelling. Unknown values are treated as `Reconnecting` (worried, never "all good").
    pub fn from_wire(value: &str) -> Self {
        match value {
            "connected" => LinkState::Connected,
            "offline" => LinkState::Offline,
            "reconnecting" => LinkState::Reconnecting,
            "pc_unreachable" => LinkState::PcUnreachable,
            "suspended" => LinkState::Suspended,
            _ => LinkState::Reconnecting,
        }
    }
}

/// The nine moods of the character (docs/character.md 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mood {
    /// Idle.
    BlinkSlow,
    /// Typing (see [`TypingVariant`]).
    Typing,
    /// Reviewing.
    Magnifier,
    /// Testing / building.
    Tools,
    /// Waiting for approval or input (see the badge).
    RaiseHand,
    /// Error.
    Flustered,
    /// Just completed.
    Celebrate,
    /// Link offline.
    Sleepy,
    /// Link trouble or a dead session.
    Worried,
}

impl Mood {
    /// The wire / fixture spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Mood::BlinkSlow => "blink_slow",
            Mood::Typing => "typing",
            Mood::Magnifier => "magnifier",
            Mood::Tools => "tools",
            Mood::RaiseHand => "raise_hand",
            Mood::Flustered => "flustered",
            Mood::Celebrate => "celebrate",
            Mood::Sleepy => "sleepy",
            Mood::Worried => "worried",
        }
    }
}

/// Typing animation variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypingVariant {
    /// Writing code.
    Full,
    /// Generic work (hands only).
    Weak,
}

/// What focus resolution needs to know about a session.
#[derive(Clone, Debug)]
pub struct FocusSession {
    /// Session key.
    pub session_key: String,
    /// Effective state (unknown values rank as `working`).
    pub state: AgentState,
    /// When the state was entered (Unix ms); only used for the 4 s `celebrate` window.
    pub state_since_ms: i64,
    /// Time of the last event (Unix ms); the tie-breaker.
    pub last_event_ms: i64,
    /// Ended sessions are ignored.
    pub ended: bool,
}

/// The result of focus resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Focus {
    /// The mood to show.
    pub mood: Mood,
    /// `!` (approvals) or `?` (input requests) on the raised hand.
    pub badge: Option<char>,
    /// Number of sessions behind the badge.
    pub badge_count: usize,
    /// Typing variant (only for `Mood::Typing`).
    pub variant: Option<TypingVariant>,
    /// The focus session; `None` without a live session or when the link overrides.
    pub focus_session_key: Option<String>,
    /// The raw state string of the focus session.
    pub focus_state: Option<String>,
}

/// Resolves mood, badge and focus session.
pub fn resolve_focus(sessions: &[FocusSession], link: LinkState, now_ms: i64) -> Focus {
    let override_mood = match link {
        LinkState::Connected => None,
        LinkState::Offline => Some(Mood::Sleepy),
        LinkState::Reconnecting | LinkState::PcUnreachable | LinkState::Suspended => {
            Some(Mood::Worried)
        }
    };
    if let Some(mood) = override_mood {
        return Focus {
            mood,
            badge: None,
            badge_count: 0,
            variant: None,
            focus_session_key: None,
            focus_state: None,
        };
    }
    let live: Vec<&FocusSession> = sessions.iter().filter(|s| !s.ended).collect();
    let Some(top) = live
        .iter()
        .min_by(|a, b| {
            a.state
                .focus_rank()
                .cmp(&b.state.focus_rank())
                .then(b.last_event_ms.cmp(&a.last_event_ms))
        })
        .copied()
    else {
        return Focus {
            mood: Mood::BlinkSlow,
            badge: None,
            badge_count: 0,
            variant: None,
            focus_session_key: None,
            focus_state: None,
        };
    };
    let count = |state: AgentState| live.iter().filter(|s| s.state == state).count();
    let effective = top.state.effective();
    let (mood, badge, badge_count, variant) = match effective {
        AgentState::AwaitingApproval => (
            Mood::RaiseHand,
            Some('!'),
            count(AgentState::AwaitingApproval),
            None,
        ),
        AgentState::AwaitingInput => (
            Mood::RaiseHand,
            Some('?'),
            count(AgentState::AwaitingInput),
            None,
        ),
        AgentState::Error => (Mood::Flustered, None, 0, None),
        AgentState::Testing => (Mood::Tools, None, 0, None),
        AgentState::WritingCode => (Mood::Typing, None, 0, Some(TypingVariant::Full)),
        AgentState::Reviewing => (Mood::Magnifier, None, 0, None),
        AgentState::Completed => {
            if now_ms - top.state_since_ms < CELEBRATE_MS {
                (Mood::Celebrate, None, 0, None)
            } else {
                (Mood::BlinkSlow, None, 0, None)
            }
        }
        AgentState::Idle => (Mood::BlinkSlow, None, 0, None),
        AgentState::Disconnected => (Mood::Worried, None, 0, None),
        // `working` and everything unknown
        _ => (Mood::Typing, None, 0, Some(TypingVariant::Weak)),
    };
    Focus {
        mood,
        badge,
        badge_count,
        variant,
        focus_session_key: Some(top.session_key.clone()),
        focus_state: Some(top.state.as_str().to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::timers::parse_ms;
    use serde_json::Value;

    #[test]
    fn mood_priority_golden() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../protocol/fixtures/mood_priority.json"
        );
        let f: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let cases = f["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 42);
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let now = parse_ms(c["now"].as_str().unwrap()).unwrap();
            let sessions: Vec<FocusSession> = c["sessions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| FocusSession {
                    session_key: s["session_key"].as_str().unwrap().to_owned(),
                    state: AgentState::from_wire(s["state"].as_str().unwrap()),
                    state_since_ms: parse_ms(s["state_since"].as_str().unwrap()).unwrap(),
                    last_event_ms: parse_ms(s["last_event_at"].as_str().unwrap()).unwrap(),
                    ended: s.get("ended").and_then(Value::as_bool).unwrap_or(false),
                })
                .collect();
            let got = resolve_focus(
                &sessions,
                LinkState::from_wire(c["link"].as_str().unwrap()),
                now,
            );
            let e = &c["expect"];
            assert_eq!(
                got.mood.as_str(),
                e["mood"].as_str().unwrap(),
                "{name}: mood"
            );
            let badge = got.badge.map(|b| b.to_string());
            assert_eq!(badge.as_deref(), e["badge"].as_str(), "{name}: badge");
            assert_eq!(
                got.badge_count as u64,
                e["badge_count"].as_u64().unwrap(),
                "{name}: badge_count"
            );
            if let Some(v) = e.get("variant").and_then(Value::as_str) {
                let got_v = match got.variant {
                    Some(TypingVariant::Full) => "full",
                    Some(TypingVariant::Weak) => "weak",
                    None => "none",
                };
                assert_eq!(got_v, v, "{name}: variant");
            }
            if e.get("focus_session_key").is_some() {
                assert_eq!(
                    got.focus_session_key.as_deref(),
                    e["focus_session_key"].as_str(),
                    "{name}: focus key"
                );
                assert_eq!(
                    got.focus_state.as_deref(),
                    e["focus_state"].as_str(),
                    "{name}: focus state"
                );
            }
        }
    }

    #[test]
    fn unknown_link_values_are_worried_not_fine() {
        assert_eq!(
            LinkState::from_wire("something_new"),
            LinkState::Reconnecting
        );
        let f = resolve_focus(&[], LinkState::from_wire("something_new"), 0);
        assert_eq!(f.mood, Mood::Worried);
    }
}
