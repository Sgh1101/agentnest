//! SessionReducer (transition table), timers and multi-session focus.
//!
//! * [`reducer`]: `reduce(prev, event, now)` and the per-session [`SessionReducer`] that also derives the phone-facing
//!   `SessionState` (docs/protocol.md 5.3, 5.4).
//! * [`timers`]: timer constants, the injectable [`timers::Clock`] and the RFC 3339 helpers.
//! * [`focus`]: focus session and mood across sessions (docs/protocol.md 5.5).

pub mod focus;
pub mod reducer;
pub mod timers;

pub use focus::{resolve_focus, Focus, FocusSession, LinkState, Mood, TypingVariant};
pub use reducer::{reduce, tick, ReducerState, SessionReducer, Update};
pub use timers::{Clock, ManualClock, SystemClock};
