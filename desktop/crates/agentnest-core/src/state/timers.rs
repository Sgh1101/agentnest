//! completed->idle, error latch expiry, stale and dead timers (docs/protocol.md 5.4), plus the injectable [`Clock`].
//!
//! The reducer never reads the system clock: every function takes `now_ms` (Unix milliseconds). The daemon owns a
//! [`Clock`] and asks [`SessionReducer::next_deadline`](super::reducer::SessionReducer::next_deadline) when to wake up,
//! so a test can drive all timers with a [`ManualClock`] without sleeping.

use std::sync::atomic::{AtomicI64, Ordering};

use chrono::{DateTime, SecondsFormat, TimeZone, Utc};

/// `completed` becomes `idle` after this long (protocol.md 5.4).
pub const COMPLETED_TO_IDLE_MS: i64 = 60_000;
/// A transient error (`tool_failed` / `command_failed`) lasts this long.
pub const ERROR_TRANSIENT_MS: i64 = 5_000;
/// A `test_failed` error lasts this long unless released earlier.
pub const ERROR_TEST_FAILED_MS: i64 = 30_000;
/// `stale = true` after this long without events while a turn is active.
pub const STALE_AFTER_MS: i64 = 15 * 60_000;
/// `disconnected` after this long without events while a turn is active.
pub const DEAD_AFTER_ACTIVE_MS: i64 = 45 * 60_000;
/// `disconnected` after this long without events while no turn is active.
pub const DEAD_AFTER_IDLE_MS: i64 = 30 * 60_000;
/// An ended session leaves the active list after this long.
pub const ENDED_REMOVE_AFTER_MS: i64 = 10 * 60_000;

/// A source of "now" in Unix milliseconds.
pub trait Clock: Send + Sync {
    /// Current time in milliseconds since the Unix epoch.
    fn now_ms(&self) -> i64;
}

/// The wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        Utc::now().timestamp_millis()
    }
}

/// A clock that only moves when told to (tests).
#[derive(Debug, Default)]
pub struct ManualClock(AtomicI64);

impl ManualClock {
    /// A clock showing `ms`.
    pub fn new(ms: i64) -> Self {
        Self(AtomicI64::new(ms))
    }

    /// Sets the time.
    pub fn set(&self, ms: i64) {
        self.0.store(ms, Ordering::SeqCst);
    }

    /// Moves the time forward.
    pub fn advance(&self, ms: i64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// `2026-10-15T09:12:33.120Z`: RFC 3339, millisecond precision, UTC (protocol.md 1). Fixed width, so the text sorts
/// like the time (the store relies on that).
pub fn format_ms(ms: i64) -> String {
    match Utc.timestamp_millis_opt(ms).single() {
        Some(dt) => dt.to_rfc3339_opts(SecondsFormat::Millis, true),
        None => "1970-01-01T00:00:00.000Z".to_owned(),
    }
}

/// Formats a `DateTime<Utc>` like [`format_ms`].
pub fn format_datetime(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Parses an RFC 3339 timestamp into Unix milliseconds.
pub fn parse_ms(text: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|d| d.timestamp_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_moves_only_when_told() {
        let c = ManualClock::new(1_000);
        assert_eq!(c.now_ms(), 1_000);
        c.advance(500);
        assert_eq!(c.now_ms(), 1_500);
        c.set(7);
        assert_eq!(c.now_ms(), 7);
    }

    #[test]
    fn timestamps_round_trip_and_sort() {
        let a = format_ms(1_760_000_000_123);
        assert_eq!(a, "2025-10-09T08:53:20.123Z");
        assert_eq!(parse_ms(&a), Some(1_760_000_000_123));
        assert!(format_ms(1_000) < format_ms(2_000));
        assert!(
            format_ms(9_999) < format_ms(10_000),
            "fixed width: lexical order equals time order"
        );
        assert_eq!(parse_ms("garbage"), None);
        assert_eq!(format_ms(i64::MAX), "1970-01-01T00:00:00.000Z");
    }
}
