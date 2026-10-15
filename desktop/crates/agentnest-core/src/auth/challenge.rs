//! Per-connection challenges and the pre-authentication admission rules (docs/security.md 5, 11).
//!
//! * [`Challenge`]: 16 CSPRNG bytes issued per connection; `pair`/`hello` must echo it. Comparison is constant time.
//! * [`AdmissionControl`]: the limits that apply before a phone is authenticated:
//!   * at most **16** concurrent connections in total (the 17th is closed with 1013 without any frame),
//!   * at most **4** concurrent not-yet-authenticated connections per IP,
//!   * **5 authentication failures per minute per IP** block that IP for **60 s** (the same number as the hello rule of
//!     security.md 5; both `hello` and `pair` failures count).
//!
//! The limiter knows nothing about sockets: the link layer calls [`AdmissionControl::admit`] when a connection arrives
//! and holds the returned [`Admission`] for the lifetime of the connection.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use agentnest_protocol::canonical::ct_eq;
use agentnest_protocol::limits::CHALLENGE_LEN;
use agentnest_protocol::qr::{b64_decode, b64_encode};
use ring::rand::{SecureRandom, SystemRandom};

use crate::ratelimit::SlidingWindow;
use crate::state::timers::Clock;

/// Concurrent connections allowed in total.
pub const MAX_CONNECTIONS: usize = 16;
/// Concurrent pre-authentication connections allowed per IP.
pub const MAX_PREAUTH_PER_IP: usize = 4;
/// Authentication failures per IP per window that trigger a block.
pub const FAILURE_LIMIT: usize = 5;
/// The failure counting window.
pub const FAILURE_WINDOW_MS: i64 = 60_000;
/// How long a blocked IP stays blocked.
pub const BLOCK_MS: i64 = 60_000;

/// A per-connection challenge.
#[derive(Clone)]
pub struct Challenge {
    raw: [u8; CHALLENGE_LEN],
}

impl std::fmt::Debug for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Challenge(<redacted>)")
    }
}

impl Challenge {
    /// 16 fresh random bytes. `None` only if the system RNG fails (the connection is then dropped).
    pub fn generate() -> Option<Self> {
        let mut raw = [0u8; CHALLENGE_LEN];
        SystemRandom::new().fill(&mut raw).ok()?;
        Some(Self { raw })
    }

    /// The raw bytes (used in the pairing proof and SAS).
    pub fn raw(&self) -> &[u8; CHALLENGE_LEN] {
        &self.raw
    }

    /// Standard base64 (the `challenge_b64` wire form).
    pub fn to_b64(&self) -> String {
        b64_encode(&self.raw)
    }

    /// `true` if `echo` (base64) decodes to exactly this challenge. Constant time over the bytes.
    pub fn matches_b64(&self, echo: &str) -> bool {
        match b64_decode(echo) {
            Ok(bytes) => ct_eq(&bytes, &self.raw),
            Err(_) => false,
        }
    }
}

/// Why a connection was refused before it started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// 16 connections are already open (close with 1013, send nothing).
    ConnectionCap,
    /// The source IP is blocked after repeated authentication failures (close with 4005, send nothing).
    IpBlocked,
    /// The source IP already has 4 unauthenticated connections (close with 1013, send nothing).
    TooManyPreAuth,
}

#[derive(Default)]
struct IpState {
    preauth: usize,
    failures: Option<SlidingWindow>,
    blocked_until: i64,
}

struct Inner {
    total: usize,
    ips: HashMap<IpAddr, IpState>,
}

/// Admission control shared by all connections.
#[derive(Clone)]
pub struct AdmissionControl {
    inner: Arc<Mutex<Inner>>,
    clock: Arc<dyn Clock>,
    max_total: usize,
}

impl std::fmt::Debug for AdmissionControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionControl").finish_non_exhaustive()
    }
}

/// A connection slot. Dropping it releases the slot (and the pre-auth slot if still held).
pub struct Admission {
    control: AdmissionControl,
    ip: IpAddr,
    preauth_held: bool,
}

impl std::fmt::Debug for Admission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admission").finish_non_exhaustive()
    }
}

impl Admission {
    /// The peer is authenticated (or its pairing finished): the pre-auth slot is released, the connection slot stays.
    pub fn authenticated(&mut self) {
        if self.preauth_held {
            self.preauth_held = false;
            let mut g = self.control.lock();
            if let Some(s) = g.ips.get_mut(&self.ip) {
                s.preauth = s.preauth.saturating_sub(1);
            }
        }
    }

    /// Records an authentication failure for the source IP. Returns `true` if it blocked the IP.
    pub fn record_failure(&self) -> bool {
        self.control.record_failure(self.ip)
    }

    /// The source IP.
    pub fn ip(&self) -> IpAddr {
        self.ip
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        let now = self.control.clock.now_ms();
        let mut g = self.control.lock();
        g.total = g.total.saturating_sub(1);
        if let Some(s) = g.ips.get_mut(&self.ip) {
            if self.preauth_held {
                s.preauth = s.preauth.saturating_sub(1);
            }
            // Forget an IP only when nothing about it is still relevant (no open pre-auth slot, no active block, no
            // failure inside the counting window).
            let idle = s.preauth == 0
                && s.blocked_until <= now
                && s.failures.as_mut().is_none_or(|w| w.count(now) == 0);
            if idle {
                g.ips.remove(&self.ip);
            }
        }
    }
}

impl AdmissionControl {
    /// Admission control with the documented limits.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self::with_max_total(clock, MAX_CONNECTIONS)
    }

    /// Admission control with a custom total limit (tests).
    pub fn with_max_total(clock: Arc<dyn Clock>, max_total: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                total: 0,
                ips: HashMap::new(),
            })),
            clock,
            max_total,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock only means another connection task panicked; the counters are still consistent enough to
        // keep serving (fail towards admitting nobody is not needed: the counts are plain integers).
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Tries to admit a new connection from `ip`.
    pub fn admit(&self, ip: IpAddr) -> Result<Admission, Rejection> {
        let now = self.clock.now_ms();
        let mut g = self.lock();
        if g.total >= self.max_total {
            return Err(Rejection::ConnectionCap);
        }
        let state = g.ips.entry(ip).or_default();
        if state.blocked_until > now {
            return Err(Rejection::IpBlocked);
        }
        if state.preauth >= MAX_PREAUTH_PER_IP {
            return Err(Rejection::TooManyPreAuth);
        }
        state.preauth += 1;
        state.blocked_until = 0.max(state.blocked_until);
        g.total += 1;
        drop(g);
        Ok(Admission {
            control: self.clone(),
            ip,
            preauth_held: true,
        })
    }

    /// Records an authentication failure for `ip`; returns `true` if the IP is now blocked.
    pub fn record_failure(&self, ip: IpAddr) -> bool {
        let now = self.clock.now_ms();
        let mut g = self.lock();
        let state = g.ips.entry(ip).or_default();
        let w = state
            .failures
            .get_or_insert_with(|| SlidingWindow::new(FAILURE_LIMIT, FAILURE_WINDOW_MS));
        let n = w.record(now);
        if n >= FAILURE_LIMIT {
            state.blocked_until = now + BLOCK_MS;
            true
        } else {
            false
        }
    }

    /// `true` if `ip` is currently blocked.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let now = self.clock.now_ms();
        self.lock()
            .ips
            .get(&ip)
            .is_some_and(|s| s.blocked_until > now)
    }

    /// Number of open connections.
    pub fn open_connections(&self) -> usize {
        self.lock().total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::timers::ManualClock;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn control() -> (AdmissionControl, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new(1_000_000));
        (AdmissionControl::new(clock.clone()), clock)
    }

    #[test]
    fn challenges_are_16_random_bytes_and_compare_exactly() {
        let a = Challenge::generate().unwrap();
        let b = Challenge::generate().unwrap();
        assert_ne!(a.raw(), b.raw());
        assert!(a.matches_b64(&a.to_b64()));
        assert!(
            !a.matches_b64(&b.to_b64()),
            "a challenge of another connection is refused"
        );
        assert!(!a.matches_b64(""));
        assert!(!a.matches_b64("%%%"));
        let mut twice = a.raw().to_vec();
        twice.extend_from_slice(a.raw());
        assert!(!a.matches_b64(&b64_encode(&twice)));
        assert!(!format!("{a:?}").contains(&a.to_b64()));
        assert_eq!(b64_decode(&a.to_b64()).unwrap().len(), 16);
    }

    #[test]
    fn the_17th_connection_is_refused() {
        let (c, _) = control();
        let mut held = Vec::new();
        for i in 0..MAX_CONNECTIONS {
            // different IPs so the per-IP pre-auth limit does not interfere
            held.push(c.admit(ip(&format!("192.168.0.{}", i + 1))).unwrap());
        }
        assert_eq!(c.open_connections(), 16);
        assert_eq!(
            c.admit(ip("192.168.1.1")).unwrap_err(),
            Rejection::ConnectionCap
        );
        held.pop();
        assert!(
            c.admit(ip("192.168.1.1")).is_ok(),
            "a freed slot can be reused"
        );
    }

    #[test]
    fn at_most_four_unauthenticated_connections_per_ip() {
        let (c, _) = control();
        let mut held: Vec<Admission> = (0..4)
            .map(|_| c.admit(ip("192.168.0.9")).unwrap())
            .collect();
        assert_eq!(
            c.admit(ip("192.168.0.9")).unwrap_err(),
            Rejection::TooManyPreAuth
        );
        assert!(
            c.admit(ip("192.168.0.10")).is_ok(),
            "other IPs are not affected"
        );
        held[0].authenticated();
        assert!(
            c.admit(ip("192.168.0.9")).is_ok(),
            "an authenticated connection frees a pre-auth slot"
        );
        // authenticated() twice does not double release
        held[0].authenticated();
        let _extra = c.admit(ip("192.168.0.9"));
        assert_eq!(
            c.admit(ip("192.168.0.9")).unwrap_err(),
            Rejection::TooManyPreAuth
        );
    }

    #[test]
    fn five_failures_in_a_minute_block_the_ip_for_a_minute() {
        let (c, clock) = control();
        let a = ip("192.168.0.9");
        for i in 0..4 {
            assert!(!c.record_failure(a), "failure {i}");
            clock.advance(1_000);
        }
        assert!(c.admit(a).is_ok(), "four failures do not block yet");
        assert!(c.record_failure(a), "the fifth blocks");
        assert!(c.is_blocked(a));
        assert_eq!(c.admit(a).unwrap_err(), Rejection::IpBlocked);
        assert!(
            c.admit(ip("192.168.0.10")).is_ok(),
            "another IP is unaffected"
        );
        clock.advance(59_000);
        assert_eq!(c.admit(a).unwrap_err(), Rejection::IpBlocked);
        clock.advance(2_000);
        assert!(!c.is_blocked(a));
        assert!(c.admit(a).is_ok(), "the block ends after 60 seconds");
    }

    #[test]
    fn failures_spread_over_more_than_a_minute_do_not_block() {
        let (c, clock) = control();
        let a = ip("10.0.0.5");
        for _ in 0..20 {
            assert!(!c.record_failure(a));
            clock.advance(20_000);
        }
    }

    #[test]
    fn an_admission_records_failures_for_its_ip() {
        let (c, _) = control();
        let adm = c.admit(ip("10.1.1.1")).unwrap();
        for _ in 0..4 {
            assert!(!adm.record_failure());
        }
        assert!(adm.record_failure());
        assert!(c.is_blocked(ip("10.1.1.1")));
        assert_eq!(adm.ip(), ip("10.1.1.1"));
    }
}
