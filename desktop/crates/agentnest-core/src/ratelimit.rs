//! Small rate limiters (docs/security.md 11): a sliding window counter for per-device message limits and a token
//! bucket for the loopback hook collector. Both take the time as an argument so tests do not sleep.

use std::collections::VecDeque;

/// At most `limit` events in any `window_ms` span.
#[derive(Clone, Debug)]
pub struct SlidingWindow {
    limit: usize,
    window_ms: i64,
    hits: VecDeque<i64>,
}

impl SlidingWindow {
    /// A limiter allowing `limit` events per `window_ms`.
    pub fn new(limit: usize, window_ms: i64) -> Self {
        Self {
            limit,
            window_ms,
            hits: VecDeque::new(),
        }
    }

    /// Records an event at `now_ms` and returns `true` if it is within the limit. A refused event is not recorded.
    pub fn try_acquire(&mut self, now_ms: i64) -> bool {
        self.prune(now_ms);
        if self.hits.len() >= self.limit {
            return false;
        }
        self.hits.push_back(now_ms);
        true
    }

    /// Records an event unconditionally (failure counters) and returns the number of events in the window.
    pub fn record(&mut self, now_ms: i64) -> usize {
        self.prune(now_ms);
        self.hits.push_back(now_ms);
        self.hits.len()
    }

    /// Events in the window at `now_ms`.
    pub fn count(&mut self, now_ms: i64) -> usize {
        self.prune(now_ms);
        self.hits.len()
    }

    fn prune(&mut self, now_ms: i64) {
        while let Some(&t) = self.hits.front() {
            if now_ms - t >= self.window_ms {
                self.hits.pop_front();
            } else {
                break;
            }
        }
    }
}

/// A token bucket: `rate_per_s` tokens per second up to `burst`.
#[derive(Clone, Debug)]
pub struct TokenBucket {
    rate_per_s: f64,
    burst: f64,
    tokens: f64,
    last_ms: i64,
}

impl TokenBucket {
    /// A full bucket.
    pub fn new(rate_per_s: u32, burst: u32, now_ms: i64) -> Self {
        Self {
            rate_per_s: f64::from(rate_per_s),
            burst: f64::from(burst),
            tokens: f64::from(burst),
            last_ms: now_ms,
        }
    }

    /// Takes one token if available.
    pub fn try_acquire(&mut self, now_ms: i64) -> bool {
        let elapsed = (now_ms - self.last_ms).max(0) as f64 / 1000.0;
        self.last_ms = now_ms.max(self.last_ms);
        self.tokens = (self.tokens + elapsed * self.rate_per_s).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sliding_window_allows_limit_events_per_window() {
        let mut w = SlidingWindow::new(10, 60_000);
        for i in 0..10 {
            assert!(w.try_acquire(i * 100), "event {i}");
        }
        assert!(!w.try_acquire(1_000), "the 11th within a minute is refused");
        assert!(!w.try_acquire(59_000));
        // the first event leaves the window after 60 s
        assert!(w.try_acquire(60_000));
        assert!(!w.try_acquire(60_050));
    }

    #[test]
    fn record_counts_failures() {
        let mut w = SlidingWindow::new(5, 60_000);
        for i in 1..=5 {
            assert_eq!(w.record(i * 1_000), i as usize);
        }
        assert_eq!(w.count(30_000), 5);
        assert_eq!(w.count(62_500), 3, "the two oldest expired");
    }

    #[test]
    fn token_bucket_bursts_then_refills() {
        let mut b = TokenBucket::new(200, 200, 0);
        for _ in 0..200 {
            assert!(b.try_acquire(0));
        }
        assert!(!b.try_acquire(0));
        assert!(!b.try_acquire(4), "0.8 token after 4 ms");
        assert!(b.try_acquire(5), "one token after 5 ms at 200/s");
        assert!(b.try_acquire(1_000));
        // a long pause refills to the burst only
        let mut taken = 0;
        while b.try_acquire(10_000) {
            taken += 1;
        }
        assert_eq!(taken, 200);
    }
}
