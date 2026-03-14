//! Sliding-window rate limiter for connection throttling.
//!
//! Tracks connection timestamps per IP address in a fixed-size window
//! and rejects new connections that exceed the configured rate.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// A sliding-window rate limiter keyed by string (IP address).
pub struct RateLimiter {
    /// Maximum events allowed within the window.
    max_events: u32,
    /// Window duration in seconds.
    window_secs: u32,
    /// Per-key event timestamps.
    state: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// - `max_events`: Maximum connections per window (0 = unlimited).
    /// - `window_secs`: Window size in seconds.
    pub fn new(max_events: u32, window_secs: u32) -> Self {
        Self {
            max_events,
            window_secs,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a connection from `key` is allowed.
    ///
    /// Returns `true` if allowed (and records the event), `false` if rate-limited.
    pub fn check_and_record(&self, key: &str) -> bool {
        if self.max_events == 0 {
            return true; // unlimited
        }

        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs as u64);

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let timestamps = state.entry(key.to_string()).or_default();

        // Evict expired entries
        timestamps.retain(|t| now.duration_since(*t) < window);

        if timestamps.len() as u32 >= self.max_events {
            return false;
        }

        timestamps.push(now);
        true
    }

    /// Remove all state for a key (called when cleaning up).
    pub fn clear_key(&self, key: &str) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.remove(key);
    }

    /// Evict stale entries across all keys.
    pub fn gc(&self) {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs as u64);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.retain(|_, timestamps| {
            timestamps.retain(|t| now.duration_since(*t) < window);
            !timestamps.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn unlimited_always_allows() {
        let rl = RateLimiter::new(0, 60);
        for _ in 0..1000 {
            assert!(rl.check_and_record("1.2.3.4"));
        }
    }

    #[test]
    fn respects_limit() {
        let rl = RateLimiter::new(3, 60);
        assert!(rl.check_and_record("1.2.3.4"));
        assert!(rl.check_and_record("1.2.3.4"));
        assert!(rl.check_and_record("1.2.3.4"));
        assert!(!rl.check_and_record("1.2.3.4"));
        // Different key still works
        assert!(rl.check_and_record("5.6.7.8"));
    }

    #[test]
    fn window_expires() {
        let rl = RateLimiter::new(2, 1); // 2 per second
        assert!(rl.check_and_record("ip"));
        assert!(rl.check_and_record("ip"));
        assert!(!rl.check_and_record("ip")); // over limit

        sleep(Duration::from_millis(1100)); // wait for window
        assert!(rl.check_and_record("ip")); // should be allowed again
    }

    #[test]
    fn gc_removes_stale() {
        let rl = RateLimiter::new(5, 1);
        rl.check_and_record("a");
        rl.check_and_record("b");

        sleep(Duration::from_millis(1100));
        rl.gc();

        let state = rl.state.lock().unwrap();
        assert!(state.is_empty());
    }
}
