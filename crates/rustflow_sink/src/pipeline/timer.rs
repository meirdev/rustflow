use std::time::{Duration, Instant};

/// A deadline that fires once per interval however often it is polled.
/// `recv_timeout(interval)` alone restarts its clock on every message, so a
/// steady trickle would never flush.
pub struct FlushTimer {
    next: Instant,
    interval: Duration,
}

impl FlushTimer {
    pub fn new(interval: Duration) -> Self {
        Self {
            next: Instant::now() + interval,
            interval,
        }
    }

    pub fn remaining(&self) -> Duration {
        self.next.saturating_duration_since(Instant::now())
    }

    pub fn due(&mut self) -> bool {
        let now = Instant::now();
        if now < self.next {
            return false;
        }
        // One interval after the previous deadline, never in the past, so
        // the cadence does not drift under load.
        self.next = (self.next + self.interval).max(now);
        true
    }
}
