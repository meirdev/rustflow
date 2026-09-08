use std::time::{Duration, Instant};

/// A fixed-cadence deadline shared by the encoder loop and the raw ingest
/// loop.
///
/// A plain `recv_timeout(interval)` restarts its clock on every message, so
/// a steady trickle would never time out and buffered output would only
/// reach the file when the buffer fills. This timer is anchored instead:
/// [`due`](Self::due) is true once per interval however often it is polled.
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

    /// Time until the next deadline; what to pass to `recv_timeout`.
    pub fn remaining(&self) -> Duration {
        self.next.saturating_duration_since(Instant::now())
    }

    /// Whether the deadline has passed. When it has, the next deadline is
    /// scheduled one interval after the previous one (never in the past), so
    /// the cadence does not drift under load.
    pub fn due(&mut self) -> bool {
        let now = Instant::now();
        if now < self.next {
            return false;
        }
        self.next = (self.next + self.interval).max(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_steady_trickle_cannot_starve_the_deadline() {
        let interval = Duration::from_millis(40);
        let mut timer = FlushTimer::new(interval);
        let start = Instant::now();
        let mut fired = 0;
        // Poll far more often than the interval, as a busy loop would.
        while start.elapsed() < Duration::from_millis(250) {
            if timer.due() {
                fired += 1;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        // ~6 deadlines in 250 ms; allow for scheduler slop.
        assert!((4..=7).contains(&fired), "fired {fired} times");
    }

    #[test]
    fn remaining_never_exceeds_the_interval_and_reaches_zero() {
        let mut timer = FlushTimer::new(Duration::from_millis(20));
        assert!(timer.remaining() <= Duration::from_millis(20));
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(timer.remaining(), Duration::ZERO);
        assert!(timer.due());
        assert!(!timer.due(), "fires once per deadline");
    }
}
