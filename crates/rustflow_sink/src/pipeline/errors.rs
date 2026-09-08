use std::io;

use prometheus::IntCounter;

use crate::sink::OutputMetrics;

/// Logs an operation's failures on state change instead of per record, and
/// counts every one.
struct ErrorGate {
    what: &'static str,
    failing: bool,
    counter: IntCounter,
}

impl ErrorGate {
    fn observe(&mut self, result: io::Result<()>) {
        match (result, self.failing) {
            (Ok(()), true) => {
                eprintln!("{} recovered", self.what);
                self.failing = false;
            }
            (Ok(()), false) => {}
            (Err(e), false) => {
                eprintln!("{} failed: {e}", self.what);
                self.failing = true;
                self.counter.inc();
            }
            (Err(_), true) => self.counter.inc(),
        }
    }
}

/// One `ErrorGate` per sink operation, so they cannot mask each other: a
/// rotation that was not due is not an observation, and only a successful
/// *write* clears a write failure.
pub struct SinkErrors {
    write: ErrorGate,
    rotate: ErrorGate,
    flush: ErrorGate,
}

impl SinkErrors {
    pub fn new(metrics: &OutputMetrics) -> Self {
        let gate = |what, counter: &IntCounter| ErrorGate {
            what,
            failing: false,
            counter: counter.clone(),
        };
        Self {
            write: gate("output write", &metrics.write_errors),
            rotate: gate("output rotation", &metrics.rotate_errors),
            flush: gate("output flush", &metrics.write_errors),
        }
    }

    pub fn write(&mut self, result: io::Result<()>) {
        self.write.observe(result);
    }

    pub fn flush(&mut self, result: io::Result<()>) {
        self.flush.observe(result);
    }

    /// `Ok(false)` means no rotation was due: neither success nor failure.
    pub fn rotate(&mut self, result: io::Result<bool>) {
        match result {
            Ok(false) => {}
            Ok(true) => self.rotate.observe(Ok(())),
            Err(e) => self.rotate.observe(Err(e)),
        }
    }

    /// Whether the last observed write failed.
    pub fn write_failing(&self) -> bool {
        self.write.failing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err() -> io::Result<()> {
        Err(io::Error::other("disk full"))
    }

    #[test]
    fn a_not_due_rotation_does_not_clear_a_write_failure() {
        let metrics = OutputMetrics::new();
        let mut errors = SinkErrors::new(&metrics);

        errors.write(err());
        assert!(errors.write_failing());
        assert_eq!(metrics.write_errors.get(), 1);

        for _ in 0..100 {
            errors.rotate(Ok(false));
        }
        assert!(errors.write_failing(), "still failing; no false recovery");

        errors.write(err());
        assert_eq!(metrics.write_errors.get(), 2);
        assert_eq!(metrics.rotate_errors.get(), 0);

        errors.write(Ok(()));
        assert!(!errors.write_failing());
    }

    #[test]
    fn rotation_failures_count_separately() {
        let metrics = OutputMetrics::new();
        let mut errors = SinkErrors::new(&metrics);
        errors.rotate(Err(io::Error::other("mkdir")));
        errors.rotate(Ok(true));
        assert_eq!(metrics.rotate_errors.get(), 1);
        assert_eq!(metrics.write_errors.get(), 0);
    }
}
