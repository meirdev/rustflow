use std::io;

use prometheus_client::metrics::counter::Counter;

use crate::sink::OutputMetrics;

/// Counts every failure but logs only on a change of state, so a broken
/// disk produces two log lines and not one per record. Each operation has
/// its own state: only a successful write clears a write failure.
pub struct SinkErrors {
    metrics: OutputMetrics,
    write_failing: bool,
    rotate_failing: bool,
    flush_failing: bool,
}

fn observe(what: &str, failing: &mut bool, counter: &Counter, result: io::Result<()>) {
    match result {
        Ok(()) if *failing => {
            eprintln!("{what} recovered");
            *failing = false;
        }
        Ok(()) => {}
        Err(e) => {
            if !*failing {
                eprintln!("{what} failed: {e}");
                *failing = true;
            }
            counter.inc();
        }
    }
}

impl SinkErrors {
    pub fn new(metrics: &OutputMetrics) -> Self {
        Self {
            metrics: metrics.clone(),
            write_failing: false,
            rotate_failing: false,
            flush_failing: false,
        }
    }

    pub fn write(&mut self, result: io::Result<()>) {
        let counter = &self.metrics.write_errors;
        observe("output write", &mut self.write_failing, counter, result);
    }

    pub fn flush(&mut self, result: io::Result<()>) {
        let counter = &self.metrics.write_errors;
        observe("output flush", &mut self.flush_failing, counter, result);
    }

    /// `Ok(false)` means no rotation was due: neither success nor failure.
    pub fn rotate(&mut self, result: io::Result<bool>) {
        let result = match result {
            Ok(false) => return,
            Ok(true) => Ok(()),
            Err(e) => Err(e),
        };
        let counter = &self.metrics.rotate_errors;
        observe("output rotation", &mut self.rotate_failing, counter, result);
    }

    pub fn write_failing(&self) -> bool {
        self.write_failing
    }
}
