use std::io;

use chrono::Utc;
use serde::Serialize;

use super::{FLUSH_INTERVAL, FlushTimer, SinkErrors};
use crate::sink::{OutputMetrics, RawSink};

/// `--format raw` has no encoder thread: the ingest loop writes packets
/// itself, and its socket read timeout keeps the flush cadence.
pub struct RawOutput {
    sink: RawSink,
    errors: SinkErrors,
    timer: FlushTimer,
}

impl RawOutput {
    pub fn new(sink: RawSink, metrics: &OutputMetrics) -> Self {
        Self {
            sink,
            errors: SinkErrors::new(metrics),
            timer: FlushTimer::new(FLUSH_INTERVAL),
        }
    }

    pub fn write<T: Serialize>(&mut self, record: &T) {
        self.errors.rotate(self.sink.rotate_if_due(Utc::now()));
        self.errors.write(self.sink.write(record));
        self.idle();
    }

    /// Flush on the deadline; also called when no packet arrives, so an
    /// idle window still rotates on time.
    pub fn idle(&mut self) {
        if self.timer.due() {
            self.errors.rotate(self.sink.rotate_if_due(Utc::now()));
            self.errors.flush(self.sink.flush());
        }
    }

    pub fn finish(self) -> io::Result<()> {
        self.sink.finish()
    }
}
