use std::io::{self, Write};

use prometheus::{IntCounter, Registry};

/// Output-side Prometheus counters. Cheap to clone: each counter is
/// reference-counted.
#[derive(Clone, Debug)]
pub struct OutputMetrics {
    /// Flows handed to the sink.
    pub flows: IntCounter,
    /// Bytes written to the destination, after encoding and compression.
    pub bytes: IntCounter,
    /// Files opened in a rotated output tree.
    pub files: IntCounter,
    /// Failed writes and flushes.
    pub write_errors: IntCounter,
    /// Failed rotations (opening the next window or committing the previous).
    pub rotate_errors: IntCounter,
}

impl OutputMetrics {
    pub fn new() -> Self {
        let counter = |name: &str, help: &str| {
            IntCounter::new(name, help).expect("static metric definitions are valid")
        };
        Self {
            flows: counter("output_flows_total", "Flows handed to the output sink"),
            bytes: counter(
                "output_bytes_total",
                "Bytes written to the output destination",
            ),
            files: counter(
                "output_files_total",
                "Files opened in the rotated output tree",
            ),
            write_errors: counter(
                "output_write_errors_total",
                "Failed output writes and flushes",
            ),
            rotate_errors: counter("output_rotate_errors_total", "Failed output file rotations"),
        }
    }

    pub fn register(&self, registry: &Registry) -> prometheus::Result<()> {
        for c in [
            &self.flows,
            &self.bytes,
            &self.files,
            &self.write_errors,
            &self.rotate_errors,
        ] {
            registry.register(Box::new(c.clone()))?;
        }
        Ok(())
    }
}

impl Default for OutputMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// A `Write` that counts the bytes passing through it.
pub(crate) struct CountingWriter<W> {
    inner: W,
    bytes: IntCounter,
}

impl<W: Write> CountingWriter<W> {
    pub(crate) fn new(inner: W, bytes: IntCounter) -> Self {
        Self { inner, bytes }
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.bytes.inc_by(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
