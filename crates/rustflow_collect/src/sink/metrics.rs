use std::io::{self, Write};

use prometheus_client::metrics::counter::Counter;
use prometheus_client::registry::Registry;

#[derive(Clone, Debug, Default)]
pub struct OutputMetrics {
    pub flows: Counter,
    /// Bytes written to the destination, after encoding and compression.
    pub bytes: Counter,
    /// Files opened in a rotated output tree.
    pub files: Counter,
    /// Failed writes and flushes.
    pub write_errors: Counter,
    pub rotate_errors: Counter,
}

impl OutputMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Counters are registered without `_total`; the encoder appends it.
    pub fn register(&self, registry: &mut Registry) {
        registry.register(
            "output_flows",
            "Flows handed to the output sink",
            self.flows.clone(),
        );
        registry.register(
            "output_bytes",
            "Bytes written to the output destination",
            self.bytes.clone(),
        );
        registry.register(
            "output_files",
            "Files opened in the rotated output tree",
            self.files.clone(),
        );
        registry.register(
            "output_write_errors",
            "Failed output writes and flushes",
            self.write_errors.clone(),
        );
        registry.register(
            "output_rotate_errors",
            "Failed output file rotations",
            self.rotate_errors.clone(),
        );
    }
}

/// A `Write` that counts the bytes passing through it.
pub(crate) struct CountingWriter<W> {
    inner: W,
    bytes: Counter,
}

impl<W: Write> CountingWriter<W> {
    pub(crate) fn new(inner: W, bytes: Counter) -> Self {
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
