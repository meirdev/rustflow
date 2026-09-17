use std::io;

use chrono::{DateTime, Utc};
use rustflow_core::common::common_flow::CommonFlow;

use super::Serialization;
use super::destination::{Destination, Opened, PendingRename};
use super::encoder::Encoder;
use super::hook::{FileHook, Job};
use super::metrics::{CountingWriter, OutputMetrics};
use crate::enrich::Enriched;

/// A [`Destination`] plus the encoder for its current window.
pub struct RotatingSink {
    serialization: Serialization,
    destination: Destination,
    enriched_fields: Vec<String>,
    metrics: OutputMetrics,
    /// `None` after a rotation until the next write, so an idle interval
    /// leaves no empty file behind.
    current: Option<Window>,
    hook: Option<FileHook>,
}

struct Window {
    encoder: Box<dyn Encoder>,
    pending: Option<PendingRename>,
    rotate_at: Option<i64>,
}

impl Window {
    /// Finishes the stream, then gives the file its final name. The rename
    /// happens even when finishing failed: a truncated window is worth more
    /// than one hidden behind a `.tmp` name.
    fn close(mut self, hook: Option<&FileHook>) -> io::Result<()> {
        let finished = self.encoder.finish();
        let window = self.pending.as_ref().map(PendingRename::window);
        let committed = self.pending.map(PendingRename::commit).transpose();
        // Only a complete file is handed to the command.
        let path = finished.and(committed)?;
        if let (Some(hook), Some(path), Some(window)) = (hook, path, window) {
            hook.run(Job { path, window });
        }
        Ok(())
    }
}

impl RotatingSink {
    pub fn serialization(&self) -> Serialization {
        self.serialization
    }

    pub fn open(
        serialization: Serialization,
        destination: Destination,
        enriched_fields: Vec<String>,
        metrics: OutputMetrics,
    ) -> io::Result<Self> {
        Self::open_at(
            serialization,
            destination,
            enriched_fields,
            metrics,
            Utc::now(),
        )
    }

    /// The first window is opened right away, so a bad path fails at startup.
    pub fn open_at(
        serialization: Serialization,
        destination: Destination,
        enriched_fields: Vec<String>,
        metrics: OutputMetrics,
        now: DateTime<Utc>,
    ) -> io::Result<Self> {
        let mut sink = Self {
            serialization,
            destination,
            enriched_fields,
            metrics,
            current: None,
            hook: None,
        };
        sink.current = Some(sink.open_window(now)?);
        Ok(sink)
    }

    /// Runs `hook` for every file this sink completes.
    pub fn with_hook(mut self, hook: FileHook) -> Self {
        self.hook = Some(hook);
        self
    }

    fn open_window(&self, now: DateTime<Utc>) -> io::Result<Window> {
        let Opened {
            writer,
            pending,
            rotate_at,
        } = self
            .destination
            .open_for(now, self.serialization.extension())?;
        let writer = Box::new(CountingWriter::new(writer, self.metrics.bytes.clone()));
        let encoder = self.serialization.open(writer, &self.enriched_fields)?;
        if pending.is_some() {
            self.metrics.files.inc();
        }
        Ok(Window {
            encoder,
            pending,
            rotate_at,
        })
    }

    fn window(&mut self) -> io::Result<&mut Window> {
        if self.current.is_none() {
            let window = self.open_window(Utc::now())?;
            self.current = Some(window);
        }
        Ok(self.current.as_mut().expect("opened above"))
    }

    pub fn write(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        self.window()?.encoder.encode(flow, enriched)
    }

    pub fn write_raw(&mut self, lines: &[u8]) -> io::Result<()> {
        self.window()?.encoder.write_raw(lines)
    }

    /// Closes the current window if `now` is past its rotation boundary;
    /// the next window opens on the next write. `Ok(false)` when nothing
    /// was due.
    pub fn rotate_if_due(&mut self, now: DateTime<Utc>) -> io::Result<bool> {
        let Some(rotate_at) = self.current.as_ref().and_then(|w| w.rotate_at) else {
            return Ok(false);
        };
        if now.timestamp() < rotate_at {
            return Ok(false);
        }
        if let Some(previous) = self.current.take() {
            previous.close(self.hook.as_ref())?;
        }
        Ok(true)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        match &mut self.current {
            Some(window) => window.encoder.flush(),
            None => Ok(()),
        }
    }

    /// Ends the stream, gives a rotated file its final name, and waits for
    /// the `-x` commands still queued.
    pub fn finish(mut self) -> io::Result<()> {
        let result = match self.current.take() {
            Some(window) => window.close(self.hook.as_ref()),
            None => Ok(()),
        };
        if let Some(hook) = self.hook.take() {
            hook.finish();
        }
        result
    }
}
