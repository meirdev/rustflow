use std::io;

use chrono::{DateTime, Utc};
use rustflow_core::common::common_flow::CommonFlow;
use serde::Serialize;

use super::FlowSink;
use super::destination::{Destination, Opened, PendingRename};
use super::metrics::{CountingWriter, OutputMetrics};
use crate::enrich::Enriched;
use crate::sink::encoder::{FlowEncoder, RawEncoder};

/// A [`Destination`] plus the encoder for its current window.
pub struct RotatingSink<E: FlowEncoder> {
    destination: Destination,
    enriched_fields: Vec<String>,
    metrics: OutputMetrics,
    /// `None` after a rotation until the next write, so an idle interval
    /// leaves no empty file behind.
    current: Option<Window<E>>,
}

struct Window<E> {
    encoder: E,
    pending: Option<PendingRename>,
    rotate_at: Option<i64>,
}

impl<E: FlowEncoder> Window<E> {
    fn open(
        destination: &Destination,
        fields: &[String],
        metrics: &OutputMetrics,
        now: DateTime<Utc>,
    ) -> io::Result<Self> {
        let Opened {
            writer,
            pending,
            rotate_at,
        } = destination.open_for(now, E::EXTENSION)?;
        let writer = Box::new(CountingWriter::new(writer, metrics.bytes.clone()));
        let encoder = E::open(writer, fields)?;
        if pending.is_some() {
            metrics.files.inc();
        }
        Ok(Self {
            encoder,
            pending,
            rotate_at,
        })
    }

    /// Finishes the stream, then gives the file its final name. The rename
    /// happens even when finishing failed: a truncated window is worth more
    /// than one hidden behind a `.tmp` name.
    fn close(self) -> io::Result<()> {
        let finished = self.encoder.finish();
        let committed = self.pending.map_or(Ok(()), PendingRename::commit);
        finished.and(committed)
    }
}

impl<E: FlowEncoder> RotatingSink<E> {
    pub fn open(
        destination: Destination,
        enriched_fields: Vec<String>,
        metrics: OutputMetrics,
    ) -> io::Result<Self> {
        Self::open_at(destination, enriched_fields, metrics, Utc::now())
    }

    /// The first window is opened right away, so a bad path fails at startup.
    pub fn open_at(
        destination: Destination,
        enriched_fields: Vec<String>,
        metrics: OutputMetrics,
        now: DateTime<Utc>,
    ) -> io::Result<Self> {
        let current = Window::open(&destination, &enriched_fields, &metrics, now)?;
        Ok(Self {
            destination,
            enriched_fields,
            metrics,
            current: Some(current),
        })
    }

    fn window(&mut self) -> io::Result<&mut Window<E>> {
        if self.current.is_none() {
            let window = Window::open(
                &self.destination,
                &self.enriched_fields,
                &self.metrics,
                Utc::now(),
            )?;
            self.current = Some(window);
        }
        Ok(self.current.as_mut().expect("opened above"))
    }
}

impl<E: FlowEncoder> FlowSink for RotatingSink<E> {
    fn write(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        self.window()?.encoder.encode(flow, enriched)
    }

    fn rotate_if_due(&mut self, now: DateTime<Utc>) -> io::Result<bool> {
        let Some(rotate_at) = self.current.as_ref().and_then(|w| w.rotate_at) else {
            return Ok(false);
        };
        if now.timestamp() < rotate_at {
            return Ok(false);
        }
        if let Some(previous) = self.current.take() {
            previous.close()?;
        }
        Ok(true)
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.current {
            Some(window) => window.encoder.flush(),
            None => Ok(()),
        }
    }

    fn finish(mut self: Box<Self>) -> io::Result<()> {
        match self.current.take() {
            Some(window) => window.close(),
            None => Ok(()),
        }
    }
}

impl<E: RawEncoder> RotatingSink<E> {
    pub fn write_raw<T: Serialize + ?Sized>(&mut self, value: &T) -> io::Result<()> {
        self.window()?.encoder.write_value(value)
    }
}
