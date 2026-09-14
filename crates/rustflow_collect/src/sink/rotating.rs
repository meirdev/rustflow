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
    current: Window<E>,
    dirty: bool,
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
        if pending.is_some() {
            metrics.files.inc();
        }
        let writer = Box::new(CountingWriter::new(writer, metrics.bytes.clone()));
        Ok(Self {
            encoder: E::open(writer, fields)?,
            pending,
            rotate_at,
        })
    }

    /// Finishes the stream, then gives the file its final name.
    fn close(self) -> io::Result<()> {
        self.encoder.finish()?;
        self.pending.map_or(Ok(()), PendingRename::commit)
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
            current,
            dirty: false,
        })
    }
}

impl<E: FlowEncoder> FlowSink for RotatingSink<E> {
    fn write(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        self.current.encoder.encode(flow, enriched)?;
        self.dirty = true;
        Ok(())
    }

    fn rotate_if_due(&mut self, now: DateTime<Utc>) -> io::Result<bool> {
        let Some(rotate_at) = self.current.rotate_at else {
            return Ok(false);
        };
        if now.timestamp() < rotate_at {
            return Ok(false);
        }

        match Window::open(&self.destination, &self.enriched_fields, &self.metrics, now) {
            Ok(next) => {
                let previous = std::mem::replace(&mut self.current, next);
                self.dirty = false;
                previous.close()?;
                Ok(true)
            }
            Err(e) => {
                // Keep writing to the current file and try again next window.
                if let Some(interval_secs) = self.destination.interval_secs() {
                    self.current.rotate_at = Some(rotate_at + interval_secs);
                }
                Err(e)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        self.current.encoder.flush()?;
        self.dirty = false;
        Ok(())
    }

    fn finish(self: Box<Self>) -> io::Result<()> {
        self.current.close()
    }
}

impl<E: RawEncoder> RotatingSink<E> {
    pub fn write_raw<T: Serialize + ?Sized>(&mut self, value: &T) -> io::Result<()> {
        self.current.encoder.write_value(value)?;
        self.dirty = true;
        Ok(())
    }
}
