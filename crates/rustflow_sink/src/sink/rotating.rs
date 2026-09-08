use std::io;

use chrono::{DateTime, Utc};
use rustflow_core::common::common_flow::CommonFlow;
use serde::Serialize;

use super::FlowSink;
use super::destination::{Destination, Opened, PendingRename};
use super::metrics::{CountingWriter, OutputMetrics};
use crate::encoder::{FlowEncoder, RawEncoder};
use crate::flow::Enriched;

/// A [`Destination`] plus the encoder for its current window: the rotation
/// state machine. Generic over the encoder, so each format is
/// monomorphized; boxed once as a [`FlowSink`].
pub struct RotatingSink<E: FlowEncoder> {
    destination: Destination,
    enriched_fields: Vec<String>,
    metrics: OutputMetrics,
    current: Window<E>,
    /// A record has been written since the last flush.
    dirty: bool,
}

/// One open stream and what to do when it ends.
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

    /// Finish the stream, then (and only then) give the file its final name.
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

    /// Open the window containing `now`. Tests use this to drive rotation
    /// without waiting.
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
                // The next window is already live; a failure to close the
                // previous one is reported but does not stop output.
                previous.close()?;
                Ok(true)
            }
            Err(e) => {
                // Keep writing to the current file; try again next window.
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

/// Raw mode: available only where the encoder can carry arbitrary records.
impl<E: RawEncoder> RotatingSink<E> {
    pub fn write_raw<T: Serialize + ?Sized>(&mut self, value: &T) -> io::Result<()> {
        self.current.encoder.write_value(value)?;
        self.dirty = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::encoder::Ndjson;
    use crate::test_support::sample_flow;

    fn stamp(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    /// 2024-01-02T15:07:00Z
    const SAMPLE: i64 = 1_704_208_020;

    fn files_under(root: &PathBuf) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn rotation_closes_the_previous_window_and_renames_it() {
        let root = std::env::temp_dir().join("rustflow_sink_rotating_test");
        std::fs::remove_dir_all(&root).ok();
        let metrics = OutputMetrics::new();
        let dest = Destination::Partitioned {
            root: root.clone(),
            level: 0,
            prefix: "flows".into(),
            interval_secs: 600,
        };

        let mut sink: Box<dyn FlowSink> = Box::new(
            RotatingSink::<Ndjson>::open_at(dest, Vec::new(), metrics.clone(), stamp(SAMPLE))
                .unwrap(),
        );
        sink.write(&sample_flow(), &Enriched::new(0)).unwrap();

        // Still inside the 15:00 window: nothing happens.
        assert!(!sink.rotate_if_due(stamp(SAMPLE + 60)).unwrap());
        assert_eq!(files_under(&root), [".flows-20240102T150000Z.ndjson.tmp"]);

        // 15:10: the first window is committed, the second is open under a
        // temporary name.
        assert!(sink.rotate_if_due(stamp(SAMPLE + 600)).unwrap());
        assert_eq!(
            files_under(&root),
            [
                ".flows-20240102T151000Z.ndjson.tmp",
                "flows-20240102T150000Z.ndjson"
            ]
        );
        let first = std::fs::read_to_string(root.join("flows-20240102T150000Z.ndjson")).unwrap();
        assert_eq!(
            first.lines().count(),
            1,
            "the buffered record was flushed on close"
        );

        sink.finish().unwrap();
        assert_eq!(
            files_under(&root),
            [
                "flows-20240102T150000Z.ndjson",
                "flows-20240102T151000Z.ndjson"
            ]
        );
        assert_eq!(metrics.files.get(), 2);
        assert!(metrics.bytes.get() > 0);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn single_file_never_rotates() {
        let path = std::env::temp_dir().join("rustflow_sink_single_file_test.ndjson");
        let metrics = OutputMetrics::new();
        let mut sink = RotatingSink::<Ndjson>::open_at(
            Destination::File(path.clone()),
            Vec::new(),
            metrics,
            stamp(SAMPLE),
        )
        .unwrap();
        sink.write(&sample_flow(), &Enriched::new(0)).unwrap();
        assert!(!sink.rotate_if_due(stamp(SAMPLE + 86_400)).unwrap());

        // Flush pushes the line out; a second flush with nothing new is a no-op.
        sink.flush().unwrap();
        assert!(!sink.dirty);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);

        Box::new(sink).finish().unwrap();
        std::fs::remove_file(&path).ok();
    }
}
