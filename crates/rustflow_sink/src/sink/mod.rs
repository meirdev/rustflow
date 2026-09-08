//! Layers 2 and 3: where bytes go and when files open, close and rotate.
//!
//! [`FlowSink`] is what the encoder thread owns; [`RotatingSink`]
//! implements it for every [`FlowEncoder`](crate::encoder::FlowEncoder) on
//! top of a [`Destination`].
//! [`build`] and [`build_raw`] hold the only `match` on the output format.

pub mod destination;
pub mod metrics;
pub mod rotating;

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rustflow_core::common::common_flow::CommonFlow;
use serde::Serialize;

pub use destination::{Destination, MAX_PARTITION_LEVEL, PendingRename};
pub use metrics::OutputMetrics;
pub use rotating::RotatingSink;

use crate::encoder::{Csv, Discard, Ndjson, Parquet, Protobuf};
use crate::flow::Enriched;

/// A sink for common-format flows, owned by exactly one thread.
///
/// Implemented by [`RotatingSink`] for every [`FlowEncoder`](crate::encoder::FlowEncoder); boxed once in
/// [`build`] so the rest of the collector is format-agnostic.
pub trait FlowSink: Send {
    fn write(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()>;

    /// Close the current window and open the next if `now` is past the
    /// rotation boundary. `Ok(false)` when nothing was due; callers must not
    /// count that as a successful rotation.
    fn rotate_if_due(&mut self, now: DateTime<Utc>) -> io::Result<bool>;

    /// Push buffered bytes out without ending the stream.
    fn flush(&mut self) -> io::Result<()>;

    /// End the stream (Parquet footer) and give a rotated file its final
    /// name.
    fn finish(self: Box<Self>) -> io::Result<()>;
}

/// Serialization formats, mirroring the `--serialization` flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Ndjson,
    Csv,
    Parquet,
    Protobuf,
    Discard,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Format::Ndjson => "ndjson",
            Format::Csv => "csv",
            Format::Parquet => "parquet",
            Format::Protobuf => "protobuf",
            Format::Discard => "discard",
        })
    }
}

/// Where and how flows are written; the sink-related CLI flags.
#[derive(Clone, Debug)]
pub struct SinkConfig {
    /// Output path: a file when `interval` is `None`, otherwise the root
    /// directory of the partitioned tree. `None` writes to stdout.
    pub path: Option<PathBuf>,
    pub format: Format,
    /// Start a new file every interval. `None` writes a single file.
    pub interval: Option<Duration>,
    /// Directory partitioning level, see [`Destination::Partitioned`].
    pub level: u8,
    /// File name prefix inside the partitioned tree.
    pub prefix: String,
}

impl SinkConfig {
    fn destination(&self) -> Destination {
        match (&self.path, self.interval) {
            (None, _) => Destination::Stdout,
            (Some(path), None) => Destination::File(path.clone()),
            (Some(root), Some(interval)) => Destination::Partitioned {
                root: root.clone(),
                level: self.level.min(MAX_PARTITION_LEVEL),
                prefix: self.prefix.clone(),
                interval_secs: interval.as_secs().max(1) as i64,
            },
        }
    }
}

/// Build the sink for `--format common`.
pub fn build(
    config: &SinkConfig,
    enriched_fields: Vec<String>,
    metrics: &OutputMetrics,
) -> io::Result<Box<dyn FlowSink>> {
    let dest = config.destination();
    let metrics = metrics.clone();
    Ok(match config.format {
        Format::Ndjson => Box::new(RotatingSink::<Ndjson>::open(
            dest,
            enriched_fields,
            metrics,
        )?),
        Format::Csv => Box::new(RotatingSink::<Csv>::open(dest, enriched_fields, metrics)?),
        Format::Parquet => {
            if matches!(dest, Destination::Stdout) {
                return Err(io::Error::other(
                    "--serialization parquet requires --output <FILE>",
                ));
            }
            Box::new(RotatingSink::<Parquet>::open(
                dest,
                enriched_fields,
                metrics,
            )?)
        }
        Format::Protobuf => Box::new(RotatingSink::<Protobuf>::open(
            dest,
            enriched_fields,
            metrics,
        )?),
        Format::Discard => Box::new(RotatingSink::<Discard>::open(
            Destination::Null,
            enriched_fields,
            metrics,
        )?),
    })
}

/// The sink for `--format raw`: any serializable packet, one per record.
///
/// Writing a raw record is generic over `T: Serialize`, so it cannot go
/// behind `dyn`. Raw mode has exactly two legal encoders, and a variant
/// cannot be added here without a [`RawEncoder`](crate::encoder::RawEncoder) impl, which is the rule
/// "raw requires ndjson or discard" expressed as a type.
pub enum RawSink {
    Ndjson(RotatingSink<Ndjson>),
    Discard(RotatingSink<Discard>),
}

impl RawSink {
    pub fn write<T: Serialize + ?Sized>(&mut self, value: &T) -> io::Result<()> {
        match self {
            RawSink::Ndjson(s) => s.write_raw(value),
            RawSink::Discard(s) => s.write_raw(value),
        }
    }

    pub fn rotate_if_due(&mut self, now: DateTime<Utc>) -> io::Result<bool> {
        match self {
            RawSink::Ndjson(s) => s.rotate_if_due(now),
            RawSink::Discard(s) => s.rotate_if_due(now),
        }
    }

    pub fn flush(&mut self) -> io::Result<()> {
        match self {
            RawSink::Ndjson(s) => s.flush(),
            RawSink::Discard(s) => s.flush(),
        }
    }

    pub fn finish(self) -> io::Result<()> {
        match self {
            RawSink::Ndjson(s) => Box::new(s).finish(),
            RawSink::Discard(s) => Box::new(s).finish(),
        }
    }
}

/// Build the sink for `--format raw`.
pub fn build_raw(config: &SinkConfig, metrics: &OutputMetrics) -> io::Result<RawSink> {
    let metrics = metrics.clone();
    Ok(match config.format {
        Format::Ndjson => RawSink::Ndjson(RotatingSink::open(
            config.destination(),
            Vec::new(),
            metrics,
        )?),
        Format::Discard => {
            RawSink::Discard(RotatingSink::open(Destination::Null, Vec::new(), metrics)?)
        }
        other => {
            return Err(io::Error::other(format!(
                "--serialization {other} requires --format common"
            )));
        }
    })
}
