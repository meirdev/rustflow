//! Output sinks: encoders turn flows into bytes, destinations say where the
//! bytes go, and the rotating sink opens and closes files on an interval.

pub mod destination;
pub mod encoder;
pub mod metrics;
pub mod pipeline;
pub mod rotating;

use std::path::PathBuf;
use std::time::Duration;
use std::{fmt, io};

use chrono::{DateTime, Utc};
use clap::ValueEnum;
pub use destination::{Destination, MAX_PARTITION_LEVEL, PendingRename};
pub use encoder::{Csv, Discard, FlowEncoder, Ndjson, Parquet, Protobuf, RawEncoder};
pub use metrics::OutputMetrics;
pub use pipeline::{FLUSH_INTERVAL, encoder_loop};
pub use rotating::RotatingSink;
use rustflow_core::common::common_flow::CommonFlow;
use serde::Serialize;

use crate::enrich::Enriched;

/// A sink for common-format flows, owned by one thread.
pub trait FlowSink: Send {
    fn write(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()>;

    /// Closes the current window and opens the next if `now` is past the
    /// rotation boundary. `Ok(false)` when nothing was due.
    fn rotate_if_due(&mut self, now: DateTime<Utc>) -> io::Result<bool>;

    fn flush(&mut self) -> io::Result<()>;

    /// Ends the stream and gives a rotated file its final name.
    fn finish(self: Box<Self>) -> io::Result<()>;
}

/// `--format`: the original packet structure, or the normalized flow.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Raw,
    Common,
}

/// `--serialization`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Newline-delimited JSON, one object per line
    Ndjson,
    Csv,
    /// Snappy-compressed Apache Parquet
    Parquet,
    /// Length-delimited protobuf, see `proto/rustflow.proto`
    Protobuf,
    /// Decode and count flows but write no output (for load testing)
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

/// The sink-related CLI flags.
#[derive(Clone, Debug)]
pub struct SinkConfig {
    /// A file when `interval` is `None`, otherwise the root of the
    /// partitioned tree. `None` writes to stdout.
    pub path: Option<PathBuf>,
    pub format: Format,
    /// Start a new file every interval.
    pub interval: Option<Duration>,
    pub level: u8,
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

fn open<E: FlowEncoder + 'static>(
    dest: Destination,
    enriched_fields: Vec<String>,
    metrics: OutputMetrics,
) -> io::Result<Box<dyn FlowSink>> {
    Ok(Box::new(RotatingSink::<E>::open(
        dest,
        enriched_fields,
        metrics,
    )?))
}

/// The sink for `--format common`.
pub fn build(
    config: &SinkConfig,
    enriched_fields: Vec<String>,
    metrics: &OutputMetrics,
) -> io::Result<Box<dyn FlowSink>> {
    let dest = config.destination();
    let metrics = metrics.clone();
    match config.format {
        Format::Ndjson => open::<Ndjson>(dest, enriched_fields, metrics),
        Format::Csv => open::<Csv>(dest, enriched_fields, metrics),
        Format::Parquet => {
            if matches!(dest, Destination::Stdout) {
                return Err(io::Error::other(
                    "--serialization parquet requires --output <FILE>",
                ));
            }
            open::<Parquet>(dest, enriched_fields, metrics)
        }
        Format::Protobuf => open::<Protobuf>(dest, enriched_fields, metrics),
        Format::Discard => open::<Discard>(Destination::Null, enriched_fields, metrics),
    }
}

/// The sink for `--format raw`: any serializable packet, one per record.
/// Writing is generic over `T: Serialize`, so it cannot go behind `dyn`;
/// raw mode has exactly the encoders with a `RawEncoder` impl.
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
