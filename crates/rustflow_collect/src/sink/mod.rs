pub mod destination;
pub mod encoder;
pub mod hook;
pub mod metrics;
pub mod pipeline;
pub mod rotating;

use std::path::PathBuf;
use std::time::Duration;
use std::{fmt, io};

use clap::ValueEnum;
pub use destination::{Destination, MAX_PARTITION_LEVEL, PendingRename};
pub use encoder::{Csv, Discard, Encoder, Ndjson, Parquet, Protobuf, Writer};
pub use hook::{FileHook, Job};
pub use metrics::OutputMetrics;
pub use pipeline::{Chunk, FLUSH_INTERVAL, Pipeline, encoder_loop};
pub use rotating::RotatingSink;

/// `--format`: the original packet structure, or the normalized flow.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Raw,
    Common,
}

/// `--serialization`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Serialization {
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

impl Serialization {
    /// File extension in the partitioned tree.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Ndjson => "ndjson",
            Self::Csv => "csv",
            Self::Parquet => "parquet",
            Self::Protobuf => "pb",
            Self::Discard => "discard",
        }
    }

    /// `--format raw` hands the sink records it serialized itself.
    fn takes_raw(self) -> bool {
        matches!(self, Self::Ndjson | Self::Discard)
    }

    /// Opens the encoder over `out`; the header is written right away.
    pub fn open(self, out: Writer, enriched_fields: &[String]) -> io::Result<Box<dyn Encoder>> {
        Ok(match self {
            Self::Ndjson => Box::new(Ndjson::open(out, enriched_fields)?),
            Self::Csv => Box::new(Csv::open(out, enriched_fields)?),
            Self::Parquet => Box::new(Parquet::open(out, enriched_fields)?),
            Self::Protobuf => Box::new(Protobuf::open(out, enriched_fields)?),
            Self::Discard => Box::new(Discard::open(out, enriched_fields)?),
        })
    }
}

/// The name clap accepts on the command line.
impl fmt::Display for Serialization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            self.to_possible_value()
                .expect("no hidden variants")
                .get_name(),
        )
    }
}

/// The sink-related CLI flags.
#[derive(Clone, Debug)]
pub struct SinkConfig {
    /// A file when `interval` is `None`, otherwise the root of the
    /// partitioned tree. `None` writes to stdout.
    pub path: Option<PathBuf>,
    pub serialization: Serialization,
    /// Start a new file every interval.
    pub interval: Option<Duration>,
    pub level: u8,
    pub prefix: String,
    /// `-x`: run after each completed file.
    pub exec: Option<String>,
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

/// The sink for the CLI flags; `format` decides which serializations
/// qualify.
pub fn build(
    format: OutputFormat,
    config: &SinkConfig,
    enriched_fields: Vec<String>,
    metrics: &OutputMetrics,
) -> io::Result<RotatingSink> {
    let serialization = config.serialization;
    if format == OutputFormat::Raw && !serialization.takes_raw() {
        return Err(io::Error::other(format!(
            "--serialization {serialization} requires --format common"
        )));
    }
    let destination = match serialization {
        Serialization::Discard => Destination::Null,
        _ => config.destination(),
    };
    if serialization == Serialization::Parquet && matches!(destination, Destination::Stdout) {
        return Err(io::Error::other(
            "--serialization parquet requires --output <FILE>",
        ));
    }
    let mut sink =
        RotatingSink::open(serialization, destination, enriched_fields, metrics.clone())?;
    if let Some(command) = &config.exec {
        sink = sink.with_hook(FileHook::spawn(command, metrics)?);
    }
    Ok(sink)
}
