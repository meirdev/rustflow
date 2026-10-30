pub mod destination;
pub mod encoder;
pub mod expire;
pub mod hook;
pub mod layout;
pub mod metrics;
pub mod pipeline;
pub mod rotating;

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use destination::Destination;
pub use encoder::{ArrowIpc, Csv, Discard, Encoder, Ndjson, Parquet, Protobuf, Writer};
pub use expire::{Expirer, Expiry};
pub use hook::FileHook;
pub use layout::{LEVEL_3_MINUTES, Layout, MAX_PARTITION_LEVEL, Partitioning};
use log::warn;
pub use metrics::OutputMetrics;
pub use rotating::RotatingSink;

/// The original packet structure, or the normalized flow.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, strum::Display, strum::IntoStaticStr, strum::VariantArray,
)]
#[strum(serialize_all = "kebab-case")]
pub enum OutputFormat {
    Raw,
    Common,
}

/// How records are written. Displays as its name on the command line.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, strum::Display, strum::IntoStaticStr, strum::VariantArray,
)]
#[strum(serialize_all = "kebab-case")]
pub enum Serialization {
    /// Newline-delimited JSON, one object per line.
    Ndjson,
    Csv,
    /// Snappy-compressed Apache Parquet; on stdout, an Arrow IPC stream.
    Parquet,
    /// Apache Arrow IPC stream, a batch per flush.
    ArrowIpc,
    /// Length-delimited protobuf, see `proto/rustflow.proto`.
    Protobuf,
    /// Decodes and counts flows but writes nothing, for load testing.
    Discard,
}

impl Serialization {
    /// File extension in the partitioned tree.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Ndjson => "ndjson",
            Self::Csv => "csv",
            Self::Parquet => "parquet",
            Self::ArrowIpc => "arrows",
            Self::Protobuf => "pb",
            Self::Discard => "discard",
        }
    }

    /// `--format raw` hands the sink records it serialized itself.
    pub(crate) fn takes_raw(self) -> bool {
        matches!(self, Self::Ndjson | Self::Discard)
    }

    /// Opens the encoder over `out`; the header is written right away.
    pub fn open(self, out: Writer, enriched_fields: &[String]) -> io::Result<Box<dyn Encoder>> {
        Ok(match self {
            Self::Ndjson => Box::new(Ndjson::open(out, enriched_fields)?),
            Self::Csv => Box::new(Csv::open(out, enriched_fields)?),
            Self::Parquet => Box::new(Parquet::open(out, enriched_fields)?),
            Self::ArrowIpc => Box::new(ArrowIpc::open(out, enriched_fields)?),
            Self::Protobuf => Box::new(Protobuf::open(out, enriched_fields)?),
            Self::Discard => Box::new(Discard::open(out, enriched_fields)?),
        })
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
    pub partitioning: Partitioning,
    pub prefix: String,
    pub exec: Option<String>,
    /// Remove rotated files older than this.
    pub expire: Option<Duration>,
    /// Run for every file `expire` removes.
    pub expire_exec: Option<String>,
}

impl SinkConfig {
    fn destination(&self) -> Destination {
        match (&self.path, self.interval) {
            (None, _) => Destination::Stdout,
            (Some(path), None) => Destination::File(path.clone()),
            (Some(root), Some(interval)) => Destination::Partitioned {
                layout: Layout {
                    root: root.clone(),
                    prefix: self.prefix.clone(),
                    extension: self.serialization.extension().into(),
                    level: self.level,
                    partitioning: self.partitioning,
                },
                interval_secs: interval.as_secs() as i64,
            },
        }
    }
}

/// The sink for the CLI flags.
pub fn build(
    config: &SinkConfig,
    enriched_fields: Vec<String>,
    metrics: &OutputMetrics,
) -> io::Result<RotatingSink> {
    let serialization = config.serialization;
    let destination = match serialization {
        Serialization::Discard => Destination::Null,
        _ => config.destination(),
    };
    let serialization = match (serialization, &destination) {
        (Serialization::Parquet, Destination::Stdout) => {
            warn!("Parquet cannot stream to stdout; writing an Arrow IPC stream instead");
            Serialization::ArrowIpc
        }
        (serialization, _) => serialization,
    };
    let expiry = match (config.expire, &destination) {
        (Some(max_age), Destination::Partitioned { layout, .. }) => Some(Expiry {
            layout: layout.clone(),
            max_age,
            hook: match &config.expire_exec {
                Some(command) => Some(FileHook::spawn(
                    "--expire-exec",
                    command,
                    &layout.root,
                    metrics,
                )?),
                None => None,
            },
        }),
        _ => None,
    };
    let mut sink =
        RotatingSink::open(serialization, destination, enriched_fields, metrics.clone())?;
    if let Some(command) = &config.exec {
        let root = config.path.as_deref().unwrap_or(Path::new(""));
        sink = sink.with_hook(FileHook::spawn("-x", command, root, metrics)?);
    }
    if let Some(expiry) = expiry {
        let every = sweep_every(expiry.max_age, config.interval.unwrap_or(expiry.max_age));
        sink = sink.with_expirer(Expirer::spawn(expiry, every, metrics)?);
    }
    Ok(sink)
}

/// The longest an expired file waits for a sweep.
const MAX_SWEEP_GAP: Duration = Duration::from_secs(3600);

/// How often expiry looks for old files.
fn sweep_every(max_age: Duration, interval: Duration) -> Duration {
    (max_age / 100).clamp(interval, MAX_SWEEP_GAP.max(interval))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweeps_follow_the_retention_within_bounds() {
        let s = Duration::from_secs;
        assert_eq!(sweep_every(s(30 * 86400), s(10)), s(3600));
        assert_eq!(sweep_every(s(7 * 86400), s(10)), s(3600));
        assert_eq!(sweep_every(s(86400), s(10)), s(864));
        assert_eq!(sweep_every(s(3600), s(10)), s(36));
        assert_eq!(sweep_every(s(3600), s(60)), s(60));
        assert_eq!(sweep_every(s(2 * 3600), s(2 * 3600)), s(2 * 3600));
    }
}
