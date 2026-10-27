pub mod destination;
pub mod encoder;
pub mod expire;
pub mod hook;
pub mod layout;
pub mod metrics;
pub mod pipeline;
pub mod rotating;

use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fmt, io};

use clap::ValueEnum;
pub use destination::{Destination, LEVEL_3_MINUTES, MAX_PARTITION_LEVEL, Partitioning};
pub use encoder::{ArrowIpc, Csv, Discard, Encoder, Ndjson, Parquet, Protobuf, Writer};
pub use expire::{Expirer, Expiry};
pub use hook::FileHook;
pub use layout::Layout;
pub use metrics::OutputMetrics;
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
    /// Snappy-compressed Apache Parquet; on stdout, an Arrow IPC stream
    Parquet,
    /// Apache Arrow IPC stream, a batch per flush
    ArrowIpc,
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
            Self::ArrowIpc => "arrows",
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
            Self::ArrowIpc => Box::new(ArrowIpc::open(out, enriched_fields)?),
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
                root: root.clone(),
                level: self.level.min(MAX_PARTITION_LEVEL),
                partitioning: self.partitioning,
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
    if let Some(interval) = config.interval {
        check_interval(interval, config.level)?;
    }
    if config.partitioning == Partitioning::Hive && config.level == 0 {
        return Err(io::Error::other("--hive needs --level 1, 2 or 3"));
    }
    if let (Some(expire), Some(interval)) = (config.expire, config.interval)
        && expire < interval
    {
        // A file is never removed while its -x command may still be using it.
        return Err(io::Error::other(
            "--expire must be at least as long as --interval",
        ));
    }
    let destination = match serialization {
        Serialization::Discard => Destination::Null,
        _ => config.destination(),
    };
    let serialization = match (serialization, &destination) {
        (Serialization::Parquet, Destination::Stdout) => {
            eprintln!("Parquet cannot stream to stdout; writing an Arrow IPC stream instead");
            Serialization::ArrowIpc
        }
        (serialization, _) => serialization,
    };
    let expiry = match (config.expire, &destination) {
        (
            Some(max_age),
            Destination::Partitioned {
                root,
                prefix,
                partitioning,
                ..
            },
        ) => Some(Expiry {
            layout: Layout {
                root: root.clone(),
                prefix: prefix.clone(),
                extension: serialization.extension().into(),
                partitioning: *partitioning,
            },
            max_age,
            hook: match &config.expire_exec {
                Some(command) => Some(FileHook::spawn("--expire-exec", command, root, metrics)?),
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

/// A window must be whole seconds and sit inside one partition directory,
/// so the directory means what it says: every file under hour 13 holds
/// flows received in hour 13. That takes an interval dividing the
/// directory's period.
fn check_interval(interval: Duration, level: u8) -> io::Result<()> {
    if interval.is_zero() || interval.subsec_nanos() != 0 {
        return Err(io::Error::other("--interval must be whole seconds"));
    }
    let (period, name) = match level {
        0 => return Ok(()),
        1 => (86400, "a day"),
        2 => (3600, "an hour"),
        _ => (u64::from(LEVEL_3_MINUTES) * 60, "5 minutes"),
    };
    if !period.is_multiple_of(interval.as_secs()) {
        return Err(io::Error::other(format!(
            "--interval must divide {name} at --level {level}, e.g. {}",
            examples(period)
        )));
    }
    Ok(())
}

/// A few intervals dividing `period`, largest first.
fn examples(period: u64) -> String {
    [3600, 1800, 600, 300, 60, 30, 10]
        .into_iter()
        .filter(|candidate| period.is_multiple_of(*candidate) && *candidate <= period)
        .take(3)
        .map(|secs| {
            if secs >= 3600 {
                format!("{}h", secs / 3600)
            } else if secs >= 60 {
                format!("{}m", secs / 60)
            } else {
                format!("{secs}s")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
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
    fn intervals_must_fit_their_partition() {
        let s = Duration::from_secs;
        let ok = |interval, level| check_interval(interval, level).is_ok();

        assert!(ok(s(7 * 60), 0));
        assert!(ok(s(7 * 3600), 0));
        assert!(ok(s(8 * 3600), 1));
        assert!(!ok(s(7 * 3600), 1));
        assert!(ok(s(5 * 60), 2));
        assert!(ok(s(3600), 2));
        assert!(!ok(s(7 * 60), 2));
        assert!(!ok(s(2 * 3600), 2));
        assert!(ok(s(60), 3));
        assert!(ok(s(300), 3));
        assert!(!ok(s(120), 3));
        assert!(!ok(s(600), 3));
        assert!(!ok(Duration::from_millis(1500), 0));
        assert!(!ok(Duration::ZERO, 0));

        let error = check_interval(s(7 * 60), 2).unwrap_err().to_string();
        assert_eq!(
            error,
            "--interval must divide an hour at --level 2, e.g. 1h, 30m, 10m"
        );
        let error = check_interval(s(600), 3).unwrap_err().to_string();
        assert_eq!(
            error,
            "--interval must divide 5 minutes at --level 3, e.g. 5m, 1m, 30s"
        );
    }

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
