use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Timelike, Utc};

pub const MAX_PARTITION_LEVEL: u8 = 3;

/// Directory resolution, in minutes, of the deepest partitioning level.
const LEVEL_3_MINUTES: u32 = 5;

/// Where bytes go. Knows about paths, temporary names, and renames, and
/// nothing about formats.
#[derive(Clone, Debug)]
pub enum Destination {
    Stdout,
    File(PathBuf),
    /// One file per interval window, see [`partition_path`].
    Partitioned {
        root: PathBuf,
        level: u8,
        prefix: String,
        interval_secs: i64,
    },
    Null,
}

pub struct Opened {
    pub writer: Box<dyn Write + Send>,
    pub pending: Option<PendingRename>,
    /// Unix timestamp of the next rotation; `None` when never.
    pub rotate_at: Option<i64>,
}

/// A file being written under a temporary name. It gets its final,
/// glob-visible name only once it is complete.
#[must_use = "a pending rename that is dropped leaves a .tmp file behind"]
#[derive(Debug)]
pub struct PendingRename {
    tmp: PathBuf,
    final_path: PathBuf,
}

impl PendingRename {
    pub fn commit(self) -> io::Result<()> {
        std::fs::rename(&self.tmp, &self.final_path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "moving {} to {}: {e}",
                    self.tmp.display(),
                    self.final_path.display()
                ),
            )
        })
    }

    pub fn final_path(&self) -> &Path {
        &self.final_path
    }
}

impl Destination {
    /// Opens the stream for the window containing `now`.
    pub fn open_for(&self, now: DateTime<Utc>, extension: &str) -> io::Result<Opened> {
        match self {
            Destination::Stdout => Ok(Opened {
                writer: Box::new(io::stdout()),
                pending: None,
                rotate_at: None,
            }),
            Destination::Null => Ok(Opened {
                writer: Box::new(io::sink()),
                pending: None,
                rotate_at: None,
            }),
            Destination::File(path) => Ok(Opened {
                writer: Box::new(create(path)?),
                pending: None,
                rotate_at: None,
            }),
            Destination::Partitioned {
                root,
                level,
                prefix,
                interval_secs,
            } => {
                // Windows are aligned to the epoch so file names land on
                // round boundaries, e.g. the top of every hour for `1h`.
                let window_start = now.timestamp().div_euclid(*interval_secs) * interval_secs;
                let stamp = DateTime::from_timestamp(window_start, 0).unwrap_or(now);
                let final_path = partition_path(root, *level, prefix, extension, stamp);
                let tmp = temp_path(&final_path);
                Ok(Opened {
                    writer: Box::new(create(&tmp)?),
                    pending: Some(PendingRename { tmp, final_path }),
                    rotate_at: Some(window_start + interval_secs),
                })
            }
        }
    }

    pub fn interval_secs(&self) -> Option<i64> {
        match self {
            Destination::Partitioned { interval_secs, .. } => Some(*interval_secs),
            _ => None,
        }
    }
}

fn create(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
}

/// `flows-X.parquet` is written as `.flows-X.parquet.tmp` in the same
/// directory, so the final rename is atomic and `*.parquet` globs skip it.
fn temp_path(final_path: &Path) -> PathBuf {
    let name = final_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".to_string());
    final_path.with_file_name(format!(".{name}.tmp"))
}

/// The file holding the interval window starting at `stamp`:
/// `<prefix>-<window start>.<extension>` under the level's directory,
/// `root/`, `root/%Y/%m/%d/`, `root/%Y/%m/%d/%H/`, or
/// `root/%Y/%m/%d/%H/%M/` in 5 minute steps.
pub fn partition_path(
    root: &Path,
    level: u8,
    prefix: &str,
    extension: &str,
    stamp: DateTime<Utc>,
) -> PathBuf {
    let mut path = root.to_path_buf();

    if level >= 1 {
        path.push(stamp.format("%Y").to_string());
        path.push(stamp.format("%m").to_string());
        path.push(stamp.format("%d").to_string());
    }
    if level >= 2 {
        path.push(stamp.format("%H").to_string());
    }
    if level >= 3 {
        path.push(format!(
            "{:02}",
            stamp.minute() / LEVEL_3_MINUTES * LEVEL_3_MINUTES
        ));
    }

    path.push(format!(
        "{}-{}.{}",
        prefix,
        stamp.format("%Y%m%dT%H%M%SZ"),
        extension
    ));
    path
}
