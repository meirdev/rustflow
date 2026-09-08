use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Timelike, Utc};

/// Deepest supported directory partitioning level.
pub const MAX_PARTITION_LEVEL: u8 = 3;

/// Directory resolution, in minutes, of the deepest partitioning level.
const LEVEL_3_MINUTES: u32 = 5;

/// Where bytes go. Knows about paths, temporary names, and renames, and
/// nothing about formats.
#[derive(Clone, Debug)]
pub enum Destination {
    Stdout,
    /// A single file that is never rotated.
    File(PathBuf),
    /// A directory tree with one file per interval window, see
    /// [`partition_path`].
    Partitioned {
        root: PathBuf,
        level: u8,
        prefix: String,
        /// Rotation interval in whole seconds, at least 1.
        interval_secs: i64,
    },
    /// Nowhere; for the discard format.
    Null,
}

/// What [`Destination::open_for`] hands back: where to write, how to
/// commit, and when to rotate.
pub struct Opened {
    pub writer: Box<dyn Write + Send>,
    pub pending: Option<PendingRename>,
    /// Unix timestamp of the next rotation; `None` when never.
    pub rotate_at: Option<i64>,
}

/// A file being written under a temporary name in the rotated tree. Only
/// once it is complete does it get its final, glob-visible name.
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
    /// Open the stream for the window containing `now`.
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
                // Align windows to the epoch so file names land on round
                // boundaries (e.g. the top of every hour for `1h`).
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

    /// Rotation interval, when this destination rotates.
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

/// Temporary name for an in-progress file: `flows-X.parquet` is written as
/// `.flows-X.parquet.tmp` in the same directory (same filesystem, so the
/// final rename is atomic), hidden from `*.parquet` globs by both the dot
/// prefix and the extension.
fn temp_path(final_path: &Path) -> PathBuf {
    let name = final_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".to_string());
    final_path.with_file_name(format!(".{name}.tmp"))
}

/// Build the path of the file holding the interval window starting at
/// `stamp`.
///
/// | Level | Layout                                    |
/// | ----- | ----------------------------------------- |
/// | 0     | `root/`                                   |
/// | 1     | `root/%Y/%m/%d/`                          |
/// | 2     | `root/%Y/%m/%d/%H/`                       |
/// | 3     | `root/%Y/%m/%d/%H/%M/` in 5 minute steps  |
///
/// The file itself is named `<prefix>-<window start>.<extension>`, e.g.
/// `flows-20240102T150500Z.parquet`.
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
        // Floor to the enclosing 5 minute bucket: 00, 05, ... 55.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    /// 2024-01-02T15:07:00Z
    const SAMPLE: i64 = 1_704_208_020;

    #[test]
    fn partition_level_0_writes_flat_into_the_root() {
        let path = partition_path(Path::new("/data"), 0, "flows", "parquet", stamp(SAMPLE));
        assert_eq!(path, PathBuf::from("/data/flows-20240102T150700Z.parquet"));
    }

    #[test]
    fn partition_level_1_is_day_resolution() {
        let path = partition_path(Path::new("/data"), 1, "flows", "ndjson", stamp(SAMPLE));
        assert_eq!(
            path,
            PathBuf::from("/data/2024/01/02/flows-20240102T150700Z.ndjson")
        );
    }

    #[test]
    fn partition_level_2_is_hour_resolution() {
        let path = partition_path(Path::new("/data"), 2, "flows", "csv", stamp(SAMPLE));
        assert_eq!(
            path,
            PathBuf::from("/data/2024/01/02/15/flows-20240102T150700Z.csv")
        );
    }

    #[test]
    fn partition_level_3_floors_to_five_minute_buckets() {
        let path = partition_path(Path::new("/data"), 3, "flows", "parquet", stamp(SAMPLE));
        assert_eq!(
            path,
            PathBuf::from("/data/2024/01/02/15/05/flows-20240102T150700Z.parquet")
        );

        // The top of the hour lands in the `00` bucket.
        let path = partition_path(
            Path::new("/data"),
            3,
            "flows",
            "parquet",
            stamp(SAMPLE - 420),
        );
        assert_eq!(
            path,
            PathBuf::from("/data/2024/01/02/15/00/flows-20240102T150000Z.parquet")
        );
    }

    #[test]
    fn partition_path_honours_the_prefix() {
        let path = partition_path(Path::new("out"), 1, "edge01", "parquet", stamp(SAMPLE));
        assert_eq!(
            path,
            PathBuf::from("out/2024/01/02/edge01-20240102T150700Z.parquet")
        );
    }

    #[test]
    fn temp_name_is_hidden_and_next_to_the_final_file() {
        let tmp = temp_path(Path::new("/data/2024/flows-20240102T150700Z.parquet"));
        assert_eq!(
            tmp,
            PathBuf::from("/data/2024/.flows-20240102T150700Z.parquet.tmp")
        );
    }

    #[test]
    fn partitioned_window_is_aligned_to_the_interval() {
        let root = std::env::temp_dir().join("rustflow_sink_destination_test");
        std::fs::remove_dir_all(&root).ok();
        let dest = Destination::Partitioned {
            root: root.clone(),
            level: 0,
            prefix: "flows".into(),
            interval_secs: 600,
        };

        // 15:07 falls in the 15:00 window, which ends at 15:10.
        let opened = dest.open_for(stamp(SAMPLE), "ndjson").unwrap();
        assert_eq!(opened.rotate_at, Some(SAMPLE - 420 + 600));
        let pending = opened.pending.unwrap();
        assert_eq!(
            pending.final_path(),
            root.join("flows-20240102T150000Z.ndjson")
        );
        assert!(root.join(".flows-20240102T150000Z.ndjson.tmp").exists());
        assert!(!pending.final_path().exists());

        drop(opened.writer);
        pending.commit().unwrap();
        assert!(root.join("flows-20240102T150000Z.ndjson").exists());
        assert!(!root.join(".flows-20240102T150000Z.ndjson.tmp").exists());

        std::fs::remove_dir_all(&root).ok();
    }
}
