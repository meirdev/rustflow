use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Timelike, Utc};

pub const MAX_PARTITION_LEVEL: u8 = 3;

/// Directory resolution, in minutes, of the deepest partitioning level.
const LEVEL_3_MINUTES: u32 = 5;

/// The window start as it appears in a rotated file's name.
pub const STAMP_FORMAT: &str = "%Y%m%dT%H%M%SZ";

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
/// glob-visible name once it is complete, or when it is dropped, so a
/// panic on the writing thread does not hide the file.
///
/// The final name is never taken from an existing file: a restart inside
/// an interval window, or two collectors sharing a tree, produce
/// `flows-X-1.parquet`, `flows-X-2.parquet`, ... next to `flows-X.parquet`.
#[derive(Debug)]
pub struct PendingRename {
    tmp: PathBuf,
    final_path: PathBuf,
    /// Start of the window the file holds.
    window: DateTime<Utc>,
    committed: bool,
}

impl PendingRename {
    /// Returns the name the file ended up with.
    pub fn commit(mut self) -> io::Result<PathBuf> {
        self.committed = true;
        self.claim()
    }

    fn claim(&self) -> io::Result<PathBuf> {
        claim_final_name(&self.tmp, &self.final_path).map_err(|e| {
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

    pub fn window(&self) -> DateTime<Utc> {
        self.window
    }
}

impl Drop for PendingRename {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.claim();
        }
    }
}

/// How many `-N` suffixes to try before giving up on a window.
const MAX_NAME_ATTEMPTS: u32 = 1000;

/// Moves `tmp` to `wanted`, or to the first free `wanted-N`, without ever
/// replacing a file. A hard link fails when the target exists, unlike
/// `rename`, which makes the claim atomic. File systems without hard links
/// fall back to a check-then-rename.
fn claim_final_name(tmp: &Path, wanted: &Path) -> io::Result<PathBuf> {
    for candidate in candidates(wanted) {
        match std::fs::hard_link(tmp, &candidate) {
            Ok(()) => {
                std::fs::remove_file(tmp)?;
                return Ok(candidate);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return claim_by_rename(tmp, wanted),
        }
    }
    Err(io::Error::other(format!(
        "no free name after {MAX_NAME_ATTEMPTS} attempts"
    )))
}

fn claim_by_rename(tmp: &Path, wanted: &Path) -> io::Result<PathBuf> {
    for candidate in candidates(wanted) {
        if candidate.exists() {
            continue;
        }
        std::fs::rename(tmp, &candidate)?;
        return Ok(candidate);
    }
    Err(io::Error::other(format!(
        "no free name after {MAX_NAME_ATTEMPTS} attempts"
    )))
}

fn candidates(wanted: &Path) -> impl Iterator<Item = PathBuf> + '_ {
    let stem = wanted
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".to_string());
    let extension = wanted
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();

    std::iter::once(wanted.to_path_buf()).chain(
        (1..MAX_NAME_ATTEMPTS)
            .map(move |n| wanted.with_file_name(format!("{stem}-{n}{extension}"))),
    )
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
                    pending: Some(PendingRename {
                        tmp,
                        final_path,
                        window: stamp,
                        committed: false,
                    }),
                    rotate_at: Some(window_start + interval_secs),
                })
            }
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

/// `flows-X.parquet` is written as `.flows-X.parquet.<pid>.tmp` in the
/// same directory, so the final move is atomic and `*.parquet` globs skip
/// it. The pid keeps two collectors in the same window off each other's
/// temporary file.
fn temp_path(final_path: &Path) -> PathBuf {
    let name = final_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".to_string());

    final_path.with_file_name(format!(".{name}.{}.tmp", std::process::id()))
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
        stamp.format(STAMP_FORMAT),
        extension
    ));
    path
}
