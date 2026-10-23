//! `--expire`: removes rotated files older than a given age.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use std::{fs, io};

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};

use super::OutputMetrics;
use super::destination::{MAX_PARTITION_DEPTH, STAMP_FORMAT, STAMP_LEN};

/// Which files in an output tree are old enough to go.
///
/// Only files this collector could have written are considered: those
/// named `<prefix>-<stamp>[-N].<extension>`, plus the temporary files a
/// crash leaves behind, in the root or in partition directories. Age is
/// taken from the stamp in the name, not from the file system. Partition
/// directories left empty are removed too; the root never is.
pub struct Expiry {
    pub root: PathBuf,
    pub prefix: String,
    pub extension: String,
    pub max_age: Duration,
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub removed: u64,
    pub failures: u64,
    /// The first removal that failed.
    pub first_failure: Option<(PathBuf, io::Error)>,
}

impl Expiry {
    /// Removes every file whose window started before `now - max_age`.
    pub fn run(&self, now: DateTime<Utc>) -> Outcome {
        let cutoff = now.timestamp() - self.max_age.as_secs() as i64;
        let mut outcome = Outcome::default();
        self.sweep(&self.root, 0, cutoff, &mut outcome);
        outcome
    }

    fn sweep(&self, dir: &Path, depth: usize, cutoff: i64, outcome: &mut Outcome) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let path = entry.path();
            if kind.is_dir() {
                // A partition directory whose period started after the
                // cutoff holds nothing old enough.
                if depth < MAX_PARTITION_DEPTH
                    && let Some(start) = period_start(dir, &self.root, &name)
                    && start < cutoff
                {
                    self.sweep(&path, depth + 1, cutoff, outcome);
                    // Only an emptied directory goes; anything else fails
                    // here and is meant to.
                    let _ = fs::remove_dir(&path);
                }
            } else if kind.is_file()
                && let Some(window) = window_of(&name, &self.prefix, &self.extension)
                && window.timestamp() < cutoff
            {
                match fs::remove_file(&path) {
                    Ok(()) => outcome.removed += 1,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        outcome.failures += 1;
                        outcome.first_failure.get_or_insert((path, error));
                    }
                }
            }
        }
    }
}

/// When the period of partition directory `name` under `parent` starts,
/// as a Unix timestamp, or `None` when the name is not a partition.
fn period_start(parent: &Path, root: &Path, name: &str) -> Option<i64> {
    let parts: Vec<u32> = parent
        .strip_prefix(root)
        .ok()?
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .chain(std::iter::once(name.to_owned()))
        .enumerate()
        .map(|(depth, name)| partition_number(&name, depth))
        .collect::<Option<_>>()?;
    let part = |i: usize, default: u32| parts.get(i).copied().unwrap_or(default);
    let year = i32::try_from(part(0, 1970)).ok()?;
    Utc.with_ymd_and_hms(year, part(1, 1), part(2, 1), part(3, 0), part(4, 0), 0)
        .single()
        .map(|start| start.timestamp())
}

/// A partition directory is a four-digit year at the top, then a two-digit
/// month, day, hour or minute.
fn partition_number(name: &str, depth: usize) -> Option<u32> {
    let width = if depth == 0 { 4 } else { 2 };
    if name.len() != width || !name.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    name.parse().ok()
}

/// The window stamp in the name of a file this collector wrote:
/// `<prefix>-<stamp>[-N].<extension>`, or the temporary form
/// `.<name>.<pid>.tmp`.
fn window_of(name: &str, prefix: &str, extension: &str) -> Option<DateTime<Utc>> {
    let name = match name.strip_prefix('.').and_then(|n| n.strip_suffix(".tmp")) {
        Some(tmp) => {
            let (name, pid) = tmp.rsplit_once('.')?;
            if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            name
        }
        None => name,
    };
    let middle = name
        .strip_prefix(prefix)?
        .strip_prefix('-')?
        .strip_suffix(extension)?
        .strip_suffix('.')?;
    let (stamp, rest) = middle.split_at_checked(STAMP_LEN)?;
    if let Some(n) = rest.strip_prefix('-') {
        if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    } else if !rest.is_empty() {
        return None;
    }
    NaiveDateTime::parse_from_str(stamp, STAMP_FORMAT)
        .ok()
        .map(|stamp| stamp.and_utc())
}

/// Runs an [`Expiry`] on its own thread: once right away, then at every
/// interval.
pub struct Expirer {
    _tx: Sender<()>,
    worker: JoinHandle<()>,
}

impl Expirer {
    pub fn spawn(expiry: Expiry, every: Duration, metrics: &OutputMetrics) -> io::Result<Self> {
        let metrics = metrics.clone();
        let (tx, rx) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("expire".into())
            .spawn(move || run(&expiry, every, &metrics, rx))?;
        Ok(Self { _tx: tx, worker })
    }

    /// Lets a sweep in progress complete, then stops.
    pub fn finish(self) {
        drop(self._tx);
        let _ = self.worker.join();
    }
}

fn run(expiry: &Expiry, every: Duration, metrics: &OutputMetrics, rx: Receiver<()>) {
    loop {
        let outcome = expiry.run(Utc::now());
        metrics.expired_files.inc_by(outcome.removed);
        metrics.expire_errors.inc_by(outcome.failures);
        if outcome.removed > 0 {
            eprintln!(
                "Removed {} expired files under {}",
                outcome.removed,
                expiry.root.display()
            );
        }
        if let Some((path, error)) = &outcome.first_failure {
            eprintln!(
                "Could not remove {} expired files under {}; first: {}: {error}",
                outcome.failures,
                expiry.root.display(),
                path.display()
            );
        }
        // Nothing is ever sent; the channel closing is the stop signal.
        match rx.recv_timeout(every) {
            Err(RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;
    use crate::sink::destination::partition_path;

    fn stamp(s: &str) -> DateTime<Utc> {
        NaiveDateTime::parse_from_str(s, STAMP_FORMAT)
            .unwrap()
            .and_utc()
    }

    #[test]
    fn names_of_own_files_carry_their_window() {
        let window = |name: &str| window_of(name, "flows", "parquet").map(|w| w.timestamp());
        let t = stamp("20260820T120000Z").timestamp();

        assert_eq!(window("flows-20260820T120000Z.parquet"), Some(t));
        assert_eq!(window("flows-20260820T120000Z-3.parquet"), Some(t));
        assert_eq!(window(".flows-20260820T120000Z.parquet.4242.tmp"), Some(t));
        assert_eq!(
            window(".flows-20260820T120000Z-1.parquet.4242.tmp"),
            Some(t)
        );

        assert_eq!(window("flows-20260820T120000Z.ndjson"), None);
        assert_eq!(window("netflow-20260820T120000Z.parquet"), None);
        assert_eq!(window("flows-20260820T120000Z-x.parquet"), None);
        assert_eq!(window("flows-20260820T120000Z-.parquet"), None);
        assert_eq!(window("flows-2026082T120000Z.parquet"), None);
        assert_eq!(window("flows-20261320T120000Z.parquet"), None);
        assert_eq!(window(".flows-20260820T120000Z.parquet.tmp"), None);
        assert_eq!(window(".flows-20260820T120000Z.parquet.pid.tmp"), None);
        assert_eq!(window("notes.txt"), None);
        assert_eq!(window("flows-"), None);
    }

    #[test]
    fn partition_periods_start_at_their_first_second() {
        let root = Path::new("/out");
        assert_eq!(
            period_start(root, root, "2026"),
            Some(stamp("20260101T000000Z").timestamp())
        );
        assert_eq!(
            period_start(&root.join("2026/08/20"), root, "12"),
            Some(stamp("20260820T120000Z").timestamp())
        );
        assert_eq!(
            period_start(&root.join("2026/08/20/12"), root, "35"),
            Some(stamp("20260820T123500Z").timestamp())
        );
        assert_eq!(period_start(root, root, "archive"), None);
        assert_eq!(period_start(root, root, "26"), None);
        assert_eq!(period_start(&root.join("2026"), root, "2026"), None);
        assert_eq!(period_start(&root.join("2026"), root, "13"), None);
    }

    #[test]
    fn old_own_files_go_and_everything_else_stays() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let touch = |path: PathBuf| {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            File::create(&path).unwrap();
            path
        };
        let own = |level: u8, s: &str| partition_path(root, level, "flows", "parquet", stamp(s));

        let old = [
            touch(own(0, "20260801T000000Z")),
            touch(own(2, "20260810T120000Z")),
            touch(own(2, "20260810T120500Z")),
            touch(own(3, "20260812T120500Z")),
            touch(own(1, "20260815T000000Z").with_file_name("flows-20260815T000000Z-1.parquet")),
            touch(root.join(".flows-20260815T000000Z.parquet.999.tmp")),
        ];
        let kept = [
            touch(own(0, "20260819T130000Z")),
            touch(own(2, "20260820T110000Z")),
            touch(own(2, "20260820T120000Z")),
            touch(root.join("2026/08/10/12/netflow-20260810T120000Z.parquet")),
            touch(root.join("2026/08/10/12/flows-20260810T120000Z.csv")),
            touch(root.join("2026/08/10/notes.txt")),
            touch(root.join("archive/flows-20260801T000000Z.parquet")),
        ];

        let expiry = Expiry {
            root: root.to_path_buf(),
            prefix: "flows".into(),
            extension: "parquet".into(),
            max_age: Duration::from_secs(24 * 3600),
        };
        let outcome = expiry.run(stamp("20260820T123000Z"));

        assert_eq!(outcome.removed, old.len() as u64, "{outcome:?}");
        assert_eq!(outcome.failures, 0);
        for path in &old {
            assert!(!path.exists(), "{}", path.display());
        }
        for path in &kept {
            assert!(path.exists(), "{}", path.display());
        }
        // Emptied partition directories are gone, the rest remain.
        assert!(!root.join("2026/08/12").exists());
        assert!(!root.join("2026/08/15").exists());
        assert!(root.join("2026/08/10/12").exists());
        assert!(root.join("2026/08/20/11").exists());
        assert!(root.exists());

        // A second sweep finds nothing.
        let again = expiry.run(stamp("20260820T123000Z"));
        assert_eq!((again.removed, again.failures), (0, 0));
    }

    #[test]
    fn files_at_the_cutoff_stay() {
        let dir = tempfile::tempdir().unwrap();
        let at = dir.path().join("flows-20260820T110000Z.parquet");
        let before = dir.path().join("flows-20260820T105959Z.parquet");
        File::create(&at).unwrap();
        File::create(&before).unwrap();

        let expiry = Expiry {
            root: dir.path().to_path_buf(),
            prefix: "flows".into(),
            extension: "parquet".into(),
            max_age: Duration::from_secs(3600),
        };
        let outcome = expiry.run(stamp("20260820T120000Z"));

        assert_eq!(outcome.removed, 1);
        assert!(at.exists());
        assert!(!before.exists());
    }

    #[test]
    fn a_missing_root_is_not_an_error() {
        let expiry = Expiry {
            root: PathBuf::from("/nonexistent/rustflow-output"),
            prefix: "flows".into(),
            extension: "parquet".into(),
            max_age: Duration::from_secs(3600),
        };
        let outcome = expiry.run(Utc::now());
        assert_eq!((outcome.removed, outcome.failures), (0, 0));
    }
}
