//! `--expire`: removes rotated files older than a given age.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use std::{fs, io};

use chrono::{DateTime, Utc};

use super::OutputMetrics;
use super::hook::{FileHook, Job};
use super::layout::Layout;

/// Which files in an output tree are old enough to go.
///
/// Only the tree's own files are considered, temporary files a crash left
/// behind included, and their age is taken from the window stamp in the
/// name, not from the file system. Partition directories left empty are
/// removed too; the root never is.
pub struct Expiry {
    pub layout: Layout,
    pub max_age: Duration,
    /// Told about every complete file removed, after the fact.
    pub hook: Option<FileHook>,
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
        for entry in self.layout.files(..cutoff) {
            match remove_file(&entry.path) {
                Ok(()) => {
                    outcome.removed += 1;
                    // A temporary file was never anyone's to know about.
                    if let (Some(hook), false) = (&self.hook, entry.temporary) {
                        hook.run(Job {
                            path: entry.path,
                            window: entry.window,
                        });
                    }
                }
                Err(error) => {
                    outcome.failures += 1;
                    outcome.first_failure.get_or_insert((entry.path, error));
                }
            }
        }
        // Deepest first, so a directory emptied here can go in turn.
        // Anything but an empty directory fails, as it should.
        for dir in self.layout.dirs(..cutoff) {
            let _ = fs::remove_dir(dir);
        }
        outcome
    }

    /// Waits for the commands still queued for removed files.
    pub fn finish(self) {
        if let Some(hook) = self.hook {
            hook.finish();
        }
    }
}

/// Removes `path`, treating an already missing file as removed.
fn remove_file(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
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
            .spawn(move || run(expiry, every, &metrics, rx))?;
        Ok(Self { _tx: tx, worker })
    }

    /// Lets a sweep in progress complete, then stops.
    pub fn finish(self) {
        drop(self._tx);
        let _ = self.worker.join();
    }
}

fn run(expiry: Expiry, every: Duration, metrics: &OutputMetrics, rx: Receiver<()>) {
    loop {
        let outcome = expiry.run(Utc::now());
        metrics.expired_files.inc_by(outcome.removed);
        metrics.expire_errors.inc_by(outcome.failures);
        if outcome.removed > 0 {
            eprintln!(
                "Removed {} expired files under {}",
                outcome.removed,
                expiry.layout.root.display()
            );
        }
        if let Some((path, error)) = &outcome.first_failure {
            eprintln!(
                "Could not remove {} expired files under {}; first: {}: {error}",
                outcome.failures,
                expiry.layout.root.display(),
                path.display()
            );
        }
        // Nothing is ever sent; the channel closing is the stop signal.
        match rx.recv_timeout(every) {
            Err(RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    expiry.finish();
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;
    use crate::sink::layout::tests::{plain, stamp};

    fn expiry(root: &Path, max_age: Duration) -> Expiry {
        Expiry {
            layout: plain(root),
            max_age,
            hook: None,
        }
    }

    #[test]
    fn the_hook_hears_of_removed_files_but_not_temporary_ones() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let heard = dir.path().join("heard");
        fs::create_dir(&heard).unwrap();
        for name in [
            "flows-20260801T000000Z.parquet",
            "flows-20260802T000000Z.parquet",
            ".flows-20260803T000000Z.parquet.7.tmp",
            "flows-20260820T000000Z.parquet",
        ] {
            File::create(root.join(name)).unwrap();
        }
        let hook = FileHook::spawn(
            "--expire-exec",
            &format!("touch {}/%t", heard.display()),
            root,
            &OutputMetrics::new(),
        )
        .unwrap();
        let mut expiry = expiry(root, Duration::from_secs(86400));
        expiry.hook = Some(hook);

        let outcome = expiry.run(stamp("20260820T120000Z"));
        expiry.finish();

        assert_eq!((outcome.removed, outcome.failures), (3, 0));
        let mut told: Vec<_> = fs::read_dir(&heard)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        told.sort();
        assert_eq!(told, ["20260801T000000Z", "20260802T000000Z"]);
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
        let own = |level: u8, s: &str| {
            Layout {
                level,
                ..plain(root)
            }
            .path_for(stamp(s))
        };

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

        let expiry = expiry(root, Duration::from_secs(24 * 3600));
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

        let expiry = expiry(dir.path(), Duration::from_secs(3600));
        let outcome = expiry.run(stamp("20260820T120000Z"));

        assert_eq!(outcome.removed, 1);
        assert!(at.exists());
        assert!(!before.exists());
    }

    #[test]
    fn a_missing_root_is_not_an_error() {
        let expiry = expiry(
            Path::new("/nonexistent/rustflow-output"),
            Duration::from_secs(3600),
        );
        let outcome = expiry.run(Utc::now());
        assert_eq!((outcome.removed, outcome.failures), (0, 0));
    }
}
