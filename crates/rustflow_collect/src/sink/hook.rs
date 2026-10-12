use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use chrono::{DateTime, Utc};

use super::OutputMetrics;
use super::destination::STAMP_FORMAT;

/// Commands running at once; the rest wait in order.
const MAX_RUNNING: usize = 8;

/// How often running commands are checked for completion.
const POLL: Duration = Duration::from_millis(250);

/// A completed file: what the `-x` command is told about.
pub struct Job {
    pub path: PathBuf,
    /// Start of the file's window, as in its name.
    pub window: DateTime<Utc>,
}

/// Runs the `-x` command for every completed file. One thread
/// starts the commands and reaps them; the commands themselves run as
/// child processes, up to [`MAX_RUNNING`] at a time.
pub struct FileHook {
    tx: Sender<Job>,
    worker: JoinHandle<()>,
}

impl FileHook {
    /// `command` is split on whitespace. `%f` is the file, `%p` its path
    /// relative to `root`, `%t` the window start as in the file name, `%u`
    /// the same as Unix time, `%%` a percent sign. Without a placeholder
    /// the file is appended.
    pub fn spawn(command: &str, root: &Path, metrics: &OutputMetrics) -> io::Result<Self> {
        let words: Vec<String> = command.split_whitespace().map(String::from).collect();
        if words.is_empty() {
            return Err(io::Error::other("-x command is empty"));
        }
        for word in &words {
            check_placeholders(word)?;
        }
        let metrics = metrics.clone();
        let root = root.to_path_buf();
        let (tx, rx) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("exec".into())
            .spawn(move || Launcher::new(words, root, metrics).run(rx))?;
        Ok(Self { tx, worker })
    }

    pub fn run(&self, job: Job) {
        // The worker outlives every sender, so this cannot fail.
        let _ = self.tx.send(job);
    }

    /// Waits for every queued and running command to complete.
    pub fn finish(self) {
        drop(self.tx);
        let _ = self.worker.join();
    }
}

fn check_placeholders(word: &str) -> io::Result<()> {
    let mut chars = word.chars();
    while let Some(c) = chars.next() {
        if c == '%' && !matches!(chars.next(), Some('f' | 'p' | 't' | 'u' | '%')) {
            return Err(io::Error::other(format!(
                "-x: unknown placeholder in '{word}', use %f, %p, %t, %u or %%"
            )));
        }
    }
    Ok(())
}

struct Launcher {
    words: Vec<String>,
    root: PathBuf,
    metrics: OutputMetrics,
    pending: VecDeque<Job>,
    running: Vec<(Child, PathBuf)>,
}

impl Launcher {
    fn new(words: Vec<String>, root: PathBuf, metrics: OutputMetrics) -> Self {
        Self {
            words,
            root,
            metrics,
            pending: VecDeque::new(),
            running: Vec::new(),
        }
    }

    fn run(mut self, rx: Receiver<Job>) {
        loop {
            match rx.recv_timeout(POLL) {
                Ok(job) => self.pending.push_back(job),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            self.reap();
            self.start_pending();
        }
        // Shutdown: everything queued still runs, and we wait for it all.
        while !self.pending.is_empty() || !self.running.is_empty() {
            self.start_pending();
            self.reap();
            thread::sleep(POLL);
        }
    }

    fn start_pending(&mut self) {
        while self.running.len() < MAX_RUNNING {
            let Some(job) = self.pending.pop_front() else {
                break;
            };
            let args = self.arguments(&job);
            match Command::new(&args[0]).args(&args[1..]).spawn() {
                Ok(child) => {
                    self.metrics.hook_running.inc();
                    self.running.push((child, job.path));
                }
                Err(e) => {
                    eprintln!(
                        "-x {} could not run for {}: {e}",
                        args[0],
                        job.path.display()
                    );
                    self.metrics.hook_errors.inc();
                }
            }
        }
    }

    /// Accounts for the commands that have exited since the last call.
    fn reap(&mut self) {
        let metrics = &self.metrics;
        self.running
            .retain_mut(|(child, path)| match child.try_wait() {
                Ok(None) => true,
                Ok(Some(status)) => {
                    metrics.hook_running.dec();
                    if status.success() {
                        metrics.hook_completed.inc();
                    } else {
                        eprintln!("-x failed for {}: {status}", path.display());
                        metrics.hook_errors.inc();
                    }
                    false
                }
                Err(e) => {
                    metrics.hook_running.dec();
                    eprintln!("-x lost for {}: {e}", path.display());
                    metrics.hook_errors.inc();
                    false
                }
            });
    }

    fn arguments(&self, job: &Job) -> Vec<String> {
        let mut args: Vec<String> = self
            .words
            .iter()
            .map(|w| expand(w, job, &self.root))
            .collect();
        if !self.words.iter().any(|w| w.contains('%')) {
            args.push(job.path.display().to_string());
        }
        args
    }
}

fn expand(word: &str, job: &Job, root: &Path) -> String {
    let mut out = String::with_capacity(word.len());
    let mut chars = word.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('f') => out.push_str(&job.path.display().to_string()),
            Some('p') => {
                let relative = job.path.strip_prefix(root).unwrap_or(&job.path);
                out.push_str(&relative.display().to_string());
            }
            Some('t') => out.push_str(&job.window.format(STAMP_FORMAT).to_string()),
            Some('u') => out.push_str(&job.window.timestamp().to_string()),
            _ => out.push('%'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_expand_per_file() {
        let job = Job {
            path: PathBuf::from("out/2026/08/27/12/flows-20260827T120000Z.parquet"),
            window: DateTime::from_timestamp(1_787_832_000, 0).unwrap(),
        };
        let root = Path::new("out");
        assert_eq!(
            expand("s3://bucket/flows/%p", &job, root),
            "s3://bucket/flows/2026/08/27/12/flows-20260827T120000Z.parquet"
        );
        assert_eq!(
            expand("%f", &job, root),
            "out/2026/08/27/12/flows-20260827T120000Z.parquet"
        );
        assert_eq!(
            expand("%t-%u-100%%", &job, root),
            "20260827T120000Z-1787832000-100%"
        );

        let flat = Job {
            path: PathBuf::from("out/flows-20260827T120000Z.parquet"),
            window: job.window,
        };
        assert_eq!(expand("%p", &flat, root), "flows-20260827T120000Z.parquet");
        assert_eq!(
            expand("%p", &flat, Path::new("elsewhere")),
            "out/flows-20260827T120000Z.parquet"
        );
    }

    #[test]
    fn unknown_placeholders_are_rejected() {
        assert!(check_placeholders("%p").is_ok());
        assert!(check_placeholders("%%").is_ok());
        assert!(check_placeholders("%x").is_err());
        assert!(check_placeholders("50%").is_err());
    }
}
