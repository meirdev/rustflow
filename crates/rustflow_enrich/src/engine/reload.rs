use std::path::Path;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use notify_debouncer_full::notify::{RecommendedWatcher, RecursiveMode};
use notify_debouncer_full::{DebounceEventResult, Debouncer, RecommendedCache, new_debouncer};

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReloadPolicy {
    #[default]
    Never,
    Interval(Duration),
    Watch {
        debounce: Duration,
    },
}

type Watcher = Debouncer<RecommendedWatcher, RecommendedCache>;

pub(crate) enum ReloadEvent {
    Reload,
    WatcherError(String),
}

enum Signal {
    Event(ReloadEvent),
    Stop,
}

pub(crate) struct ReloadDriver {
    policy: ReloadPolicy,
    watcher: Option<Watcher>,
    tx: Sender<Signal>,
    rx: Receiver<Signal>,
}

impl ReloadDriver {
    pub fn new(path: &Path, policy: ReloadPolicy) -> Result<Self> {
        let (tx, rx) = mpsc::channel();

        let watcher = match policy {
            ReloadPolicy::Watch { debounce } => Some(watcher(path, debounce, tx.clone())?),
            _ => None,
        };

        Ok(Self {
            policy,
            watcher,
            tx,
            rx,
        })
    }

    pub fn start(
        self,
        mut callback: impl FnMut(ReloadEvent) + Send + 'static,
    ) -> Result<ReloadGuard> {
        let Self {
            policy,
            watcher,
            tx,
            rx,
        } = self;

        let worker = if policy == ReloadPolicy::Never {
            None
        } else {
            Some(
                thread::Builder::new()
                    .name("enrichment-reload".into())
                    .spawn(move || {
                        while let Some(Signal::Event(event)) = next(policy, &rx) {
                            callback(event);
                        }
                    })?,
            )
        };

        Ok(ReloadGuard {
            watcher,
            tx,
            worker,
        })
    }
}

fn next(policy: ReloadPolicy, rx: &Receiver<Signal>) -> Option<Signal> {
    match policy {
        ReloadPolicy::Interval(duration) => match rx.recv_timeout(duration) {
            Ok(signal) => Some(signal),
            Err(RecvTimeoutError::Timeout) => Some(Signal::Event(ReloadEvent::Reload)),
            Err(RecvTimeoutError::Disconnected) => None,
        },
        _ => rx.recv().ok(),
    }
}

fn watcher(path: &Path, debounce: Duration, tx: Sender<Signal>) -> Result<Watcher> {
    let filename = path
        .file_name()
        .ok_or_else(|| Error::Config("Source must name a file".into()))?;

    // Watch the parent to survive atomic replacement of the source file.
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent.canonicalize()?;
    let target = parent.join(filename);

    let mut watcher = new_debouncer(debounce, None, move |result: DebounceEventResult| {
        let event = match result {
            Ok(events) => {
                let relevant = events.iter().any(|event| {
                    event.need_rescan()
                        || ((event.kind.is_create()
                            || event.kind.is_modify()
                            || event.kind.is_remove())
                            && event.paths.iter().any(|path| path == &target))
                });
                if !relevant {
                    return;
                }
                ReloadEvent::Reload
            }
            Err(errors) => ReloadEvent::WatcherError(
                errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
        };

        let _ = tx.send(Signal::Event(event));
    })?;

    watcher.watch(&parent, RecursiveMode::NonRecursive)?;

    Ok(watcher)
}

pub(crate) struct ReloadGuard {
    watcher: Option<Watcher>,
    tx: Sender<Signal>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for ReloadGuard {
    fn drop(&mut self) {
        // Stop producing events before stopping the consumer.
        self.watcher.take();
        let _ = self.tx.send(Signal::Stop);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
