//! Reload scheduling owns its resources; dropping the guard stops and joins the
//! worker.
use std::path::Path;
use std::str::FromStr;
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

/// Parses `never`, `watch` (250ms debounce), or a duration such as `30s`.
/// Durations below 1ms are rejected here because the reload worker would spin;
/// programmatic construction is not checked.
impl FromStr for ReloadPolicy {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Ok(match value {
            "never" => Self::Never,
            "watch" => Self::Watch {
                debounce: Duration::from_millis(250),
            },
            _ => {
                let interval = duration_str::parse(value).map_err(|e| {
                    Error::Config(format!("Invalid reload duration '{value}': {e}"))
                })?;
                if interval < Duration::from_millis(1) {
                    return Err(Error::Config(format!(
                        "Reload interval '{value}' must be at least 1ms"
                    )));
                }
                Self::Interval(interval)
            }
        })
    }
}
type Watcher = Debouncer<RecommendedWatcher, RecommendedCache>;

/// What the reload worker hands to its callback.
pub(crate) enum ReloadEvent {
    Reload,
    WatcherError(String),
}

enum Signal {
    Event(ReloadEvent),
    Stop,
}

/// Register before the initial load so changes during loading remain queued.
pub(crate) struct ReloadDriver {
    policy: ReloadPolicy,
    watcher: Option<Watcher>,
    tx: Sender<Signal>,
    rx: Receiver<Signal>,
}

impl ReloadDriver {
    pub fn new(path: &Path, policy: ReloadPolicy) -> Result<Self> {
        let (tx, rx) = mpsc::channel();
        let watcher = if let ReloadPolicy::Watch { debounce } = policy {
            // Watch the parent to survive atomic replacement of the source file.
            let filename = path
                .file_name()
                .ok_or_else(|| Error::Config("Source must name a file".into()))?;
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let parent = parent.canonicalize()?;
            let target = parent.join(filename);
            let callback_tx = tx.clone();
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
                let _ = callback_tx.send(Signal::Event(event));
            })?;
            watcher.watch(&parent, RecursiveMode::NonRecursive)?;
            Some(watcher)
        } else {
            None
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
                        loop {
                            let signal = match policy {
                                ReloadPolicy::Interval(duration) => match rx.recv_timeout(duration)
                                {
                                    Ok(signal) => signal,
                                    Err(RecvTimeoutError::Timeout) => {
                                        Signal::Event(ReloadEvent::Reload)
                                    }
                                    Err(RecvTimeoutError::Disconnected) => break,
                                },
                                _ => match rx.recv() {
                                    Ok(signal) => signal,
                                    Err(_) => break,
                                },
                            };
                            match signal {
                                Signal::Stop => break,
                                Signal::Event(event) => callback(event),
                            }
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
