use std::sync::{Arc, Mutex, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod metrics;
pub mod reload;

use metrics::{SourceMetrics, TableMetrics};
pub use reload::ReloadPolicy;
use reload::{ReloadDriver, ReloadEvent, ReloadGuard};

use crate::enrich::{Key, Result, Row, Source, SourceConfig, source};

struct Shared {
    config: SourceConfig,
    source: RwLock<Arc<dyn Source>>,
    // Serialize explicit and scheduled reloads so older loads cannot replace newer ones.
    loading: Mutex<()>,
    metrics: SourceMetrics,
}

impl Shared {
    fn source(&self) -> RwLockReadGuard<'_, Arc<dyn Source>> {
        self.source.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn source_mut(&self) -> RwLockWriteGuard<'_, Arc<dyn Source>> {
        self.source.write().unwrap_or_else(PoisonError::into_inner)
    }

    fn reload(&self) -> Result<usize> {
        let _loading = self.loading.lock().unwrap_or_else(PoisonError::into_inner);
        match source::open(&self.config) {
            Ok(source) => {
                let count = source.len();
                // Swap under the lock, but free the previous source only
                // after readers can proceed again.
                let previous = std::mem::replace(&mut *self.source_mut(), Arc::from(source));
                drop(previous);
                self.record_load(count);
                Ok(count)
            }
            Err(error) => {
                self.metrics.reload_failures_total.inc();
                eprintln!("{error}");
                Err(error)
            }
        }
    }

    fn record_load(&self, count: usize) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        self.metrics.loaded_rows.set(count as i64);
        self.metrics.last_load_timestamp_seconds.set(now);
        self.metrics.loads_total.inc();
    }
}

pub struct Table {
    // Guard is owned here, not by Shared: no reference cycle with the worker.
    _reload: ReloadGuard,
    shared: Arc<Shared>,
}

impl Table {
    pub fn new(config: SourceConfig, metrics: &TableMetrics) -> Result<Self> {
        let driver = ReloadDriver::new(config.source(), config.reload())?;
        let source = source::open(&config)?;
        let shared = Arc::new(Shared {
            metrics: metrics.for_source(&config.source().display().to_string()),
            config,
            source: RwLock::new(Arc::from(source)),
            loading: Mutex::new(()),
        });
        shared.record_load(shared.source().len());
        let worker_shared = Arc::clone(&shared);
        let guard = driver.start(move |event| match event {
            // A failed reload is already counted and reported.
            ReloadEvent::Reload => {
                let _ = worker_shared.reload();
            }
            ReloadEvent::WatcherError(message) => {
                worker_shared.metrics.watcher_failures_total.inc();
                eprintln!(
                    "Watcher error on {}: {message}",
                    worker_shared.config.source().display()
                );
            }
        })?;
        Ok(Self {
            _reload: guard,
            shared,
        })
    }

    pub fn config(&self) -> &SourceConfig {
        &self.shared.config
    }

    pub fn metrics(&self) -> &SourceMetrics {
        &self.shared.metrics
    }

    pub fn len(&self) -> usize {
        self.shared.source().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn reload(&self) -> Result<usize> {
        self.shared.reload()
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            source: Arc::clone(&self.shared.source()),
        }
    }

    pub fn lookup(&self, key: Key<'_>) -> Option<Row> {
        self.snapshot().lookup(key)
    }
}

#[derive(Clone)]
pub struct Snapshot {
    source: Arc<dyn Source>,
}

impl Snapshot {
    pub fn lookup(&self, key: Key<'_>) -> Option<Row> {
        self.source.lookup(key)
    }
}
