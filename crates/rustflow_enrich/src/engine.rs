//! Orchestration and immutable snapshots. No dependency on collector metrics or
//! output.
use std::sync::{Arc, Mutex, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::SystemTime;

use crate::lookup::{Lookup, Row};
use crate::reload::{ReloadDriver, ReloadEvent, ReloadGuard};
use crate::{EnrichmentConfig, Error, Key, Result, loader};

#[derive(Debug, Clone, Default)]
pub struct LoadStats {
    pub loaded_rows: usize,
    pub successful_loads: u64,
    pub reload_failures: u64,
    pub watcher_failures: u64,
    pub last_success: Option<SystemTime>,
    pub last_error: Option<String>,
}

/// The currently published table and its statistics.
struct State {
    table: Arc<dyn Lookup>,
    stats: LoadStats,
}

struct Shared {
    config: EnrichmentConfig,
    state: RwLock<State>,
    // Serialize explicit and scheduled reloads so older loads cannot replace newer ones.
    loading: Mutex<()>,
}

impl Shared {
    fn state(&self) -> RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn state_mut(&self) -> RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    fn reload(&self) -> Result<usize> {
        let _loading = self.loading.lock().unwrap_or_else(PoisonError::into_inner);
        let loaded = loader::load(&self.config);
        let mut state = self.state_mut();
        match loaded {
            Ok(table) => {
                let count = table.len();
                state.table = Arc::from(table);
                state.stats.loaded_rows = count;
                state.stats.successful_loads += 1;
                state.stats.last_success = Some(SystemTime::now());
                state.stats.last_error = None;
                Ok(count)
            }
            Err(error) => {
                state.stats.reload_failures += 1;
                state.stats.last_error = Some(error.to_string());
                Err(error)
            }
        }
    }

    fn record_watcher_error(&self, message: String) {
        let mut state = self.state_mut();
        state.stats.watcher_failures += 1;
        state.stats.last_error = Some(Error::Watcher(message).to_string());
    }
}

pub struct Enrichment {
    // Guard is owned here, not by Shared: no reference cycle with the worker.
    _reload: ReloadGuard,
    shared: Arc<Shared>,
}

impl Enrichment {
    pub fn new(config: EnrichmentConfig) -> Result<Self> {
        let driver = ReloadDriver::new(config.source(), config.reload())?;
        let table = loader::load(&config)?;
        let stats = LoadStats {
            loaded_rows: table.len(),
            successful_loads: 1,
            last_success: Some(SystemTime::now()),
            ..Default::default()
        };
        let shared = Arc::new(Shared {
            config,
            state: RwLock::new(State {
                table: Arc::from(table),
                stats,
            }),
            loading: Mutex::new(()),
        });
        let worker_shared = Arc::clone(&shared);
        let guard = driver.start(move |event| match event {
            // A failed reload is already recorded in the statistics.
            ReloadEvent::Reload => {
                let _ = worker_shared.reload();
            }
            ReloadEvent::WatcherError(message) => worker_shared.record_watcher_error(message),
        })?;
        Ok(Self {
            _reload: guard,
            shared,
        })
    }

    pub fn config(&self) -> &EnrichmentConfig {
        &self.shared.config
    }

    pub fn reload(&self) -> Result<usize> {
        self.shared.reload()
    }

    pub fn stats(&self) -> LoadStats {
        self.shared.state().stats.clone()
    }

    /// Capture a stable view for multiple lookups while reloads run
    /// concurrently.
    pub fn snapshot(&self) -> LookupSnapshot {
        LookupSnapshot {
            table: Arc::clone(&self.shared.state().table),
        }
    }

    /// Look up one key, returning an owned row. Use `snapshot()` to borrow
    /// rows.
    pub fn lookup(&self, key: Key<'_>) -> Option<Row> {
        self.snapshot().lookup(key).cloned()
    }
}

/// An immutable table view. All lookups through this handle see the same load.
#[derive(Clone)]
pub struct LookupSnapshot {
    table: Arc<dyn Lookup>,
}

impl LookupSnapshot {
    pub fn lookup(&self, key: Key<'_>) -> Option<&Row> {
        self.table.lookup(key)
    }
}
