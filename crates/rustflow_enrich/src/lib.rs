//! Typed source lookup and reload. Readers, lookup indexes, and reload
//! scheduling are independent.
pub mod config;
pub mod engine;
pub mod formats;
pub mod loader;
pub mod lookup;
pub mod reload;

pub use config::{CsvLookup, EnrichmentConfig, SourceFormat, parse_enrich_arg};
pub use engine::{Enrichment, LoadStats, LookupSnapshot};
pub use lookup::{Key, KeyType, Row, Schema};
pub use reload::ReloadPolicy;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid enrichment configuration: {0}")]
    Config(String),
    #[error("Invalid source data: {0}")]
    Data(String),
    /// A load failed; `error` says why and `path` says which source.
    #[error("Failed to load {}: {error}", path.display())]
    Load {
        path: std::path::PathBuf,
        #[source]
        error: Box<Error>,
    },
    /// The filesystem watcher reported a runtime failure.
    #[error("Watcher error: {0}")]
    Watcher(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Csv(#[from] csv::Error),
    #[error(transparent)]
    Mmdb(#[from] maxminddb::MaxMindDbError),
    #[error(transparent)]
    Notify(#[from] notify_debouncer_full::notify::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
