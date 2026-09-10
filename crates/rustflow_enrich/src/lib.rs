pub mod config;
pub mod engine;
pub mod key;
pub mod row;
pub mod source;

pub use config::{CsvLookup, EnrichmentConfig, SourceFormat, parse_enrich_arg};
pub use engine::{Enrichment, LoadStats, LookupSnapshot, ReloadPolicy};
pub use key::{Key, KeyType};
pub use row::{Row, Schema};
pub use source::{ExactTable, MmdbSource, PrefixTable, Source};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid enrichment configuration: {0}")]
    Config(String),
    #[error("Invalid source data: {0}")]
    Data(String),
    #[error("Failed to load {}: {error}", path.display())]
    Load {
        path: std::path::PathBuf,
        #[source]
        error: Box<Error>,
    },
    #[error("Watcher error: {0}")]
    Watcher(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Csv(#[from] ::csv::Error),
    #[error(transparent)]
    Mmdb(#[from] maxminddb::MaxMindDbError),
    #[error(transparent)]
    Notify(#[from] notify_debouncer_full::notify::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
