pub mod csv;
pub mod exact;
pub mod mmdb;
pub mod prefix;

pub use exact::ExactTable;
pub use mmdb::MmdbSource;
pub use prefix::PrefixTable;

use crate::enrich::config::{SourceConfig, SourceFormat};
use crate::enrich::key::Key;
use crate::enrich::row::{Row, Schema};
use crate::enrich::{Error, Result};

pub trait Source: Send + Sync {
    fn lookup(&self, key: Key<'_>) -> Option<Row>;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub fn open(config: &SourceConfig) -> Result<Box<dyn Source>> {
    let schema = Schema::new(config.columns());

    let source = match config.format() {
        SourceFormat::Csv { key_column, lookup } => {
            csv::open(config.source(), key_column, *lookup, &schema)
        }
        SourceFormat::Mmdb => MmdbSource::open(config.source(), &schema).map(|s| Box::new(s) as _),
    };

    source.map_err(|error| Error::Load {
        path: config.source().to_owned(),
        error: Box::new(error),
    })
}
