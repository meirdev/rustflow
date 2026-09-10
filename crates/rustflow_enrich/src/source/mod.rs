pub mod csv;
pub mod exact;
pub mod mmdb;
pub mod prefix;

use crate::config::{EnrichmentConfig, SourceFormat};
use crate::key::Key;
use crate::row::{Row, Schema};
use crate::{Error, Result};

pub use exact::ExactTable;
pub use mmdb::MmdbSource;
pub use prefix::PrefixTable;

pub trait Source: Send + Sync {
    fn lookup(&self, key: Key<'_>) -> Option<Row>;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub fn open(config: &EnrichmentConfig) -> Result<Box<dyn Source>> {
    let schema = Schema::new(config.columns());

    let source = match config.format() {
        SourceFormat::Csv(lookup) => csv::open(config.source(), lookup, &schema),
        SourceFormat::Mmdb => MmdbSource::open(config.source(), &schema).map(|s| Box::new(s) as _),
    };

    source.map_err(|error| Error::Load {
        path: config.source().to_owned(),
        error: Box::new(error),
    })
}
