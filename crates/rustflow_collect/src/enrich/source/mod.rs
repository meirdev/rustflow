pub mod command;
pub mod csv;
pub mod exact;
pub mod mmdb;
pub mod prefix;

use std::fs::File;
use std::process::Command;
use std::sync::atomic::AtomicBool;

pub use exact::ExactTable;
pub use mmdb::MmdbSource;
pub use prefix::PrefixTable;

use crate::enrich::config::{Origin, SourceConfig, SourceFormat};
use crate::enrich::key::Key;
use crate::enrich::row::{Row, Schema};
use crate::enrich::{Error, Result};

pub trait Source: Send + Sync {
    fn lookup(&self, key: &[Key]) -> Option<Row>;

    fn len(&self) -> usize;
}

/// Loads the source. Setting `cancel` gives up on a command still running.
pub fn open(config: &SourceConfig, cancel: &AtomicBool) -> Result<Box<dyn Source>> {
    load(config, cancel).map_err(|error| Error::Load {
        path: config.source().to_owned(),
        error: Box::new(error),
    })
}

fn load(config: &SourceConfig, cancel: &AtomicBool) -> Result<Box<dyn Source>> {
    let schema = Schema::new(config.columns());

    match (config.format(), config.origin()) {
        (
            SourceFormat::Csv {
                key_columns,
                lookup,
            },
            Origin::File(path),
        ) => csv::open(File::open(path)?, key_columns, lookup, &schema),
        (
            SourceFormat::Csv {
                key_columns,
                lookup,
            },
            Origin::Command { program, timeout },
        ) => command::read(Command::new(program), *timeout, cancel, |output| {
            let source = csv::open(output, key_columns, lookup, &schema)?;
            // A script that ignores a failed step still exits successfully,
            // and would replace a good table with an empty one.
            if source.len() == 0 {
                return Err(Error::Data("Command printed no rows".into()));
            }
            Ok(source)
        }),
        (SourceFormat::Mmdb, Origin::File(path)) => Ok(Box::new(MmdbSource::open(path, &schema)?)),
        (SourceFormat::Mmdb, Origin::Command { .. }) => {
            Err(Error::Config("A command supports only CSV".into()))
        }
    }
}
