//! Composition: pick the table for the configured format, parse keys, and
//! build a complete table from one source file.
use crate::config::{CsvLookup, EnrichmentConfig, SourceFormat};
use crate::formats::{csv, mmdb};
use crate::lookup::{ExactTable, Lookup, PrefixTable, Schema, parse_prefix};
use crate::{Error, Result};

/// Read the whole source and return the finished table. Any invalid record
/// fails the load, and the error names the source path.
pub fn load(config: &EnrichmentConfig) -> Result<Box<dyn Lookup>> {
    build(config).map_err(|error| Error::Load {
        path: config.source().to_owned(),
        error: Box::new(error),
    })
}

fn build(config: &EnrichmentConfig) -> Result<Box<dyn Lookup>> {
    let source = config.source();
    let schema = Schema::new(config.columns());

    Ok(match config.format() {
        SourceFormat::Csv(CsvLookup::Exact {
            key_column,
            key_type,
        }) => {
            let mut table = ExactTable::default();
            csv::read(source, key_column, &schema, |key, row| {
                table.insert(key_type.parse(key)?, row);
                Ok(())
            })?;
            Box::new(table)
        }
        SourceFormat::Csv(CsvLookup::Prefix { prefix_column }) => {
            let mut table = PrefixTable::default();
            csv::read(source, prefix_column, &schema, |key, row| {
                table.insert(parse_prefix(key)?, row);
                Ok(())
            })?;
            Box::new(table)
        }
        SourceFormat::Mmdb => {
            let mut table = PrefixTable::default();
            mmdb::read(source, &schema, |network, row| {
                table.insert(network, row);
                Ok(())
            })?;
            Box::new(table)
        }
    })
}
