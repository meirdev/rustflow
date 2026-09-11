use std::collections::HashSet;
use std::path::Path;

use super::{ExactTable, PrefixTable, Source};
use crate::enrich::config::CsvLookup;
use crate::enrich::key::parse_prefix;
use crate::enrich::row::{Row, Schema};
use crate::enrich::{Error, Result};

/// Read the whole file into the table `lookup` asks for, keyed by
/// `key_column`. Only the schema's columns are kept per row.
pub fn open(
    path: &Path,
    key_column: &str,
    lookup: CsvLookup,
    schema: &Schema,
) -> Result<Box<dyn Source>> {
    Ok(match lookup {
        CsvLookup::Exact(key_type) => {
            let mut table = ExactTable::default();
            read(path, key_column, schema, |key, row| {
                table.insert(key_type.parse(key)?.into_owned(), row);
                Ok(())
            })?;
            Box::new(table)
        }
        CsvLookup::Prefix => {
            let mut table = PrefixTable::default();
            read(path, key_column, schema, |key, row| {
                table.insert(parse_prefix(key)?, row);
                Ok(())
            })?;
            Box::new(table)
        }
    })
}

fn read(
    path: &Path,
    key_column: &str,
    schema: &Schema,
    mut emit: impl FnMut(&str, Row) -> Result<()>,
) -> Result<()> {
    let mut reader = ::csv::Reader::from_path(path)?;

    let headers: Vec<_> = reader
        .headers()?
        .iter()
        .map(str::trim)
        .map(str::to_owned)
        .collect();

    let mut seen = HashSet::new();
    if headers.iter().any(|h| h.is_empty() || !seen.insert(h)) {
        return Err(Error::Data(
            "CSV headers must be nonempty and unique".into(),
        ));
    }

    let key_index = headers
        .iter()
        .position(|h| h == key_column)
        .ok_or_else(|| Error::Data(format!("CSV key column '{key_column}' not found")))?;

    let column_indexes = schema
        .columns()
        .iter()
        .map(|column| {
            headers
                .iter()
                .position(|h| h == column)
                .ok_or_else(|| Error::Data(format!("CSV field column '{column}' not found")))
        })
        .collect::<Result<Vec<_>>>()?;

    for (index, result) in reader.records().enumerate() {
        let record = result?;

        let cell = |i: usize| record.get(i).unwrap_or_default().trim();

        let key = cell(key_index);
        if key.is_empty() {
            return Err(Error::Data(format!(
                "Empty CSV key at record {}",
                index + 1
            )));
        }

        let fields = schema.row(column_indexes.iter().map(|&i| {
            let value = cell(i);
            (!value.is_empty()).then(|| value.to_owned())
        }));

        emit(key, fields)?;
    }

    Ok(())
}
