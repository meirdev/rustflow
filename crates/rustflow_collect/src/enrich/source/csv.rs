use std::collections::HashSet;
use std::io::Read;

use super::{ExactTable, PrefixTable, Source};
use crate::enrich::config::CsvLookup;
use crate::enrich::key::parse_prefix;
use crate::enrich::row::{Row, Schema};
use crate::enrich::{Error, Result};

pub fn open(
    input: impl Read,
    key_columns: &[String],
    lookup: &CsvLookup,
    schema: &Schema,
) -> Result<Box<dyn Source>> {
    Ok(match lookup {
        CsvLookup::Exact(key_types) => {
            let mut table = ExactTable::default();
            read(input, key_columns, schema, |keys, row| {
                let key = keys
                    .iter()
                    .zip(key_types)
                    .map(|(key, key_type)| key_type.parse(key))
                    .collect::<Result<_>>()?;
                table.insert(key, row);
                Ok(())
            })?;
            Box::new(table)
        }
        CsvLookup::Prefix => {
            let mut table = PrefixTable::default();
            read(input, key_columns, schema, |keys, row| {
                table.insert(parse_prefix(keys[0])?, row);
                Ok(())
            })?;
            Box::new(table)
        }
    })
}

/// Calls `emit` with the key cells, in `key_columns` order, and the row of
/// every record.
fn read(
    input: impl Read,
    key_columns: &[String],
    schema: &Schema,
    mut emit: impl FnMut(&[&str], Row) -> Result<()>,
) -> Result<()> {
    let mut reader = ::csv::Reader::from_reader(input);

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

    let key_indexes = key_columns
        .iter()
        .map(|column| {
            headers
                .iter()
                .position(|h| h == column)
                .ok_or_else(|| Error::Data(format!("CSV key column '{column}' not found")))
        })
        .collect::<Result<Vec<_>>>()?;

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

        let keys: Vec<_> = key_indexes.iter().map(|&i| cell(i)).collect();
        if keys.iter().any(|key| key.is_empty()) {
            return Err(Error::Data(format!(
                "Empty CSV key at record {}",
                index + 1
            )));
        }

        let fields = schema.row(column_indexes.iter().map(|&i| {
            let value = cell(i);
            (!value.is_empty()).then(|| value.to_owned())
        }));

        emit(&keys, fields)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::enrich::key::{Key, KeyType};

    #[test]
    fn exact_rows_match_on_every_key_column() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "name,exporter,ifindex").unwrap();
        writeln!(file, "uplink,10.0.0.1,1").unwrap();
        writeln!(file, "lan,10.0.0.1,2").unwrap();
        writeln!(file, "wan,10.0.0.2,1").unwrap();

        let schema = Schema::new(["name"]);
        let table = open(
            file.reopen().unwrap(),
            &["exporter".into(), "ifindex".into()],
            &CsvLookup::Exact(vec![KeyType::Ip, KeyType::Number]),
            &schema,
        )
        .unwrap();

        let exporter = Key::Ip(Ipv4Addr::new(10, 0, 0, 1).into());
        let name = |keys: &[Key]| {
            table
                .lookup(keys)
                .map(|row| row.values()[0].clone().unwrap().to_string())
        };

        assert_eq!(table.len(), 3);
        assert_eq!(name(&[exporter, Key::Number(2)]).as_deref(), Some("lan"));
        assert_eq!(name(&[exporter, Key::Number(3)]), None);
        assert_eq!(name(&[Key::Number(2), exporter]), None);
        assert_eq!(name(&[exporter]), None);
    }
}
