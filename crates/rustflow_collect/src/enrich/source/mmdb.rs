use std::path::Path;

use maxminddb::{PathElement, Reader};
use serde_json::Value;

use super::Source;
use crate::enrich::Result;
use crate::enrich::key::Key;
use crate::enrich::row::{Row, Schema};
use crate::field::{self, Kind};

pub struct MmdbSource {
    reader: Reader<Vec<u8>>,
    schema: Schema,
    paths: Vec<Vec<String>>,
    networks: usize,
}

impl MmdbSource {
    pub fn open(path: &Path, schema: &Schema) -> Result<Self> {
        let reader = Reader::open_readfile(path)?;

        let networks = reader
            .networks(Default::default())?
            .map(|result| Ok(usize::from(result?.has_data())))
            .sum::<Result<usize>>()?;

        let paths = schema
            .columns()
            .iter()
            .map(|(column, _)| column.split('.').map(str::to_owned).collect())
            .collect();

        Ok(Self {
            reader,
            schema: schema.clone(),
            paths,
            networks,
        })
    }
}

impl Source for MmdbSource {
    fn lookup(&self, key: &[Key]) -> Option<Row> {
        let [Key::Ip(ip)] = key else {
            return None;
        };

        let result = self.reader.lookup(*ip).ok()?;
        if !result.has_data() {
            return None;
        }

        let values: Vec<_> = self
            .paths
            .iter()
            .zip(self.schema.columns())
            .map(|(path, (_, kind))| {
                let path: Vec<_> = path.iter().map(|k| PathElement::Key(k)).collect();
                let value = result.decode_path::<Value>(&path).ok().flatten()?;
                value_of(value, *kind)
            })
            .collect();

        (!values.iter().all(Option::is_none)).then(|| self.schema.row(values))
    }

    fn len(&self) -> usize {
        self.networks
    }
}

/// A database value as a column of `kind` holds it; `None` when it is not
/// of that kind. Any value has a text form.
fn value_of(value: Value, kind: Kind) -> Option<field::Value> {
    Some(match (kind, value) {
        (Kind::Unsigned, value) => field::Value::Unsigned(value.as_u64()?),
        (Kind::Signed, value) => field::Value::Signed(value.as_i64()?),
        (Kind::Timestamp, value) => field::Value::Timestamp(value.as_i64()?),
        (Kind::Float, value) => field::Value::Float(value.as_f64()?),
        (Kind::Boolean, value) => field::Value::Boolean(value.as_bool()?),
        (Kind::Text, Value::Null) => return None,
        (Kind::Text, Value::String(text)) if text.is_empty() => return None,
        (Kind::Text, Value::String(text)) => field::Value::Text(text.into()),
        (Kind::Text, value) => field::Value::Text(value.to_string().into()),
    })
}
