use std::path::Path;

use maxminddb::{PathElement, Reader};
use serde_json::Value;

use super::Source;
use crate::Result;
use crate::key::Key;
use crate::row::{Row, Schema};

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
            .map(|column| column.split('.').map(str::to_owned).collect())
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
    fn lookup(&self, key: Key<'_>) -> Option<Row> {
        let Key::Ip(ip) = key else {
            return None;
        };

        let result = self.reader.lookup(ip).ok()?;
        if !result.has_data() {
            return None;
        }

        let values: Vec<_> = self
            .paths
            .iter()
            .map(|path| {
                let path: Vec<_> = path.iter().map(|k| PathElement::Key(k)).collect();
                result
                    .decode_path::<Value>(&path)
                    .ok()
                    .flatten()
                    .and_then(value_to_string)
            })
            .collect();

        (!values.iter().all(Option::is_none)).then(|| self.schema.row(values))
    }

    fn len(&self) -> usize {
        self.networks
    }
}

pub fn value_to_string(value: Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(s) => (!s.is_empty()).then_some(s),
        value => Some(value.to_string()),
    }
}
