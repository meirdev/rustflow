use std::path::Path;

use ipnet::IpNet;
use maxminddb::PathElement;
use serde_json::Value;

use crate::lookup::{Row, Schema};
use crate::{Error, Result};

pub fn read(
    path: &Path,
    schema: &Schema,
    mut emit: impl FnMut(IpNet, Row) -> Result<()>,
) -> Result<()> {
    let reader = maxminddb::Reader::open_readfile(path)?;

    let paths: Vec<Vec<_>> = schema
        .columns()
        .iter()
        .map(|column| column.split('.').map(PathElement::Key).collect())
        .collect();

    for result in reader.networks(Default::default())? {
        let lookup = result?;
        if !lookup.has_data() {
            continue;
        }

        let values = paths
            .iter()
            .map(|path| Ok(lookup.decode_path::<Value>(path)?.and_then(value_to_string)))
            .collect::<Result<Vec<_>>>()?;
        if values.iter().all(Option::is_none) {
            continue;
        }

        let network = lookup.network()?;
        let network = IpNet::new(network.ip(), network.prefix())
            .map_err(|e| Error::Data(format!("Invalid MMDB network {network}: {e}")))?;

        emit(network, schema.row(values))?;
    }

    Ok(())
}

pub fn value_to_string(value: Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(s) => (!s.is_empty()).then_some(s),
        value => Some(value.to_string()),
    }
}
