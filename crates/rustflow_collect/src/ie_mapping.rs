use std::borrow::Cow;
use std::path::Path;

use anyhow::{Context, Result};
use rustflow_core::information_element::{DataType, ElementId, InformationElement, Registry};
use serde::Deserialize;

/// A custom element: a row of the `--ie-mapping` CSV, or an `[[element]]`
/// of the configuration file, which has shorter names for two of the keys.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Element {
    id: u16,
    #[serde(alias = "enterprise")]
    enterprise_number: Option<u32>,
    name: String,
    #[serde(alias = "type")]
    data_type: String,
}

impl Element {
    pub fn insert(&self, registry: &mut Registry) -> Result<()> {
        let Self {
            id,
            enterprise_number,
            name,
            data_type,
        } = self;
        let data_type: DataType = data_type
            .parse()
            .with_context(|| format!("element {name}: unknown data type '{data_type}'"))?;
        let id =
            ElementId::new(*enterprise_number, *id).with_context(|| format!("element {name}"))?;
        registry.insert(InformationElement {
            id,
            name: Cow::Owned(name.clone()),
            data_type,
            semantic: None,
            unit: None,
            range: None,
            description: None,
        })?;
        Ok(())
    }
}

pub fn load(registry: &mut Registry, path: &Path) -> Result<usize> {
    let mut reader = csv::Reader::from_path(path)?;
    let mut count = 0;
    for row in reader.deserialize() {
        let element: Element = row?;
        element.insert(registry)?;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn mapping(rows: &[&str]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "id,enterprise_number,name,data_type").unwrap();
        for row in rows {
            writeln!(file, "{row}").unwrap();
        }
        file
    }

    #[test]
    fn rows_become_elements() {
        let file = mapping(&[
            "1,9,ciscoBytes,unsigned64",
            "500,,myString,string",
            "501,,myAddress,ipv4Address",
        ]);
        let mut registry = Registry::iana();
        assert_eq!(load(&mut registry, file.path()).unwrap(), 3);

        let element = |enterprise, id| {
            let element = registry
                .get(ElementId::new(enterprise, id).unwrap())
                .unwrap();
            (element.name.as_ref(), element.data_type)
        };
        assert_eq!(element(Some(9), 1), ("ciscoBytes", DataType::Unsigned64));
        assert_eq!(element(None, 500), ("myString", DataType::String));
        assert_eq!(element(None, 501), ("myAddress", DataType::Ipv4Address));
    }

    #[test]
    fn an_unknown_data_type_is_an_error() {
        let file = mapping(&["1,9,odd,Unsigned"]);
        let error = load(&mut Registry::iana(), file.path()).unwrap_err();
        assert!(format!("{error:#}").contains("odd"), "{error:#}");
    }
}
