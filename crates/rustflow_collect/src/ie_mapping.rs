use std::borrow::Cow;
use std::path::Path;

use anyhow::{Context, Result};
use rustflow_core::information_element::{DataType, ElementId, InformationElement, Registry};
use serde::Deserialize;

#[derive(Deserialize)]
struct Row {
    id: u16,
    enterprise_number: Option<u32>,
    name: String,
    data_type: String,
}

pub fn load(registry: &mut Registry, path: &Path) -> Result<usize> {
    let mut reader = csv::Reader::from_path(path)?;
    let mut count = 0;
    for row in reader.deserialize() {
        let row: Row = row?;
        let data_type: DataType = row.data_type.parse().with_context(|| {
            format!(
                "element {}: unknown data type '{}'",
                row.name, row.data_type
            )
        })?;
        let id = ElementId::new(row.enterprise_number, row.id)
            .with_context(|| format!("element {}", row.name))?;
        registry.insert(InformationElement {
            id,
            name: Cow::Owned(row.name),
            data_type,
            semantic: None,
            unit: None,
            range: None,
            description: None,
        })?;
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
