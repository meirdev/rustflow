//! Custom information elements from the `--ie-mapping` CSV file: a row per
//! element with its `id`, `enterprise_number` (empty for IANA), `name` and
//! `data_type`, the type named as the registry's own or as the earlier
//! release named it, `Unsigned` standing for any width.

use std::borrow::Cow;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rustflow_core_new::protocol::information_element::{
    DataType, ElementId, InformationElement, Registry,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Row {
    id: u16,
    enterprise_number: Option<u32>,
    name: String,
    data_type: String,
}

/// Adds the file's elements to `registry`, returning how many.
pub fn load(registry: &mut Registry, path: &Path) -> Result<usize> {
    let mut reader = csv::Reader::from_path(path)?;
    let mut count = 0;
    for row in reader.deserialize() {
        let row: Row = row?;
        let data_type = data_type(&row.data_type)
            .with_context(|| format!("element {}: unknown data type", row.name))?;
        registry.insert(InformationElement {
            id: ElementId {
                enterprise_number: row.enterprise_number,
                id: row.id,
            },
            name: Cow::Owned(row.name),
            data_type,
            semantics: None,
        });
        count += 1;
    }
    Ok(count)
}

fn data_type(name: &str) -> Result<DataType> {
    Ok(match name {
        "octetArray" | "OctetArray" => DataType::OctetArray,
        "unsigned8" | "Unsigned8" => DataType::Unsigned8,
        "unsigned16" | "Unsigned16" => DataType::Unsigned16,
        "unsigned32" | "Unsigned32" => DataType::Unsigned32,
        "unsigned64" | "Unsigned64" | "Unsigned" => DataType::Unsigned64,
        "signed8" | "Signed8" => DataType::Signed8,
        "signed16" | "Signed16" => DataType::Signed16,
        "signed32" | "Signed32" => DataType::Signed32,
        "signed64" | "Signed64" | "Signed" => DataType::Signed64,
        "float32" | "Float32" => DataType::Float32,
        "float64" | "Float64" | "Float" => DataType::Float64,
        "boolean" | "Boolean" => DataType::Boolean,
        "macAddress" | "MacAddress" => DataType::MacAddress,
        "string" | "String" => DataType::String,
        "dateTimeSeconds" | "DateTimeSeconds" => DataType::DateTimeSeconds,
        "dateTimeMilliseconds" | "DateTimeMilliseconds" => DataType::DateTimeMilliseconds,
        "dateTimeMicroseconds" | "DateTimeMicroseconds" => DataType::DateTimeMicroseconds,
        "dateTimeNanoseconds" | "DateTimeNanoseconds" => DataType::DateTimeNanoseconds,
        "ipv4Address" | "Ipv4Address" => DataType::Ipv4Address,
        "ipv6Address" | "Ipv6Address" => DataType::Ipv6Address,
        "basicList" | "BasicList" => DataType::BasicList,
        "subTemplateList" | "SubTemplateList" => DataType::SubTemplateList,
        "subTemplateMultiList" | "SubTemplateMultiList" => DataType::SubTemplateMultiList,
        "unsigned256" | "Unsigned256" => DataType::Unsigned256,
        other => bail!("'{other}'"),
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn rows_become_elements_in_either_naming() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "id,enterprise_number,name,data_type").unwrap();
        writeln!(file, "1,9,ciscoBytes,Unsigned").unwrap();
        writeln!(file, "500,,myString,string").unwrap();
        let mut registry = Registry::iana();
        assert_eq!(load(&mut registry, file.path()).unwrap(), 2);
        let cisco = registry.get(ElementId::from((9, 1))).unwrap();
        assert_eq!(
            (cisco.name.as_ref(), cisco.data_type),
            ("ciscoBytes", DataType::Unsigned64)
        );
        let mine = registry.get(ElementId::iana(500)).unwrap();
        assert_eq!(
            (mine.name.as_ref(), mine.data_type),
            ("myString", DataType::String)
        );
    }

    #[test]
    fn an_unknown_data_type_is_an_error() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "id,enterprise_number,name,data_type").unwrap();
        writeln!(file, "1,9,odd,Blob").unwrap();
        let error = load(&mut Registry::iana(), file.path()).unwrap_err();
        assert!(error.to_string().contains("odd"), "{error}");
    }
}
