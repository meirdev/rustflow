use std::str::FromStr;

use anyhow::{Context, Result, anyhow};
use rustflow_core::information_element::{ElementId, Registry};
use serde::Deserialize;

use crate::field::{Field, Kind};

/// An `[[extra_field]]` of the configuration file, before its element is
/// looked up.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtraFieldSpec {
    name: String,
    element: String,
    number: Option<u32>,
}

/// An extra field with its element found in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraField {
    pub id: ElementId,
    pub field: Field,
}

impl ExtraFieldSpec {
    /// The element is a name, an ID, or `enterprise/ID`. It must be in
    /// the registry, which gives it the data type its values decode as.
    pub fn resolve(&self, registry: &Registry) -> Result<ExtraField> {
        let Self {
            name,
            element,
            number,
        } = self;
        let id = element_id(element, registry)
            .with_context(|| format!("Extra field '{name}': unknown element '{element}'"))?;
        let element = registry.get(id).ok_or_else(|| {
            anyhow!(
                "Extra field '{name}': element {element} is not in the registry; \
                 add it with --ie-mapping"
            )
        })?;
        let kind = Kind::of(element.data_type).ok_or_else(|| {
            anyhow!(
                "Extra field '{name}': element {} of type {} cannot be a column",
                element.name,
                element.data_type
            )
        })?;
        Ok(ExtraField {
            id,
            field: Field {
                name: name.clone(),
                kind,
                number: *number,
            },
        })
    }
}

fn number<T: FromStr>(text: &str) -> Result<T> {
    text.parse()
        .map_err(|_| anyhow!("'{text}' is not a number"))
}

fn element_id(element: &str, registry: &Registry) -> Result<ElementId> {
    let id = match element.split_once('/') {
        Some((enterprise, id)) => ElementId::new(Some(number(enterprise)?), number(id)?)?,
        None if element.starts_with(|c: char| c.is_ascii_digit()) => {
            ElementId::new(None, number(element)?)?
        }
        None => {
            return registry
                .find(element)
                .ok_or_else(|| anyhow!("no such name"));
        }
    };
    Ok(id)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use rustflow_core::information_element::{DataType, InformationElement};

    use super::*;

    /// The extra field `name` of `element`, with the number after `@`, if
    /// any.
    fn resolve(field: &str) -> Result<ExtraField> {
        let (name, element) = field.split_once('=').unwrap();
        let (element, number) = match element.split_once('@') {
            Some((element, number)) => (element, Some(number.parse().unwrap())),
            None => (element, None),
        };
        let spec = ExtraFieldSpec {
            name: name.into(),
            element: element.into(),
            number,
        };
        let mut registry = Registry::iana();
        registry
            .insert(InformationElement {
                id: ElementId::new(Some(9), 1).unwrap(),
                name: Cow::Borrowed("ciscoExample"),
                data_type: DataType::Unsigned32,
                semantic: None,
                unit: None,
                range: None,
                description: None,
            })
            .unwrap();
        spec.resolve(&registry)
    }

    #[test]
    fn an_element_is_a_name_an_id_or_an_enterprise_id() {
        let by_name = resolve("phys=ingressPhysicalInterface").unwrap();
        assert_eq!(by_name.id, ElementId::INGRESS_PHYSICAL_INTERFACE);
        assert_eq!(by_name.field.name, "phys");
        assert_eq!(by_name.field.kind, Kind::U64);
        assert_eq!(by_name.field.number, None);

        assert_eq!(resolve("phys=252").unwrap(), by_name);
        let enterprise = resolve("cisco=9/1").unwrap();
        assert_eq!(enterprise.id, ElementId::new(Some(9), 1).unwrap());
        assert_eq!(resolve("cisco=ciscoExample").unwrap(), enterprise);
        assert_eq!(
            resolve("host=sourceIPv4Address").unwrap().field.kind,
            Kind::Address
        );
        assert_eq!(resolve("phys=252@1007").unwrap().field.number, Some(1007));
    }

    #[test]
    fn an_element_must_be_known_and_have_a_column_form() {
        assert!(resolve("x=noSuchElement").is_err());
        assert!(resolve("x=9/2").is_err());
        assert!(resolve("x=40000").is_err());
        assert!(resolve("x=basicList").is_err());
    }
}
