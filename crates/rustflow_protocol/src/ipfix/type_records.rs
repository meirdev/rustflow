//! RFC 5610: an exporter describing the information elements it sends, in
//! options records called type records.

use std::borrow::Cow;
use std::collections::HashMap;

use super::OptionsTemplate;
use crate::information_element::{
    DataType, DataTypeSemantics, ElementId, InformationElement, Registry, iana,
};
use crate::value::Value;

/// Elements one exporter may describe across its domains; it decides how
/// many it sends.
const MAX_ELEMENTS: usize = 1024;

/// Longest name kept, in bytes; RFC 5610 sets no limit short of the
/// message's.
const MAX_NAME_LENGTH: usize = 256;

/// What type records said about the elements of each observation domain.
#[derive(Default)]
pub(super) struct ElementTypes {
    domains: HashMap<u32, HashMap<ElementId, Learned>>,
    len: usize,
}

enum Learned {
    Defined(InformationElement),
    /// Type records disagreed, so the element is ignored (RFC 5610 section
    /// 3.9).
    Conflicting,
}

impl ElementTypes {
    pub(super) fn get(&self, domain: u32, element: ElementId) -> Option<&InformationElement> {
        match self.domains.get(&domain)?.get(&element)? {
            Learned::Defined(element) => Some(element),
            Learned::Conflicting => None,
        }
    }

    /// Learns from the type records among `records`, decoded by `template`.
    /// They never redefine an element of `registry` (RFC 5610 section 3.9).
    /// True when what [`ElementTypes::get`] gives changed.
    pub(super) fn learn(
        &mut self,
        domain: u32,
        template: &OptionsTemplate,
        records: &[Vec<Value>],
        registry: &Registry,
    ) -> bool {
        let mut changed = false;
        for record in records {
            if let Some(element) = describe(template, record)
                && registry.get(element.element_id()).is_none()
            {
                changed |= self.insert(domain, element);
            }
        }
        changed
    }

    fn insert(&mut self, domain: u32, element: InformationElement) -> bool {
        let full = self.len >= MAX_ELEMENTS;
        let elements = self.domains.entry(domain).or_default();
        let key = element.element_id();
        match elements.get_mut(&key) {
            Some(Learned::Defined(known)) if *known == element => false,
            Some(Learned::Conflicting) => false,
            Some(learned) => {
                *learned = Learned::Conflicting;
                true
            }
            None if !full => {
                elements.insert(key, Learned::Defined(element));
                self.len += 1;
                true
            }
            None => false,
        }
    }
}

/// The element a type record describes; `None` for a record that is not a
/// type record, or one to ignore. A type record's informationElementId is a
/// scope field (RFC 5610 section 3.9).
fn describe(template: &OptionsTemplate, record: &[Value]) -> Option<InformationElement> {
    if !template
        .scope_fields
        .iter()
        .any(|field| field.element_id() == iana::INFORMATION_ELEMENT_ID)
    {
        return None;
    }

    let (mut id, mut enterprise_number, mut data_type) = (None, None, None);
    let (mut semantics, mut name) = (None, None);
    let fields = template.scope_fields.iter().chain(&template.option_fields);
    for (field, value) in fields.zip(record) {
        match field.element_id() {
            // The enterprise bit must be ignored (RFC 5610 section 3.8).
            iana::INFORMATION_ELEMENT_ID => {
                id = Some(u16::try_from(value.as_u64()?).ok()? & 0x7fff);
            }
            iana::PRIVATE_ENTERPRISE_NUMBER => {
                enterprise_number = Some(u32::try_from(value.as_u64()?).ok()?);
            }
            iana::INFORMATION_ELEMENT_DATA_TYPE => {
                data_type = Some(DataType::try_from(u8::try_from(value.as_u64()?).ok()?).ok()?);
            }
            iana::INFORMATION_ELEMENT_SEMANTICS => {
                semantics =
                    Some(DataTypeSemantics::try_from(u8::try_from(value.as_u64()?).ok()?).ok()?);
            }
            // A name holding a null character must be ignored (RFC 5610
            // section 4).
            iana::INFORMATION_ELEMENT_NAME => {
                name = match value {
                    Value::String(name)
                        if !name.is_empty()
                            && name.len() <= MAX_NAME_LENGTH
                            && !name.contains('\0') =>
                    {
                        Some(name.clone())
                    }
                    _ => None,
                };
            }
            _ => {}
        }
    }

    let (id, data_type) = (id?, data_type?);
    if !semantics_fit(data_type, semantics) {
        return None;
    }
    // Zero, or no field at all, for an IANA element (RFC 5610 section 3.8).
    let enterprise_number = enterprise_number.filter(|&number| number != 0);
    let name = name.unwrap_or_else(|| match enterprise_number {
        Some(enterprise_number) => format!("{enterprise_number}.{id}"),
        None => id.to_string(),
    });

    Some(InformationElement {
        id,
        enterprise_number,
        name: Cow::Owned(name),
        data_type,
        semantics,
    })
}

/// RFC 5610 section 3.10, with RFC 8038's SNMP semantics for unsigned
/// integers and RFC 6313's list semantics for lists. No semantics count as
/// default.
fn semantics_fit(data_type: DataType, semantics: Option<DataTypeSemantics>) -> bool {
    use DataTypeSemantics::*;

    let Some(semantics) = semantics else {
        return true;
    };
    match data_type {
        DataType::Unsigned8
        | DataType::Unsigned16
        | DataType::Unsigned32
        | DataType::Unsigned64
        | DataType::Unsigned256 => semantics != List,
        DataType::Signed8 | DataType::Signed16 | DataType::Signed32 | DataType::Signed64 => {
            matches!(
                semantics,
                Default | Quantity | TotalCounter | DeltaCounter | Identifier
            )
        }
        DataType::Float32 | DataType::Float64 => {
            matches!(semantics, Default | Quantity | TotalCounter | DeltaCounter)
        }
        DataType::BasicList | DataType::SubTemplateList | DataType::SubTemplateMultiList => {
            matches!(semantics, Default | List)
        }
        _ => semantics == Default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipfix::FieldSpecifier;

    fn type_template() -> OptionsTemplate {
        let field = |element: ElementId, field_length| FieldSpecifier {
            information_element_id: element.id,
            field_length,
            enterprise_number: element.enterprise_number,
        };
        OptionsTemplate {
            template_id: 400,
            scope_fields: vec![
                field(iana::INFORMATION_ELEMENT_ID, 2),
                field(iana::PRIVATE_ENTERPRISE_NUMBER, 4),
            ],
            option_fields: vec![
                field(iana::INFORMATION_ELEMENT_DATA_TYPE, 1),
                field(iana::INFORMATION_ELEMENT_NAME, 65535),
            ],
        }
    }

    fn type_record(id: u16, name: String) -> Vec<Value> {
        vec![
            Value::Unsigned16(id),
            Value::Unsigned32(9),
            Value::Unsigned8(DataType::Unsigned32 as u8),
            Value::String(name),
        ]
    }

    #[test]
    fn an_exporter_describes_at_most_max_elements() {
        let records: Vec<_> = (0..=MAX_ELEMENTS)
            .map(|id| type_record(u16::try_from(id).unwrap(), String::new()))
            .collect();
        let mut types = ElementTypes::default();
        assert!(types.learn(7, &type_template(), &records, &Registry::empty()));

        let last = u16::try_from(MAX_ELEMENTS).unwrap();
        assert!(types.get(7, ElementId::from((9, last - 1))).is_some());
        assert!(types.get(7, ElementId::from((9, last))).is_none());
    }

    #[test]
    fn names_longer_than_the_limit_are_replaced_by_the_element_key() {
        let mut types = ElementTypes::default();
        let records = [
            type_record(1, "a".repeat(MAX_NAME_LENGTH)),
            type_record(2, "a".repeat(MAX_NAME_LENGTH + 1)),
        ];
        types.learn(7, &type_template(), &records, &Registry::empty());
        assert_eq!(
            types.get(7, ElementId::from((9, 1))).unwrap().name.len(),
            MAX_NAME_LENGTH
        );
        assert_eq!(types.get(7, ElementId::from((9, 2))).unwrap().name, "9.2");
    }

    #[test]
    fn semantics_fit_their_data_types() {
        use DataTypeSemantics::*;

        assert!(semantics_fit(DataType::Unsigned32, Some(Flags)));
        assert!(semantics_fit(DataType::Unsigned64, Some(SnmpCounter)));
        assert!(!semantics_fit(DataType::Unsigned64, Some(List)));
        assert!(semantics_fit(DataType::Signed32, Some(Identifier)));
        assert!(!semantics_fit(DataType::Signed32, Some(Flags)));
        assert!(semantics_fit(DataType::Float64, Some(DeltaCounter)));
        assert!(!semantics_fit(DataType::Float64, Some(Identifier)));
        assert!(semantics_fit(DataType::BasicList, Some(List)));
        assert!(!semantics_fit(DataType::BasicList, Some(Quantity)));
        assert!(semantics_fit(DataType::String, Some(Default)));
        assert!(!semantics_fit(DataType::String, Some(Identifier)));
        assert!(semantics_fit(DataType::Ipv4Address, None));
    }
}
