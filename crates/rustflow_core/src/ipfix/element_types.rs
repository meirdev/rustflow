//! RFC 5610: an exporter describing the Information Elements it sends, in
//! options records called type records.

use std::sync::Arc;

use log::{debug, warn};
use rustc_hash::FxHashMap;

use super::parser::{DataRecord, FieldValue, unknown_element_name};
use crate::common::InformationElement;
use crate::common::ie_registry::{DataType, IEDefinition, IERegistry};

/// Elements one exporter may describe across its domains; it decides how
/// many it sends.
const MAX_ELEMENTS: usize = 1024;

/// Longest name kept, in bytes. A longer one is ignored, as one holding a
/// null character must be (RFC 5610 section 4).
const MAX_NAME_LENGTH: usize = 256;

/// An element's ID and enterprise number.
type ElementKey = (u16, Option<u32>);

/// What type records said about the elements of each observation domain.
/// They only describe elements the registry does not define: a type record
/// never redefines a known element (RFC 5610 section 3.9).
#[derive(Default)]
pub struct ElementTypes {
    domains: FxHashMap<u32, FxHashMap<ElementKey, Learned>>,
    len: usize,
}

enum Learned {
    Defined {
        description: Description,
        definition: IEDefinition,
    },
    /// Type records disagreed, so the element is treated as unknown
    /// (RFC 5610 section 3.9).
    Conflicting,
}

impl ElementTypes {
    pub fn lookup(
        &self,
        domain: u32,
        id: u16,
        enterprise_number: Option<u32>,
    ) -> Option<&IEDefinition> {
        match self.domains.get(&domain)?.get(&(id, enterprise_number))? {
            Learned::Defined { definition, .. } => Some(definition),
            Learned::Conflicting => None,
        }
    }

    /// Learns from `record` if it is a type record. True when what
    /// [`ElementTypes::lookup`] gives for an element changed.
    pub fn learn(&mut self, domain: u32, record: &DataRecord, registry: &IERegistry) -> bool {
        let Some(description) = Description::read(record) else {
            return false;
        };
        let key = (description.id, description.enterprise_number);
        if registry.lookup(key.0, key.1).is_some() {
            return false;
        }
        let Some(data_type) = description.data_type() else {
            debug!(
                "Type record for element {key:?} ignored: data type {} with semantics {}",
                description.data_type, description.semantics
            );
            return false;
        };

        match self
            .domains
            .get_mut(&domain)
            .and_then(|elements| elements.get_mut(&key))
        {
            Some(Learned::Defined {
                description: known, ..
            }) if *known == description => false,
            Some(Learned::Conflicting) => false,
            Some(learned) => {
                warn!("Type records for element {key:?} disagree; it is left undecoded");
                *learned = Learned::Conflicting;
                true
            }
            None if self.len < MAX_ELEMENTS => {
                let name = description
                    .name
                    .as_deref()
                    .map_or_else(|| Arc::from(unknown_element_name(key.0, key.1)), Arc::from);
                let definition = IEDefinition {
                    id: key.0,
                    enterprise_number: key.1,
                    name,
                    data_type,
                };
                self.domains.entry(domain).or_default().insert(
                    key,
                    Learned::Defined {
                        description,
                        definition,
                    },
                );
                self.len += 1;
                true
            }
            None => {
                debug!(
                    "Type record for element {key:?} ignored: {MAX_ELEMENTS} elements already described"
                );
                false
            }
        }
    }
}

/// The parts of a type record a collector uses.
#[derive(PartialEq, Eq)]
struct Description {
    id: u16,
    enterprise_number: Option<u32>,
    data_type: u8,
    semantics: u8,
    name: Option<String>,
}

impl Description {
    /// A type record names the element and its data type; semantics default
    /// to 0, and a name that is not usable is left out.
    fn read(record: &DataRecord) -> Option<Self> {
        let (mut id, mut enterprise_number, mut data_type) = (None, None, None);
        let (mut semantics, mut name) = (0, None);
        for (field, _, value) in record.iter() {
            if field.enterprise_number.is_some() {
                continue;
            }
            match InformationElement::from_id(field.information_element_identifier) {
                // RFC 5610 section 3.8: the Enterprise bit is ignored here.
                Some(InformationElement::InformationElementId) => {
                    id = unsigned(value)
                        .and_then(|v| u16::try_from(v).ok())
                        .map(|v| v & 0x7fff);
                }
                Some(InformationElement::PrivateEnterpriseNumber) => {
                    enterprise_number = unsigned(value).and_then(|v| u32::try_from(v).ok());
                }
                Some(InformationElement::InformationElementDataType) => {
                    data_type = unsigned(value).and_then(|v| u8::try_from(v).ok());
                }
                Some(InformationElement::InformationElementSemantics) => {
                    semantics = unsigned(value).and_then(|v| u8::try_from(v).ok())?;
                }
                Some(InformationElement::InformationElementName) => {
                    name = match value {
                        FieldValue::String(name)
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

        Some(Self {
            id: id?,
            // Zero, or no field at all, for an IANA element.
            enterprise_number: enterprise_number.filter(|&number| number != 0),
            data_type: data_type?,
            semantics,
            name,
        })
    }

    /// RFC 5610 section 3.1, with the list types of RFC 6313; `None` for an
    /// unknown type or one its semantics do not fit (section 3.10).
    fn data_type(&self) -> Option<DataType> {
        let fits = match self.data_type {
            // snmpCounter (7) and snmpGauge (8) are RFC 8038's.
            1..=4 => matches!(self.semantics, 0..=5 | 7 | 8),
            5..=8 => self.semantics <= 4,
            9 | 10 => self.semantics <= 3,
            // RFC 6313's list semantics.
            20..=22 => matches!(self.semantics, 0 | 6),
            _ => self.semantics == 0,
        };
        if !fits {
            return None;
        }
        Some(match self.data_type {
            0 => DataType::OctetArray,
            1..=4 => DataType::Unsigned,
            5..=8 => DataType::Signed,
            9 | 10 => DataType::Float,
            11 => DataType::Boolean,
            12 => DataType::MacAddress,
            13 => DataType::String,
            14 => DataType::DateTimeSeconds,
            15 => DataType::DateTimeMilliseconds,
            16 => DataType::DateTimeMicroseconds,
            17 => DataType::DateTimeNanoseconds,
            18 => DataType::Ipv4Address,
            19 => DataType::Ipv6Address,
            20 => DataType::BasicList,
            21 => DataType::SubTemplateList,
            22 => DataType::SubTemplateMultiList,
            _ => return None,
        })
    }
}

fn unsigned(value: &FieldValue) -> Option<u64> {
    match *value {
        FieldValue::Unsigned8(v) => Some(v.into()),
        FieldValue::Unsigned16(v) => Some(v.into()),
        FieldValue::Unsigned32(v) => Some(v.into()),
        FieldValue::Unsigned64(v) => Some(v),
        _ => None,
    }
}
