//! IPFIX (RFC 7011): a message header followed by sets. Template sets
//! describe the records of later data sets, so the parser keeps the
//! templates each exporter sent. A field may be variable-length, and may
//! hold a list of values or of records (RFC 6313).

use std::sync::Arc;

pub use list::{BasicList, ListRecords, ListSemantic, SubTemplateList, SubTemplateMultiList};
pub use parser::Parser;
pub use writer::write;

use crate::protocol::DataSet;
use crate::protocol::information_element::ElementId;

mod list;
mod parser;
#[cfg(test)]
mod tests;
mod type_records;
mod writer;

pub const VERSION: u16 = 10;
pub const TEMPLATE_SET_ID: u16 = 2;
pub const OPTIONS_TEMPLATE_SET_ID: u16 = 3;
/// The lowest template ID. Set IDs below it are reserved; from it up, a set
/// ID is the template ID of the data records it holds.
pub const MIN_TEMPLATE_ID: u16 = 256;
/// The field length of a variable-length field, whose values each carry
/// their own length.
pub const VARIABLE_LENGTH: u16 = 65535;

/// Version, Length, Export Time, Sequence Number and Observation Domain ID.
const HEADER_SIZE: usize = 16;
/// Set ID and Length.
const SET_HEADER_SIZE: usize = 4;
/// Template ID and Data Records Length.
const LIST_GROUP_HEADER_SIZE: usize = 4;
const ENTERPRISE_BIT: u16 = 0x8000;
/// How deep lists may nest before the rest is kept undecoded. The exporter
/// controls the nesting, and each level costs stack.
const MAX_LIST_DEPTH: usize = 8;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Packet {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub header: Header,
    pub sets: Vec<Set>,
}

/// The message header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Header {
    /// Version of the IPFIX format of the message.
    pub version: u16,
    /// Total length of the message in octets, header and sets included.
    pub length: u16,
    /// Seconds since 0000 UTC 1970, modulo 2^32, at which the message
    /// left the exporter.
    pub export_time: u32,
    /// Counter, modulo 2^32, of the data records the exporter sent from the
    /// observation domain before this message.
    pub sequence_number: u32,
    /// The observation domain the message's records come from, unique
    /// within the exporter.
    pub observation_domain_id: u32,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Set {
    Templates(Vec<Arc<Template>>),
    OptionsTemplates(Vec<Arc<OptionsTemplate>>),
    Data(DataSet<Template>),
    OptionsData(DataSet<OptionsTemplate>),
    /// Data whose template is unknown or expired, as sent.
    Undecoded {
        set_id: u16,
        body: Vec<u8>,
    },
    /// A set of a reserved ID.
    Unknown(u16),
}

impl Packet {
    /// Whether the message carries templates, data or options.
    pub fn has_templates(&self) -> bool {
        self.sets
            .iter()
            .any(|set| matches!(set, Set::Templates(_) | Set::OptionsTemplates(_)))
    }

    /// Whether the message carries data whose template was not known.
    pub fn has_undecoded(&self) -> bool {
        self.sets
            .iter()
            .any(|set| matches!(set, Set::Undecoded { .. }))
    }
}

/// A template, or with no fields, a template withdrawal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Template {
    pub template_id: u16,
    pub fields: Vec<FieldSpecifier>,
}

/// An options template, or with no fields, an options template withdrawal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OptionsTemplate {
    pub template_id: u16,
    /// The fields saying what the options describe: elements as other
    /// fields are (RFC 7011 section 3.4.2.1).
    pub scope_fields: Vec<FieldSpecifier>,
    pub option_fields: Vec<FieldSpecifier>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FieldSpecifier {
    /// The information element's ID, without the enterprise bit.
    pub information_element_id: u16,
    /// In octets, or [`VARIABLE_LENGTH`].
    pub field_length: u16,
    /// The private enterprise number of a vendor's element; `None` for an
    /// IANA element.
    pub enterprise_number: Option<u32>,
}

impl FieldSpecifier {
    pub fn element_id(&self) -> ElementId {
        ElementId {
            enterprise_number: self.enterprise_number,
            id: self.information_element_id,
        }
    }
}

/// A template held by the parser, of either kind.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TemplateRef {
    Data(Arc<Template>),
    Options(Arc<OptionsTemplate>),
}

impl TemplateRef {
    pub fn template_id(&self) -> u16 {
        match self {
            Self::Data(template) => template.template_id,
            Self::Options(template) => template.template_id,
        }
    }

    /// Every field in record order: an options template's scope fields
    /// first.
    pub fn fields(&self) -> impl Iterator<Item = &FieldSpecifier> {
        let (scope_fields, fields): (&[_], &[_]) = match self {
            Self::Data(template) => (&[], &template.fields),
            Self::Options(template) => (&template.scope_fields, &template.option_fields),
        };
        scope_fields.iter().chain(fields)
    }
}
