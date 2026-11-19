mod encoder;
mod parser;

use std::sync::Arc;

use jiff::Timestamp;

pub use self::encoder::{EncodeError, encode_packet};
pub use self::parser::{LearnedElement, Parser};
pub use crate::set::{DataSet, Set};
pub use crate::template::{FieldSpecifier, OptionsTemplate, Template, TemplateRef};

pub const VERSION: u16 = 10;

/// The field length of a variable-length field, whose values each carry
/// their own length.
pub const VARIABLE_LENGTH: u16 = 65535;

/// The set ID for template sets.
const TEMPLATE_SET_ID: u16 = 2;

/// The set ID for options template sets.
const OPTIONS_TEMPLATE_SET_ID: u16 = 3;

/// The lowest template ID. Set IDs below it are reserved.
const MIN_TEMPLATE_ID: u16 = 256;

/// Length of the message header.
pub const HEADER_LENGTH: u16 = 16;

/// Length of a set header (set ID and length).
pub const SET_HEADER_LENGTH: u16 = 4;

/// Length of the smallest template or options template record.
const MIN_TEMPLATE_RECORD_LENGTH: usize = 4;

/// High bit of the information element ID.
const ENTERPRISE_BIT: u16 = 0x8000;

/// How deep lists may nest.
const MAX_LIST_DEPTH: usize = 8;

/// Template ID and Data Records Length.
const LIST_GROUP_HEADER_SIZE: usize = 4;

fn is_valid_template_header(template_id: u16, field_count: u16, set_id: u16) -> bool {
    template_id >= MIN_TEMPLATE_ID || (template_id == set_id && field_count == 0)
}

pub fn is_withdrawal(template: &Template) -> bool {
    template.fields.is_empty()
}

pub fn withdraws_all(template: &Template) -> bool {
    is_withdrawal(template) && template.template_id == TEMPLATE_SET_ID
}

pub fn is_options_withdrawal(template: &OptionsTemplate) -> bool {
    template.scope_fields.is_empty() && template.option_fields.is_empty()
}

pub fn withdraws_all_options(template: &OptionsTemplate) -> bool {
    is_options_withdrawal(template) && template.template_id == OPTIONS_TEMPLATE_SET_ID
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Packet {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub header: Header,
    pub sets: Vec<Set>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
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

impl Header {
    pub fn unix_time(&self) -> Timestamp {
        Timestamp::from_second(self.export_time.into()).expect("within jiff's range")
    }
}
