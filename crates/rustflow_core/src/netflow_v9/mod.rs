mod encoder;
mod parser;

use jiff::Timestamp;

pub use self::encoder::{EncodeError, encode_packet};
pub use self::parser::Parser;
pub use crate::set::DataSet;
use crate::set::Set;
pub use crate::template::{FieldSpecifier, OptionsTemplate, Template};

const VERSION: u16 = 9;

const TEMPLATE_FLOW_SET_ID: u16 = 0;
const OPTIONS_TEMPLATE_FLOW_SET_ID: u16 = 1;

/// FlowSet IDs 2-255 are reserved; data FlowSets use template IDs from 256.
const MIN_TEMPLATE_ID: u16 = 256;

/// Length of a FlowSet header (FlowSet ID and length).
const FLOW_SET_HEADER_LENGTH: u16 = 4;

/// Template ID and field count.
const TEMPLATE_RECORD_HEADER_LENGTH: usize = 4;

/// Template ID, option scope length and option length.
const OPTIONS_TEMPLATE_RECORD_HEADER_LENGTH: usize = 6;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Packet {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub header: Header,
    pub flow_sets: Vec<FlowSet>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Header {
    /// Version of Flow Record format exported in this packet.
    pub version: u16,
    /// Total number of records in the packet: template, options template
    /// and data records together.
    pub count: u16,
    /// Time in milliseconds since this device was first booted.
    pub sys_uptime: u32,
    /// Time in seconds since 0000 UTC 1970, at which the packet leaves the
    /// exporter.
    pub unix_secs: u32,
    /// Incremental sequence counter of all packets sent from the current
    /// observation domain.
    pub sequence_number: u32,
    /// The exporter observation domain.
    pub source_id: u32,
}

impl Header {
    pub fn unix_time(&self) -> Timestamp {
        Timestamp::from_second(self.unix_secs.into()).expect("within jiff's range")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ScopeField {
    pub field_type: ScopeType,
    pub length: u16,
}

pub type FlowSet = Set<ScopeField>;

pub type TemplateRef = crate::template::TemplateRef<ScopeField>;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    strum::Display,
    num_enum::FromPrimitive,
    num_enum::IntoPrimitive,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[strum(serialize_all = "camelCase")]
#[repr(u16)]
pub enum ScopeType {
    System = 1,
    Interface = 2,
    LineCard = 3,
    Cache = 4,
    Template = 5,
    #[num_enum(catch_all)]
    #[strum(to_string = "{0}")]
    Unassigned(u16),
}

#[cfg(feature = "serde")]
impl serde::Serialize for DataSet<OptionsTemplate<ScopeField>> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let template = &self.template;
        let scope_keys = template
            .scope_fields
            .iter()
            .map(|scope| scope.field_type.to_string().into());
        let keys = scope_keys.chain(crate::value::field_keys(&template.option_fields));
        crate::value::serialize_data_set(serializer, template.template_id, keys, &self.records)
    }
}
