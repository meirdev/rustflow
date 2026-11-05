//! NetFlow v9 (RFC 3954): a header followed by FlowSets. Template FlowSets
//! describe the records of later data FlowSets, so the parser keeps the
//! templates each exporter sent.

use std::sync::Arc;

use num_enum::{FromPrimitive, IntoPrimitive};
pub use parser::Parser;
pub use writer::write;

use crate::DataSet;

mod parser;
#[cfg(test)]
mod tests;
mod writer;

pub const VERSION: u16 = 9;
pub const TEMPLATE_FLOW_SET_ID: u16 = 0;
pub const OPTIONS_TEMPLATE_FLOW_SET_ID: u16 = 1;

/// The lowest template ID. FlowSet IDs below it are reserved; from it up, a
/// FlowSet ID is the template ID of the data records it holds.
pub const MIN_TEMPLATE_ID: u16 = 256;

/// FlowSet ID and Length.
const FLOW_SET_HEADER_SIZE: usize = 4;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Packet {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub header: Header,
    pub flow_sets: Vec<FlowSet>,
}

/// The packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FlowSet {
    Templates(Vec<Arc<Template>>),
    OptionsTemplates(Vec<Arc<OptionsTemplate>>),
    Data(DataSet<Template>),
    OptionsData(DataSet<OptionsTemplate>),
    /// A reserved FlowSet ID, or data whose template is unknown or expired.
    Unknown(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Template {
    pub template_id: u16,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Field {
    /// The ID of an IANA element, or in a scope field a [`ScopeType`].
    pub field_type: u16,
    /// The length of the field's values, in bytes.
    pub length: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OptionsTemplate {
    pub template_id: u16,
    /// What the options describe. The field type is a [`ScopeType`].
    pub scope_fields: Vec<Field>,
    pub option_fields: Vec<Field>,
}

/// What a scope field of an options template names (RFC 3954 section
/// 6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum ScopeType {
    System = 1,
    Interface = 2,
    LineCard = 3,
    Cache = 4,
    Template = 5,
    #[num_enum(catch_all)]
    Unassigned(u16),
}
