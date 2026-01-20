use std::fmt::{self, Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::Utc;
use macaddr::MacAddr6;
use primitive_types::U256;
use rustc_hash::FxHashMap;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Message {
    /// Header
    pub version: u16,
    pub length: u16,
    pub export_time: u32,
    pub sequence_number: u32,
    pub observation_domain_id: u32,

    pub sets: Vec<Set>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Set {
    pub set_id: u16,
    pub length: u16,
    pub records: Vec<Record>,
}

#[derive(Debug, Clone, Serialize)]
pub enum Record {
    Template(TemplateRecord),
    OptionsTemplate(OptionsTemplateRecord),
    Data(DataRecord),
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateRecord {
    pub template_id: u16,
    pub field_count: u16,
    pub fields: Vec<FieldSpecifier>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OptionsTemplateRecord {
    pub template_id: u16,
    pub field_count: u16,
    pub scope_field_count: u16,
    pub fields: Vec<FieldSpecifier>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldSpecifier {
    pub enterprise_bit: bool,
    pub information_element_identifier: u16,
    pub field_length: u16,
    pub enterprise_number: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataRecord(pub FxHashMap<(u32, u16), FieldValue>);

#[derive(Debug, Clone, Serialize)]
pub enum FieldValue {
    Unsigned8(u8),
    Unsigned16(u16),
    Unsigned32(u32),
    Unsigned64(u64),
    Unsigned256(U256),
    Signed8(i8),
    Signed16(i16),
    Signed32(i32),
    Signed64(i64),
    Float32(f32),
    Float64(f64),
    Boolean(bool),
    MacAddress(MacAddr6),
    OctetArray(Vec<u8>),
    String(String),
    DateTimeSeconds(chrono::DateTime<Utc>),
    DateTimeMilliseconds(chrono::DateTime<Utc>),
    DateTimeMicroseconds(chrono::DateTime<Utc>),
    DateTimeNanoseconds(chrono::DateTime<Utc>),
    Ipv4Address(Ipv4Addr),
    Ipv6Address(Ipv6Addr),
    BasicList(BasicList),
    SubTemplateList(SubTemplateList),
    SubTemplateMultiList(SubTemplateMultiList),
}

#[repr(u8)]
#[derive(Debug, Clone, Serialize)]
pub enum Semantic {
    NoneOf = 0x00,
    ExactlyOneOf = 0x01,
    OneOrMoreOf = 0x02,
    AllOf = 0x03,
    Ordered = 0x04,
    Undefined = 0xff,
}

#[derive(Debug, Clone, Serialize)]
pub struct BasicList {
    pub semantic: Semantic,
    pub field: FieldSpecifier,
    pub content: Vec<FieldValue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubTemplateList {
    pub semantic: Semantic,
    pub template_id: u16,
    pub data: Vec<DataRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubTemplateMultiList {
    pub semantic: Semantic,
    pub data: Vec<SubTemplateMultiItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubTemplateMultiItem {
    pub template_id: u16,
    pub length: u16,
    pub data: Vec<DataRecord>,
}

impl TryFrom<u8> for Semantic {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Semantic::NoneOf),
            0x01 => Ok(Semantic::ExactlyOneOf),
            0x02 => Ok(Semantic::OneOrMoreOf),
            0x03 => Ok(Semantic::AllOf),
            0x04 => Ok(Semantic::Ordered),
            0xff => Ok(Semantic::Undefined),
            _ => Err(()),
        }
    }
}

impl Display for Semantic {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Semantic::NoneOf => write!(f, "noneOf"),
            Semantic::ExactlyOneOf => write!(f, "exactlyOneOf"),
            Semantic::OneOrMoreOf => write!(f, "oneOrMoreOf"),
            Semantic::AllOf => write!(f, "allOf"),
            Semantic::Ordered => write!(f, "ordered"),
            Semantic::Undefined => write!(f, "undefined"),
        }
    }
}

impl Display for FieldValue {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            FieldValue::Unsigned8(v) => write!(f, "{}", v),
            FieldValue::Unsigned16(v) => write!(f, "{}", v),
            FieldValue::Unsigned32(v) => write!(f, "{}", v),
            FieldValue::Unsigned64(v) => write!(f, "{}", v),
            FieldValue::Unsigned256(v) => write!(f, "{}", v),
            FieldValue::Signed8(v) => write!(f, "{}", v),
            FieldValue::Signed16(v) => write!(f, "{}", v),
            FieldValue::Signed32(v) => write!(f, "{}", v),
            FieldValue::Signed64(v) => write!(f, "{}", v),
            FieldValue::Float32(v) => write!(f, "{}", v),
            FieldValue::Float64(v) => write!(f, "{}", v),
            FieldValue::Boolean(v) => write!(f, "{}", v),
            FieldValue::MacAddress(v) => write!(f, "{}", v),
            FieldValue::OctetArray(v) => write!(f, "{}", hex::encode(v)),
            FieldValue::String(v) => write!(f, "{}", v),
            FieldValue::DateTimeSeconds(v) => write!(f, "{}", v.format("%Y-%m-%dT%H:%M:%S")),
            FieldValue::DateTimeMilliseconds(v) => {
                write!(f, "{}", v.format("%Y-%m-%dT%H:%M:%S.%3f"))
            }
            FieldValue::DateTimeMicroseconds(v) => {
                write!(f, "{}", v.format("%Y-%m-%dT%H:%M:%S.%6f"))
            }
            FieldValue::DateTimeNanoseconds(v) => {
                write!(f, "{}", v.format("%Y-%m-%dT%H:%M:%S.%9f"))
            }
            FieldValue::Ipv4Address(v) => write!(f, "{}", v),
            FieldValue::Ipv6Address(v) => write!(f, "{}", v),
            // There is no RFC for this:
            FieldValue::BasicList(v) => write!(f, "{:?}", v),
            FieldValue::SubTemplateList(v) => write!(f, "{:?}", v),
            FieldValue::SubTemplateMultiList(v) => write!(f, "{:?}", v),
        }
    }
}
