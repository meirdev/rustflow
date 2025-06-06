use std::net;

use macaddr::MacAddr6;
use serde::Serialize;

pub const IPFIX_VERSION: u16 = 10;

pub const TEMPLATE_SET_ID: u16 = 2;

pub const OPTIONS_TEMPLATE_SET_ID: u16 = 3;

pub const VALID_TEMPLATE_ID_RANGE: std::ops::RangeInclusive<u16> = 256..=65535;

#[derive(Debug, Clone, Serialize)]
pub struct Ipfix {
    pub message_header: MessageHeader,
    pub sets: Vec<Set>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MessageHeader {
    pub version: u16,
    pub length: u16,
    pub export_time: u32,
    pub sequence_number: u32,
    pub observation_domain_id: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldSpecifier {
    pub enterprise_bit: bool,
    pub information_element_identifier: u16,
    pub field_length: u16,
    pub enterprise_number: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetHeader {
    pub set_id: u16,
    pub length: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct Set {
    pub set_header: SetHeader,
    pub records: Vec<Record>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Record {
    Template(TemplateRecord),
    OptionsTemplate(OptionsTemplateRecord),
    Data(DataRecord),
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateRecordHeader {
    pub template_id: u16,
    pub field_count: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateRecord {
    pub template_record_header: TemplateRecordHeader,
    pub fields: Vec<FieldSpecifier>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OptionsTemplateRecordHeader {
    pub template_id: u16,
    pub field_count: u16,
    pub scope_field_count: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct OptionsTemplateRecord {
    pub options_template_record_header: OptionsTemplateRecordHeader,
    pub fields: Vec<FieldSpecifier>,
    pub scope_fields: Vec<FieldSpecifier>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataRecord {
    pub fields: Vec<DataRecordField>,
}

#[derive(Debug, Clone, Serialize)]
pub enum TemplateRecordType {
    Template(TemplateRecord),
    OptionsTemplate(OptionsTemplateRecord),
}

#[derive(Debug, Clone, Serialize)]
pub struct DataRecordField(pub u16, pub Vec<u8>);

pub enum DataType {
    Octet(u8),
    Signed8(i8),
    Unsigned16(u16),
    Signed16(i16),
    Unsigned32(u32),
    Signed32(i32),
    Unsigned64(u64),
    Signed64(i64),
    MacAddress(MacAddr6),
    Ipv4Address(net::Ipv4Addr),
    Ipv6Address(net::Ipv6Addr),
    Float32(f32),
    Float64(f64),
    Boolean(bool),
    String(String),
    OctetArray(Vec<u8>),
    DateTimeSeconds(chrono::DateTime<chrono::Utc>),
    DateTimeMilliseconds(chrono::DateTime<chrono::Utc>),
    DateTimeMicroseconds(chrono::DateTime<chrono::Utc>),
    DateTimeNanoseconds(chrono::DateTime<chrono::Utc>),
}
