use serde::Serialize;

pub const IPFIX_VERSION: u16 = 10;

pub const TEMPLATE_SET_ID: u16 = 2;

pub const OPTIONS_TEMPLATE_SET_ID: u16 = 3;

#[derive(Debug, Clone, Serialize)]
pub struct IPFIX<'a> {
    pub header: Header,
    pub sets: Vec<Set<'a>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    pub version: u16,
    pub length: u16,
    pub export_time: u32,
    pub sequence_number: u32,
    pub observation_domain_id: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldSpecifier {
    pub enterprise_bit: u8,
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
pub struct Set<'a> {
    pub header: SetHeader,
    pub records: Vec<Record<'a>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Record<'a> {
    Template(TemplateRecord),
    OptionsTemplate(OptionsTemplateRecord),
    Data(DataRecord<'a>),
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateRecordHeader {
    pub template_id: u16,
    pub field_count: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateRecord {
    pub header: TemplateRecordHeader,
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
    pub header: OptionsTemplateRecordHeader,
    pub fields: Vec<FieldSpecifier>,
    pub scope_fields: Vec<FieldSpecifier>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataRecord<'a> {
    pub fields: Vec<&'a [u8]>,
}

#[derive(Debug, Clone, Serialize)]
pub enum TemplateRecordType {
    Template(TemplateRecord),
    OptionsTemplate(OptionsTemplateRecord),
}
