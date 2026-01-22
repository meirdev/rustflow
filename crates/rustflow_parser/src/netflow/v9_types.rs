use chrono::Utc;
use serde::Serialize;

use crate::types::DataRecord;

#[derive(Debug, Clone, Serialize)]
pub struct Message {
    /// Header
    pub version: u16,
    pub count: u16,
    pub sys_uptime: chrono::DateTime<Utc>,
    pub unix_time: chrono::DateTime<Utc>,
    pub sequence_number: u32,
    pub source_id: u32,

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
    pub fields: Vec<FieldDefinition>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OptionsTemplateRecord {
    pub template_id: u16,
    pub field_count: u16,
    pub scope_field_count: u16,
    pub fields: Vec<FieldDefinition>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldDefinition {
    pub field_type: u16,
    pub field_length: u16,
}
