use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use nom::bytes::complete::take;
use nom::combinator::{map, map_parser};
use nom::multi::{count, many0};
use nom::number::complete::{
    be_f32, be_f64, be_i8, be_i16, be_i32, be_i64, be_u8, be_u16, be_u32, be_u64,
};
use nom::{IResult, Parser, ToUsize};
use serde::Serialize;

use crate::common::ie_registry::{DataType, IERegistry};
use crate::common::parser::{
    ipv4_addr, ipv6_addr, macaddr6, string, timestamp_micros, timestamp_millis, timestamp_nanos,
    timestamp_secs, vector, verify_version,
};
use crate::common::serializer::serialize_as_hex;
use crate::common::timeout_map::TimeoutHashMap;

pub const NETFLOW_V9_VERSION: u16 = 9;
pub const NETFLOW_V9_TEMPLATE_FLOW_SET_ID: u16 = 0;
pub const NETFLOW_V9_OPTIONS_TEMPLATE_FLOW_SET_ID: u16 = 1;

// 2 (id) + 2 (length)
const FLOW_SET_HEADER_SIZE: usize = 4;

// (source_id, template_id)
type TemplateKey = (u32, u16);

pub struct NetflowV9Parser {
    pub ie_registry: IERegistry,
    pub templates: TimeoutHashMap<TemplateKey, TemplateRecord>,
    pub options_templates: TimeoutHashMap<TemplateKey, OptionsTemplateRecord>,
}

impl NetflowV9Parser {
    pub fn new(ie_registry: IERegistry, timeout: Duration) -> Self {
        Self {
            ie_registry,
            templates: TimeoutHashMap::new(timeout),
            options_templates: TimeoutHashMap::new(timeout),
        }
    }

    pub fn parse<'a>(&mut self, input: &'a [u8]) -> IResult<&'a [u8], NetFlowV9Packet> {
        let (input, header) = parse_header(input)?;
        let (input, flow_sets) = count(
            |i| self.parse_flow_set(header.source_id, i),
            header.count.to_usize(),
        )
        .parse(input)?;

        Ok((input, NetFlowV9Packet { header, flow_sets }))
    }

    fn parse_flow_set<'a>(
        &mut self,
        source_id: u32,
        input: &'a [u8],
    ) -> IResult<&'a [u8], FlowSet> {
        let (input, id) = be_u16(input)?;
        let (input, length) = be_u16(input)?;

        let value_length = (length as usize).saturating_sub(FLOW_SET_HEADER_SIZE);
        let (input, records) = map_parser(take(value_length), |data| {
            self.parse_records(source_id, id, data)
        })
        .parse(input)?;

        Ok((
            input,
            FlowSet {
                id,
                length,
                records,
            },
        ))
    }

    fn parse_records<'a>(
        &mut self,
        source_id: u32,
        flow_set_id: u16,
        input: &'a [u8],
    ) -> IResult<&'a [u8], Vec<Record>> {
        match flow_set_id {
            NETFLOW_V9_TEMPLATE_FLOW_SET_ID => {
                let (input, templates) = many0(parse_template_record).parse(input)?;

                for template in &templates {
                    self.templates
                        .insert((source_id, template.id), template.clone());
                }

                Ok((input, templates.into_iter().map(Record::Template).collect()))
            }
            NETFLOW_V9_OPTIONS_TEMPLATE_FLOW_SET_ID => {
                let (input, options_templates) =
                    many0(parse_options_template_record).parse(input)?;

                for template in &options_templates {
                    self.options_templates
                        .insert((source_id, template.id), template.clone());
                }

                Ok((
                    input,
                    options_templates
                        .into_iter()
                        .map(Record::OptionsTemplate)
                        .collect(),
                ))
            }
            template_id => {
                let (input, records) = self.parse_data_records(source_id, template_id, input)?;

                Ok((input, records))
            }
        }
    }

    fn parse_data_records<'a>(
        &self,
        source_id: u32,
        template_id: u16,
        input: &'a [u8],
    ) -> IResult<&'a [u8], Vec<Record>> {
        if let Some(template) = self.templates.get(&(source_id, template_id)) {
            let (input, records) = many0(|i| self.parse_data_record(template, i)).parse(input)?;
            return Ok((input, records.into_iter().map(Record::Data).collect()));
        }

        if let Some(template) = self.options_templates.get(&(source_id, template_id)) {
            let (input, records) =
                many0(|i| self.parse_options_data_record(template, i)).parse(input)?;
            return Ok((
                input,
                records.into_iter().map(Record::OptionsData).collect(),
            ));
        }

        log::warn!(
            "Unknown template for source_id: {}, template_id: {}. Parsing raw data as fallback.",
            source_id,
            template_id
        );

        let (input, _) = take(input.len())(input)?;

        Ok((input, vec![]))
    }

    fn parse_data_record<'a>(
        &self,
        template: &TemplateRecord,
        input: &'a [u8],
    ) -> IResult<&'a [u8], DataRecord> {
        let mut values = Vec::with_capacity(template.fields.len());
        let mut remaining = input;

        for field in &template.fields {
            let (data_type, name): (DataType, Arc<str>) =
                self.ie_registry.lookup(field.r#type, None).map_or_else(
                    || (DataType::OctetArray, Arc::from(field.r#type.to_string())),
                    |ie| (ie.data_type, ie.name.clone()),
                );

            let (input, value) = parse_field_value(data_type, field.length.to_usize())(remaining)?;
            values.push((field.r#type, name, value));

            remaining = input;
        }

        Ok((remaining, DataRecord(values)))
    }

    fn parse_options_data_record<'a>(
        &self,
        template: &OptionsTemplateRecord,
        input: &'a [u8],
    ) -> IResult<&'a [u8], DataRecord> {
        let field_count = template.scope_fields.len() + template.option_fields.len();
        let mut values = Vec::with_capacity(field_count);
        let mut remaining = input;

        for field in &template.scope_fields {
            let (input, value) =
                parse_field_value(DataType::Unsigned, field.length.to_usize())(remaining)?;
            let name: Arc<str> = Arc::from(field.r#type.to_string());
            values.push((field.r#type.clone().into(), name, value));

            remaining = input;
        }

        for field in &template.option_fields {
            let (data_type, name): (DataType, Arc<str>) =
                self.ie_registry.lookup(field.r#type, None).map_or_else(
                    || (DataType::OctetArray, Arc::from(field.r#type.to_string())),
                    |ie| (ie.data_type, ie.name.clone()),
                );

            let (input, value) = parse_field_value(data_type, field.length.to_usize())(remaining)?;
            values.push((field.r#type, name, value));

            remaining = input;
        }

        Ok((remaining, DataRecord(values)))
    }
}

impl Default for NetflowV9Parser {
    fn default() -> Self {
        let ie_registry = IERegistry::default();
        let timeout = std::time::Duration::from_mins(10);

        Self {
            ie_registry,
            templates: TimeoutHashMap::new(timeout),
            options_templates: TimeoutHashMap::new(timeout),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NetFlowV9Packet {
    #[serde(flatten)]
    pub header: Header,
    pub flow_sets: Vec<FlowSet>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    pub version: u16,
    pub count: u16,
    /// Milliseconds since device boot
    pub system_uptime: u32,
    pub unix_seconds: DateTime<Utc>,
    pub sequence_number: u32,
    pub source_id: u32,
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, version) = verify_version(input, NETFLOW_V9_VERSION)?;
    let (input, count) = be_u16(input)?;
    let (input, system_uptime) = be_u32(input)?;
    let (input, unix_seconds) = timestamp_secs(input)?;
    let (input, sequence_number) = be_u32(input)?;
    let (input, source_id) = be_u32(input)?;

    Ok((
        input,
        Header {
            version,
            count,
            system_uptime,
            unix_seconds,
            sequence_number,
            source_id,
        },
    ))
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowSet {
    pub id: u16,
    pub length: u16,
    pub records: Vec<Record>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Record {
    Template(TemplateRecord),
    OptionsTemplate(OptionsTemplateRecord),
    Data(DataRecord),
    OptionsData(DataRecord),
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateRecord {
    pub id: u16,
    pub fields: Vec<TemplateField>,
}

fn parse_template_record(input: &[u8]) -> IResult<&[u8], TemplateRecord> {
    let (input, id) = be_u16(input)?;
    let (input, field_count) = be_u16(input)?;
    let (input, fields) = count(parse_template_field, field_count.to_usize()).parse(input)?;

    Ok((input, TemplateRecord { id, fields }))
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateField {
    pub r#type: u16,
    pub length: u16,
}

fn parse_template_field(input: &[u8]) -> IResult<&[u8], TemplateField> {
    let (input, r#type) = be_u16(input)?;
    let (input, length) = be_u16(input)?;

    Ok((input, TemplateField { r#type, length }))
}

#[derive(Debug, Clone, Serialize)]
pub struct OptionsTemplateRecord {
    pub id: u16,
    pub option_scope_length: u16,
    pub option_length: u16,
    pub scope_fields: Vec<ScopeField>,
    pub option_fields: Vec<OptionField>,
}

fn parse_options_template_record(input: &[u8]) -> IResult<&[u8], OptionsTemplateRecord> {
    let (input, id) = be_u16(input)?;
    let (input, option_scope_length) = be_u16(input)?;
    let (input, option_length) = be_u16(input)?;
    let (input, scope_fields) = map_parser(
        take(option_scope_length.to_usize()),
        many0(parse_scope_field),
    )
    .parse(input)?;
    let (input, option_fields) =
        map_parser(take(option_length.to_usize()), many0(parse_option_field)).parse(input)?;

    Ok((
        input,
        OptionsTemplateRecord {
            id,
            option_scope_length,
            option_length,
            scope_fields,
            option_fields,
        },
    ))
}

#[derive(Debug, Clone, Serialize, strum_macros::Display)]
#[repr(u16)]
pub enum ScopeFieldType {
    System = 1,
    Interface = 2,
    LineCard = 3,
    Cache = 4,
    Template = 5,
    Unknown(u16),
}

impl From<u16> for ScopeFieldType {
    fn from(value: u16) -> Self {
        match value {
            1 => ScopeFieldType::System,
            2 => ScopeFieldType::Interface,
            3 => ScopeFieldType::LineCard,
            4 => ScopeFieldType::Cache,
            5 => ScopeFieldType::Template,
            other => ScopeFieldType::Unknown(other),
        }
    }
}

impl From<ScopeFieldType> for u16 {
    fn from(value: ScopeFieldType) -> Self {
        match value {
            ScopeFieldType::System => 1,
            ScopeFieldType::Interface => 2,
            ScopeFieldType::LineCard => 3,
            ScopeFieldType::Cache => 4,
            ScopeFieldType::Template => 5,
            ScopeFieldType::Unknown(v) => v,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopeField {
    pub r#type: ScopeFieldType,
    pub length: u16,
}

fn parse_scope_field(input: &[u8]) -> IResult<&[u8], ScopeField> {
    let (input, r#type) = be_u16(input)?;
    let (input, length) = be_u16(input)?;

    Ok((
        input,
        ScopeField {
            r#type: ScopeFieldType::from(r#type),
            length,
        },
    ))
}

#[derive(Debug, Clone, Serialize)]
pub struct OptionField {
    pub r#type: u16,
    pub length: u16,
}

fn parse_option_field(input: &[u8]) -> IResult<&[u8], OptionField> {
    let (input, r#type) = be_u16(input)?;
    let (input, length) = be_u16(input)?;

    Ok((input, OptionField { r#type, length }))
}

#[derive(Debug, Clone)]
pub struct DataRecord(pub Vec<(u16, Arc<str>, FieldValue)>);

impl Serialize for DataRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (_, key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }

        map.end()
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum FieldValue {
    Unsigned8(u8),
    Unsigned16(u16),
    Unsigned32(u32),
    Unsigned64(u64),
    Signed8(i8),
    Signed16(i16),
    Signed32(i32),
    Signed64(i64),
    Float32(f32),
    Float64(f64),
    MacAddress(MacAddr6),
    #[serde(serialize_with = "serialize_as_hex")]
    OctetArray(Vec<u8>),
    String(String),
    DateTimeSeconds(DateTime<Utc>),
    DateTimeMilliseconds(DateTime<Utc>),
    DateTimeMicroseconds(DateTime<Utc>),
    DateTimeNanoseconds(DateTime<Utc>),
    Ipv4Address(Ipv4Addr),
    Ipv6Address(Ipv6Addr),
    Null,
}

fn parse_field_value(
    data_type: DataType,
    length: usize,
) -> impl Fn(&[u8]) -> IResult<&[u8], FieldValue> {
    move |input: &[u8]| match (data_type, length) {
        (_, 0) => Ok((input, FieldValue::Null)),
        (DataType::Unsigned, 1) => map(be_u8, FieldValue::Unsigned8).parse(input),
        (DataType::Unsigned, 2) => map(be_u16, FieldValue::Unsigned16).parse(input),
        (DataType::Unsigned, 4) => map(be_u32, FieldValue::Unsigned32).parse(input),
        (DataType::Unsigned, 8) => map(be_u64, FieldValue::Unsigned64).parse(input),
        (DataType::Signed, 1) => map(be_i8, FieldValue::Signed8).parse(input),
        (DataType::Signed, 2) => map(be_i16, FieldValue::Signed16).parse(input),
        (DataType::Signed, 4) => map(be_i32, FieldValue::Signed32).parse(input),
        (DataType::Signed, 8) => map(be_i64, FieldValue::Signed64).parse(input),
        (DataType::Float, 4) => map(be_f32, FieldValue::Float32).parse(input),
        (DataType::Float, 8) => map(be_f64, FieldValue::Float64).parse(input),
        (DataType::MacAddress, 6) => map(macaddr6, FieldValue::MacAddress).parse(input),
        (DataType::Ipv4Address, 4) => map(ipv4_addr, FieldValue::Ipv4Address).parse(input),
        (DataType::Ipv6Address, 16) => map(ipv6_addr, FieldValue::Ipv6Address).parse(input),
        (DataType::String, len) => map(string(len), FieldValue::String).parse(input),
        (DataType::DateTimeSeconds, 4) => {
            map(timestamp_secs, FieldValue::DateTimeSeconds).parse(input)
        }
        (DataType::DateTimeMilliseconds, 8) => {
            map(timestamp_millis, FieldValue::DateTimeMilliseconds).parse(input)
        }
        (DataType::DateTimeMicroseconds, 8) => {
            map(timestamp_micros, FieldValue::DateTimeMicroseconds).parse(input)
        }
        (DataType::DateTimeNanoseconds, 8) => {
            map(timestamp_nanos, FieldValue::DateTimeNanoseconds).parse(input)
        }
        _ => map(vector(length), FieldValue::OctetArray).parse(input),
    }
}
