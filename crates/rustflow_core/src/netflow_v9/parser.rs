use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use macaddr::MacAddr6;
use nom::bytes::complete::take;
use nom::combinator::{fail, map, map_parser};
use nom::multi::{count, many0};
use nom::number::complete::{
    be_f32, be_f64, be_i8, be_i16, be_i24, be_i32, be_i64, be_u8, be_u16, be_u24, be_u32, be_u64,
};
use nom::{IResult, Parser, ToUsize};
use num_enum::{FromPrimitive, IntoPrimitive};
use serde::Serialize;

use crate::common::data_record;
use crate::common::ie_registry::{DataType, IERegistry};
use crate::common::parser::{
    be_int, be_uint, ipv4_addr, ipv6_addr, macaddr6, string, timestamp_micros, timestamp_millis,
    timestamp_nanos, timestamp_secs, vector, verify_version,
};
use crate::common::serializer::{serialize_as_hex, serialize_duration_millis, serialize_mac};
use crate::common::timeout_map::TimeoutHashMap;

pub const NETFLOW_V9_VERSION: u16 = 9;
pub const NETFLOW_V9_TEMPLATE_FLOW_SET_ID: u16 = 0;
pub const NETFLOW_V9_OPTIONS_TEMPLATE_FLOW_SET_ID: u16 = 1;

// 2 (id) + 2 (length)
const FLOW_SET_HEADER_SIZE: usize = 4;

// (source_id, template_id)
type TemplateKey = (u32, u16);
type TemplateCache = TimeoutHashMap<TemplateKey, Arc<[ResolvedField]>>;

pub struct NetflowV9Parser {
    pub ie_registry: IERegistry,
    pub templates: TemplateCache,
    pub options_templates: TemplateCache,
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
        parse_netflow_v9(
            input,
            &self.ie_registry,
            &mut self.templates,
            &mut self.options_templates,
        )
    }
}

fn parse_netflow_v9<'a>(
    input: &'a [u8],
    registry: &IERegistry,
    templates: &mut TemplateCache,
    options_templates: &mut TemplateCache,
) -> IResult<&'a [u8], NetFlowV9Packet> {
    let (input, header) = parse_header(input)?;
    // Templates must be installed before decoding later FlowSets in this packet.
    let (input, flow_sets) = many0(|input| {
        parse_flow_set(
            input,
            header.source_id,
            registry,
            templates,
            options_templates,
        )
    })
    .parse(input)?;

    Ok((input, NetFlowV9Packet { header, flow_sets }))
}

fn parse_records<'a>(
    input: &'a [u8],
    source_id: u32,
    flow_set_id: u16,
    registry: &IERegistry,
    templates: &mut TemplateCache,
    options_templates: &mut TemplateCache,
) -> IResult<&'a [u8], Vec<Record>> {
    match flow_set_id {
        NETFLOW_V9_TEMPLATE_FLOW_SET_ID => {
            let (input, records) = many0(parse_template_record).parse(input)?;
            let records = records
                .into_iter()
                .map(|template| {
                    templates.insert(
                        (source_id, template.id),
                        resolve_template(registry, &template),
                    );
                    Record::Template(template)
                })
                .collect();
            Ok((input, records))
        }
        NETFLOW_V9_OPTIONS_TEMPLATE_FLOW_SET_ID => {
            let (input, records) = many0(parse_options_template_record).parse(input)?;
            let records = records
                .into_iter()
                .map(|template| {
                    options_templates.insert(
                        (source_id, template.id),
                        resolve_options_template(registry, &template),
                    );
                    Record::OptionsTemplate(template)
                })
                .collect();
            Ok((input, records))
        }
        template_id => {
            let key = (source_id, template_id);
            if let Some(fields) = templates.get(&key) {
                map(
                    |input| parse_data_records(fields, input),
                    |records| records.into_iter().map(Record::Data).collect(),
                )
                .parse(input)
            } else if let Some(fields) = options_templates.get(&key) {
                map(
                    |input| parse_data_records(fields, input),
                    |records| records.into_iter().map(Record::OptionsData).collect(),
                )
                .parse(input)
            } else {
                log::debug!(
                    "Unknown template for source_id: {source_id}, template_id: {template_id}"
                );
                Ok((&input[input.len()..], vec![]))
            }
        }
    }
}

fn parse_data_records<'a>(
    fields: &Arc<[ResolvedField]>,
    input: &'a [u8],
) -> IResult<&'a [u8], Vec<DataRecord>> {
    if fields.is_empty() {
        return Ok((input, vec![]));
    }

    many0(map(
        |input| parse_data_record(fields, input),
        |values| DataRecord::from_template(Arc::clone(fields), values),
    ))
    .parse(input)
}

fn parse_data_record<'a>(
    fields: &[ResolvedField],
    input: &'a [u8],
) -> IResult<&'a [u8], Vec<FieldValue>> {
    let mut values = Vec::with_capacity(fields.len());
    let mut remaining = input;

    for field in fields {
        let (input, value) =
            parse_field_value(field.data_type, field.spec.length.to_usize(), remaining)?;
        values.push(value);
        remaining = input;
    }

    Ok((remaining, values))
}

impl Default for NetflowV9Parser {
    fn default() -> Self {
        Self::new(IERegistry::default(), Duration::from_mins(10))
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
    #[serde(serialize_with = "serialize_duration_millis")]
    pub system_uptime: TimeDelta,
    pub unix_seconds: DateTime<Utc>,
    pub sequence_number: u32,
    pub source_id: u32,
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, version) = verify_version(input, NETFLOW_V9_VERSION)?;
    let (input, count) = be_u16(input)?;
    let (input, system_uptime) =
        map(be_u32, |ms| TimeDelta::milliseconds(i64::from(ms))).parse(input)?;
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

fn parse_flow_set<'a>(
    input: &'a [u8],
    source_id: u32,
    registry: &IERegistry,
    templates: &mut TemplateCache,
    options_templates: &mut TemplateCache,
) -> IResult<&'a [u8], FlowSet> {
    let (input, id) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let Some(value_length) = length.to_usize().checked_sub(FLOW_SET_HEADER_SIZE) else {
        log::warn!(
            "FlowSet length {length} is shorter than its header. Discarding the rest of the packet."
        );
        return fail().parse(input);
    };
    let (input, body) = take(value_length)(input)?;
    let (_, records) = parse_records(body, source_id, id, registry, templates, options_templates)?;

    Ok((
        input,
        FlowSet {
            id,
            length,
            records,
        },
    ))
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

fn resolve_template(registry: &IERegistry, template: &TemplateRecord) -> Arc<[ResolvedField]> {
    template
        .fields
        .iter()
        .map(|field| ResolvedField::from_registry(registry, field.r#type, field.length))
        .collect()
}

pub type ResolvedField = data_record::ResolvedField<TemplateField>;

impl ResolvedField {
    fn from_registry(registry: &IERegistry, r#type: u16, length: u16) -> Self {
        let (data_type, name) = registry.lookup(r#type, None).map_or_else(
            || (DataType::OctetArray, Arc::from(r#type.to_string())),
            |ie| (ie.data_type, ie.name.clone()),
        );
        Self {
            spec: TemplateField { r#type, length },
            data_type,
            name,
        }
    }
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

fn resolve_options_template(
    registry: &IERegistry,
    template: &OptionsTemplateRecord,
) -> Arc<[ResolvedField]> {
    let scope = template.scope_fields.iter().map(|field| ResolvedField {
        spec: TemplateField {
            r#type: field.r#type.clone().into(),
            length: field.length,
        },
        data_type: DataType::Unsigned,
        name: Arc::from(field.r#type.to_string()),
    });
    let options = template
        .option_fields
        .iter()
        .map(|field| ResolvedField::from_registry(registry, field.r#type, field.length));
    scope.chain(options).collect()
}

#[derive(Debug, Clone, Serialize, strum_macros::Display, FromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum ScopeFieldType {
    System = 1,
    Interface = 2,
    LineCard = 3,
    Cache = 4,
    Template = 5,
    #[num_enum(catch_all)]
    Unknown(u16),
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopeField {
    pub r#type: ScopeFieldType,
    pub length: u16,
}

fn parse_scope_field(input: &[u8]) -> IResult<&[u8], ScopeField> {
    let (input, r#type) = map(be_u16, ScopeFieldType::from).parse(input)?;
    let (input, length) = be_u16(input)?;

    Ok((input, ScopeField { r#type, length }))
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

pub type DataRecord = data_record::DataRecord<TemplateField, FieldValue>;

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
    MacAddress(#[serde(serialize_with = "serialize_mac")] MacAddr6),
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
    input: &[u8],
) -> IResult<&[u8], FieldValue> {
    match (data_type, length) {
        (_, 0) => Ok((input, FieldValue::Null)),
        (DataType::Unsigned, 1) => map(be_u8, FieldValue::Unsigned8).parse(input),
        (DataType::Unsigned, 2) => map(be_u16, FieldValue::Unsigned16).parse(input),
        (DataType::Unsigned, 4) => map(be_u32, FieldValue::Unsigned32).parse(input),
        (DataType::Unsigned, 8) => map(be_u64, FieldValue::Unsigned64).parse(input),
        (DataType::Unsigned, 3) => map(be_u24, FieldValue::Unsigned32).parse(input),
        (DataType::Unsigned, len @ 5..=7) => map(be_uint(len), FieldValue::Unsigned64).parse(input),
        (DataType::Signed, 1) => map(be_i8, FieldValue::Signed8).parse(input),
        (DataType::Signed, 2) => map(be_i16, FieldValue::Signed16).parse(input),
        (DataType::Signed, 4) => map(be_i32, FieldValue::Signed32).parse(input),
        (DataType::Signed, 8) => map(be_i64, FieldValue::Signed64).parse(input),
        (DataType::Signed, 3) => map(be_i24, FieldValue::Signed32).parse(input),
        (DataType::Signed, len @ 5..=7) => map(be_int(len), FieldValue::Signed64).parse(input),
        (DataType::Float, 4) => map(be_f32, FieldValue::Float32).parse(input),
        (DataType::Float, 8) => map(be_f64, FieldValue::Float64).parse(input),
        (DataType::MacAddress, 6) => map(macaddr6, FieldValue::MacAddress).parse(input),
        (DataType::Ipv4Address, 4) => map(ipv4_addr, FieldValue::Ipv4Address).parse(input),
        (DataType::Ipv6Address, 16) => map(ipv6_addr, FieldValue::Ipv6Address).parse(input),
        (DataType::String, len) => map(string(len), |v| {
            v.map_or(FieldValue::Null, FieldValue::String)
        })
        .parse(input),
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

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    const TEMPLATE: [u8; 12] = hex!("0000 000c 0100 0001 0001 0004");
    const DATA: [u8; 8] = hex!("0100 0008 0000002a");
    const OPTIONS_TEMPLATE: [u8; 20] = hex!("0001 0014 0101 0004 0004 0001 0004 0022 0004 0000");
    const OPTIONS_DATA: [u8; 12] = hex!("0101 000c 00000007 00000064");

    fn packet(source_id: u32, count: u16, flow_sets: &[&[u8]]) -> Vec<u8> {
        let mut bytes = NETFLOW_V9_VERSION.to_be_bytes().to_vec();
        bytes.extend(count.to_be_bytes());
        bytes.extend([0; 12]);
        bytes.extend(source_id.to_be_bytes());
        for flow_set in flow_sets {
            bytes.extend_from_slice(flow_set);
        }
        bytes
    }

    #[test]
    fn system_uptime_preserves_wire_milliseconds() {
        for millis in [0u32, 1, 1_234, u32::MAX] {
            let mut bytes = packet(7, 0, &[]);
            bytes[4..8].copy_from_slice(&millis.to_be_bytes());
            bytes.push(0xff);

            let (remaining, header) = parse_header(&bytes).unwrap();

            assert_eq!(header.system_uptime.num_milliseconds(), i64::from(millis));
            assert_eq!(header.source_id, 7);
            assert_eq!(remaining, &[0xff]);
        }
    }

    #[test]
    fn templates_apply_in_wire_order_and_share_resolved_fields() {
        let bytes = packet(7, 4, &[&DATA, &TEMPLATE, &DATA, &DATA]);
        let mut parser = NetflowV9Parser::default();
        let (remaining, packet) = parser.parse(&bytes).unwrap();

        assert!(remaining.is_empty());
        assert_eq!(packet.flow_sets.len(), 4);
        assert!(packet.flow_sets[0].records.is_empty());
        let Record::Template(template) = &packet.flow_sets[1].records[0] else {
            panic!("expected template");
        };
        assert_eq!(template.id, 256);
        assert_eq!(template.fields.len(), 1);
        let fields = parser.templates.get(&(7, 256)).unwrap();
        for flow_set in &packet.flow_sets[2..] {
            let [Record::Data(data)] = flow_set.records.as_slice() else {
                panic!("expected one data record");
            };
            assert!(matches!(data.values(), [FieldValue::Unsigned32(42)]));
            assert_eq!(data.fields()[0].name.as_ref(), "octetDeltaCount");
            assert!(std::ptr::eq(fields.as_ref(), data.fields()));
        }
    }

    #[test]
    fn cached_templates_are_scoped_by_source_and_can_be_replaced() {
        let mut parser = NetflowV9Parser::default();
        parser.parse(&packet(7, 1, &[&TEMPLATE])).unwrap();
        let bytes = packet(8, 1, &[&DATA]);
        let (_, other_source) = parser.parse(&bytes).unwrap();
        assert!(other_source.flow_sets[0].records.is_empty());

        let bytes = packet(7, 1, &[&DATA]);
        let (_, cached) = parser.parse(&bytes).unwrap();
        let Record::Data(cached_data) = &cached.flow_sets[0].records[0] else {
            panic!("expected cached template to decode data");
        };
        assert_eq!(cached_data.fields()[0].name.as_ref(), "octetDeltaCount");

        let replacement = hex!("0000 000c 0100 0001 0002 0004");
        let bytes = packet(7, 2, &[&replacement, &DATA]);
        let (_, updated) = parser.parse(&bytes).unwrap();
        let Record::Data(updated_data) = &updated.flow_sets[1].records[0] else {
            panic!("expected replacement template to decode data");
        };
        assert_eq!(updated_data.fields()[0].name.as_ref(), "packetDeltaCount");
        assert!(matches!(
            updated_data.values(),
            [FieldValue::Unsigned32(42)]
        ));
        assert_eq!(cached_data.fields()[0].name.as_ref(), "octetDeltaCount");
    }

    #[test]
    fn options_templates_decode_scope_before_options_and_are_cached() {
        let mut parser = NetflowV9Parser::default();
        let bytes = packet(7, 2, &[&OPTIONS_TEMPLATE, &OPTIONS_DATA]);
        let (remaining, parsed) = parser.parse(&bytes).unwrap();
        assert!(remaining.is_empty());
        let [Record::OptionsTemplate(template)] = parsed.flow_sets[0].records.as_slice() else {
            panic!("expected one options template despite padding");
        };
        let bytes = packet(7, 1, &[&OPTIONS_DATA]);
        let (_, cached) = parser.parse(&bytes).unwrap();
        assert_eq!(template.id, 257);
        assert_eq!(template.scope_fields.len(), 1);
        assert_eq!(template.option_fields.len(), 1);
        let fields = parser.options_templates.get(&(7, 257)).unwrap();
        for flow_set in [&parsed.flow_sets[1], &cached.flow_sets[0]] {
            let [Record::OptionsData(data)] = flow_set.records.as_slice() else {
                panic!("expected one options data record");
            };
            assert!(matches!(
                data.values(),
                [FieldValue::Unsigned32(7), FieldValue::Unsigned32(100)]
            ));
            assert_eq!(data.fields()[0].name.as_ref(), "System");
            assert_eq!(data.fields()[1].name.as_ref(), "samplingInterval");
            assert!(std::ptr::eq(fields.as_ref(), data.fields()));
        }
    }

    #[test]
    fn data_padding_does_not_consume_the_next_flow_set() {
        let template = hex!("0000 000c 0100 0001 0001 0008");
        let padded_data = hex!("0100 0018 000000000000002a 000000000000002b 00000000");
        let bytes = packet(7, 4, &[&template, &padded_data, &TEMPLATE]);
        let mut parser = NetflowV9Parser::default();
        let (remaining, parsed) = parser.parse(&bytes).unwrap();

        assert!(remaining.is_empty());
        assert_eq!(parsed.flow_sets.len(), 3);
        let [Record::Data(first), Record::Data(second)] = parsed.flow_sets[1].records.as_slice()
        else {
            panic!("expected two records before padding");
        };
        assert!(matches!(first.values(), [FieldValue::Unsigned64(42)]));
        assert!(matches!(second.values(), [FieldValue::Unsigned64(43)]));
        assert!(matches!(
            parsed.flow_sets[2].records.as_slice(),
            [Record::Template(_)]
        ));
    }

    #[test]
    fn truncated_flow_set_is_returned_as_unconsumed_input() {
        let truncated = hex!("0100 000c 0000002a");
        let bytes = packet(7, 2, &[&TEMPLATE, &truncated]);
        let mut parser = NetflowV9Parser::default();
        let (remaining, parsed) = parser.parse(&bytes).unwrap();

        assert_eq!(remaining, truncated);
        assert_eq!(parsed.flow_sets.len(), 1);
        assert!(parser.templates.get(&(7, 256)).is_some());
    }

    #[test]
    fn unknown_fields_keep_their_bytes_and_zero_length_fields_are_null() {
        let template = hex!("0000 0010 0100 0002 ffff 0003 0001 0000");
        let data = hex!("0100 0008 aabbcc 00");
        let bytes = packet(7, 2, &[&template, &data]);
        let mut parser = NetflowV9Parser::default();
        let (remaining, parsed) = parser.parse(&bytes).unwrap();

        assert!(remaining.is_empty());
        let [Record::Data(record)] = parsed.flow_sets[1].records.as_slice() else {
            panic!("expected one data record");
        };
        assert_eq!(record.fields()[0].name.as_ref(), "65535");
        assert!(
            matches!(record.values(), [FieldValue::OctetArray(bytes), FieldValue::Null] if bytes == &hex!("aabbcc"))
        );
    }
}
