use std::cell::RefCell;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;

use chrono::{TimeZone, Utc};
use macaddr::MacAddr6;
use nom::bytes::complete::take;
use nom::combinator::{cond, map, verify};
use nom::multi::{fold_many1, many, many1};
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom::{IResult, Parser as _};
use primitive_types::U256;
use rustc_hash::FxHashMap;

use crate::ie_registry::{DataType, IERegistry};
use crate::templates_manager::TemplatesManager;
use crate::types::{
    BasicList, DataRecord, FieldSpecifier, FieldValue, Message, OptionsTemplateRecord, Record,
    Semantic, Set, SubTemplateList, SubTemplateMultiItem, SubTemplateMultiList, TemplateRecord,
};

pub const IPFIX_VERSION: u16 = 10;

pub const TEMPLATE_SET_ID: u16 = 2;

pub struct Parser {
    templates_manager: RefCell<TemplatesManager>,
}

impl Parser {
    /// Create a new parser with the default IANA IE registry.
    pub fn new() -> Self {
        Self {
            templates_manager: RefCell::new(TemplatesManager::new()),
        }
    }

    /// Create a new parser with a custom IE registry.
    pub fn with_registry(registry: IERegistry) -> Self {
        Self {
            templates_manager: RefCell::new(TemplatesManager::with_registry(registry)),
        }
    }

    /// Parse an IPFIX message from raw bytes.
    ///
    /// Returns the parsed message and any remaining unparsed bytes.
    pub fn parse<'a>(&'a self, input: &'a [u8]) -> IResult<&'a [u8], Message> {
        parse_message(input, &self.templates_manager)
    }

    /// Clear all stored templates.
    pub fn clear_templates(&self) {
        self.templates_manager.borrow_mut().clear();
    }

    /// Get a reference to the templates manager.
    pub fn templates_manager(&self) -> &RefCell<TemplatesManager> {
        &self.templates_manager
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

pub const OPTIONS_TEMPLATE_SET_ID: u16 = 3;

pub const VALID_TEMPLATE_ID_RANGE: RangeInclusive<u16> = 256..=65535;

pub const VARIABLE_LENGTH: u16 = 0xffff;

/// Context for parsing structured data types that require template lookups
pub struct ParserContext<'a> {
    pub templates_manager: &'a TemplatesManager,
    pub ie_registry: &'a IERegistry,
    pub observation_domain_id: u32,
}

fn parse_semantic(value: u8) -> Semantic {
    match value {
        0x00 => Semantic::NoneOf,
        0x01 => Semantic::ExactlyOneOf,
        0x02 => Semantic::OneOrMoreOf,
        0x03 => Semantic::AllOf,
        0x04 => Semantic::Ordered,
        _ => Semantic::Undefined,
    }
}

pub fn parse_message<'a>(
    input: &'a [u8],
    templates_manager: &'a RefCell<TemplatesManager>,
) -> IResult<&'a [u8], Message> {
    let (input, version) = verify(be_u16, |i| *i == IPFIX_VERSION).parse(input)?;
    let (input, length) = be_u16(input)?;

    let (_, input) = take(length as usize - 4)(input)?;

    let (input, export_time) = be_u32(input)?;
    let (input, sequence_number) = be_u32(input)?;
    let (input, observation_domain_id) = be_u32(input)?;

    let (input, sets) = many1(|i| {
        parse_set(
            i,
            &mut templates_manager.borrow_mut(),
            observation_domain_id,
        )
    })
    .parse(input)?;

    Ok((
        input,
        Message {
            version,
            length,
            export_time,
            sequence_number,
            observation_domain_id,
            sets,
        },
    ))
}

pub fn parse_set<'a>(
    input: &'a [u8],
    templates_manager: &mut TemplatesManager,
    observation_domain_id: u32,
) -> IResult<&'a [u8], Set> {
    let (input, set_id) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let (input, set_body) = take(length as usize - 4)(input)?;

    let (_, records) = match set_id {
        TEMPLATE_SET_ID => fold_many1(
            map(parse_template_record, |i| {
                templates_manager
                    .add_template((observation_domain_id, i.template_id), i.fields.clone());
                i
            }),
            || Vec::with_capacity(16),
            |mut acc, record| {
                acc.push(Record::Template(record));
                acc
            },
        )
        .parse(set_body)?,
        OPTIONS_TEMPLATE_SET_ID => fold_many1(
            map(parse_options_template_record, |i| {
                templates_manager
                    .add_template((observation_domain_id, i.template_id), i.fields.clone());
                i
            }),
            || Vec::with_capacity(16),
            |mut acc, record| {
                acc.push(Record::OptionsTemplate(record));
                acc
            },
        )
        .parse(set_body)?,
        _ => {
            let template = templates_manager
                .get_template((observation_domain_id, set_id))
                .ok_or_else(|| {
                    nom::Err::Error(nom::error::Error::new(
                        set_body,
                        nom::error::ErrorKind::Verify,
                    ))
                })?;
            let fields = &template.fields;
            let ie_registry = templates_manager.ie_registry();

            let ctx = ParserContext {
                templates_manager,
                ie_registry,
                observation_domain_id,
            };

            fold_many1(
                |i| parse_data_record_with_context(i, fields, &ctx),
                || Vec::with_capacity(16),
                |mut acc, record| {
                    acc.push(Record::Data(record));
                    acc
                },
            )
            .parse(set_body)?
        }
    };

    Ok((
        input,
        Set {
            set_id,
            length,
            records,
        },
    ))
}

fn parse_template_record(input: &[u8]) -> IResult<&[u8], TemplateRecord> {
    let (input, template_id) =
        verify(be_u16, |i| VALID_TEMPLATE_ID_RANGE.contains(i)).parse(input)?;
    let (input, field_count) = be_u16(input)?;
    let (input, fields) = many(field_count as usize, parse_field_specifier).parse(input)?;

    Ok((
        input,
        TemplateRecord {
            template_id,
            field_count,
            fields,
        },
    ))
}

fn parse_options_template_record(input: &[u8]) -> IResult<&[u8], OptionsTemplateRecord> {
    let (input, template_id) =
        verify(be_u16, |i| VALID_TEMPLATE_ID_RANGE.contains(i)).parse(input)?;
    let (input, field_count) = be_u16(input)?;
    let (input, scope_field_count) = be_u16(input)?;
    let (input, fields) = many(field_count as usize, parse_field_specifier).parse(input)?;

    Ok((
        input,
        OptionsTemplateRecord {
            template_id,
            field_count,
            scope_field_count,
            fields,
        },
    ))
}

fn parse_field_specifier(input: &[u8]) -> IResult<&[u8], FieldSpecifier> {
    let (input, enterprise_bit_and_information_element_identifier) = be_u16(input)?;

    let enterprise_bit = enterprise_bit_and_information_element_identifier & 0x8000 != 0;
    let information_element_identifier = enterprise_bit_and_information_element_identifier & 0x7fff;

    let (input, field_length) = be_u16(input)?;
    let (input, enterprise_number) = cond(enterprise_bit, be_u32).parse(input)?;

    Ok((
        input,
        FieldSpecifier {
            enterprise_bit,
            information_element_identifier,
            field_length,
            enterprise_number,
        },
    ))
}

fn parse_unsigned(data: &[u8], length: u16) -> FieldValue {
    match length {
        1 => FieldValue::Unsigned8(data[0]),
        2 => FieldValue::Unsigned16(u16::from_be_bytes(data.try_into().unwrap())),
        4 => FieldValue::Unsigned32(u32::from_be_bytes(data.try_into().unwrap())),
        8 => FieldValue::Unsigned64(u64::from_be_bytes(data.try_into().unwrap())),
        _ => {
            let mut bytes = [0u8; 32];
            let start = 32 - data.len().min(32);
            bytes[start..].copy_from_slice(&data[..data.len().min(32)]);
            FieldValue::Unsigned256(U256::from_big_endian(&bytes))
        }
    }
}

fn parse_unsigned_raw(data: &[u8], length: u16) -> u64 {
    match length {
        1 => data[0] as u64,
        2 => u16::from_be_bytes(data.try_into().unwrap()) as u64,
        4 => u32::from_be_bytes(data.try_into().unwrap()) as u64,
        8 => u64::from_be_bytes(data.try_into().unwrap()),
        _ => {
            let mut result = 0u64;
            for &b in data.iter().take(8) {
                result = (result << 8) | (b as u64);
            }
            result
        }
    }
}

fn parse_signed(data: &[u8], length: u16) -> FieldValue {
    match length {
        1 => FieldValue::Signed8(data[0] as i8),
        2 => FieldValue::Signed16(i16::from_be_bytes(data.try_into().unwrap())),
        4 => FieldValue::Signed32(i32::from_be_bytes(data.try_into().unwrap())),
        8 => FieldValue::Signed64(i64::from_be_bytes(data.try_into().unwrap())),
        _ => FieldValue::Signed64(i64::from_be_bytes(data[..8].try_into().unwrap_or([0; 8]))),
    }
}

fn parse_float(data: &[u8], length: u16) -> FieldValue {
    match length {
        4 => FieldValue::Float32(f32::from_be_bytes(data.try_into().unwrap())),
        8 => FieldValue::Float64(f64::from_be_bytes(data.try_into().unwrap())),
        _ => FieldValue::Float64(0.0),
    }
}

fn parse_basic_list<'a>(input: &'a [u8], ctx: &ParserContext<'_>) -> IResult<&'a [u8], BasicList> {
    let (input, semantic_byte) = be_u8(input)?;
    let semantic = parse_semantic(semantic_byte);

    let (input, field) = parse_field_specifier(input)?;

    let data_type = ctx
        .ie_registry
        .lookup(
            field.information_element_identifier,
            field.enterprise_number,
        )
        .map(|def| &def.data_type);

    let element_length = field.field_length;
    let mut content = Vec::new();
    let mut remaining = input;

    while !remaining.is_empty() {
        let (rest, value) =
            parse_field_value_with_context(remaining, element_length, data_type, Some(ctx))?;
        content.push(value);
        remaining = rest;
    }

    Ok((
        &[][..],
        BasicList {
            semantic,
            field,
            content,
        },
    ))
}

fn parse_subtemplate_list<'a>(
    input: &'a [u8],
    ctx: &ParserContext<'_>,
) -> IResult<&'a [u8], SubTemplateList> {
    let (input, semantic_byte) = be_u8(input)?;
    let semantic = parse_semantic(semantic_byte);

    let (input, template_id) = be_u16(input)?;

    let template_key = (ctx.observation_domain_id, template_id);
    let template = ctx
        .templates_manager
        .get_template(template_key)
        .ok_or_else(|| {
            nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;

    let mut data = Vec::new();
    let mut remaining = input;

    while !remaining.is_empty() {
        let (rest, record) = parse_data_record_with_context(remaining, &template.fields, ctx)?;
        data.push(record);
        remaining = rest;
    }

    Ok((
        &[][..],
        SubTemplateList {
            semantic,
            template_id,
            data,
        },
    ))
}

/// Parse a SubTemplateMultiList (IE 293) according to RFC 6313 Section 4.5.3
/// Format:
/// - 1 byte: semantic
/// - Multiple items, each: template ID (2) + content length (2) + records
fn parse_subtemplate_multi_list<'a>(
    input: &'a [u8],
    ctx: &ParserContext<'_>,
) -> IResult<&'a [u8], SubTemplateMultiList> {
    let (input, semantic_byte) = be_u8(input)?;
    let semantic = parse_semantic(semantic_byte);

    let mut data = Vec::new();
    let mut remaining = input;

    while !remaining.is_empty() {
        let (rest, item) = parse_subtemplate_multi_item(remaining, ctx)?;
        data.push(item);
        remaining = rest;
    }

    Ok((&[][..], SubTemplateMultiList { semantic, data }))
}

fn parse_subtemplate_multi_item<'a>(
    input: &'a [u8],
    ctx: &ParserContext<'_>,
) -> IResult<&'a [u8], SubTemplateMultiItem> {
    let (input, template_id) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let (input, item_content) = take(length as usize)(input)?;

    let template_key = (ctx.observation_domain_id, template_id);
    let template = ctx
        .templates_manager
        .get_template(template_key)
        .ok_or_else(|| {
            nom::Err::Error(nom::error::Error::new(
                item_content,
                nom::error::ErrorKind::Verify,
            ))
        })?;

    let mut records = Vec::new();
    let mut item_remaining = item_content;

    while !item_remaining.is_empty() {
        let (rest, record) = parse_data_record_with_context(item_remaining, &template.fields, ctx)?;
        records.push(record);
        item_remaining = rest;
    }

    Ok((
        input,
        SubTemplateMultiItem {
            template_id,
            length,
            data: records,
        },
    ))
}

fn parse_data_record_with_context<'a>(
    input: &'a [u8],
    fields: &[FieldSpecifier],
    ctx: &ParserContext<'_>,
) -> IResult<&'a [u8], DataRecord> {
    let mut remaining = input;
    let mut record = FxHashMap::default();

    for field in fields {
        let enterprise_number = field.enterprise_number.unwrap_or(0);
        let key = (enterprise_number, field.information_element_identifier);

        let data_type = ctx
            .ie_registry
            .lookup(
                field.information_element_identifier,
                field.enterprise_number,
            )
            .map(|def| &def.data_type);

        let (rest, value) =
            parse_field_value_with_context(remaining, field.field_length, data_type, Some(ctx))?;
        record.insert(key, value);
        remaining = rest;
    }

    Ok((remaining, DataRecord(record)))
}

fn parse_field_value_with_context<'a>(
    input: &'a [u8],
    length: u16,
    data_type: Option<&DataType>,
    ctx: Option<&ParserContext<'_>>,
) -> IResult<&'a [u8], FieldValue> {
    let (input, length) = if length == VARIABLE_LENGTH {
        let (input, first_byte) = be_u8(input)?;
        if first_byte < 255 {
            (input, first_byte as u16)
        } else {
            let (input, len) = be_u16(input)?;
            (input, len)
        }
    } else {
        (input, length)
    };

    let (input, field_data) = take(length as usize)(input)?;

    let value = match data_type {
        Some(DataType::Unsigned) => parse_unsigned(field_data, length),
        Some(DataType::Signed) => parse_signed(field_data, length),
        Some(DataType::Float) => parse_float(field_data, length),
        Some(DataType::Boolean) => {
            FieldValue::Boolean(field_data.first().map_or(false, |&b| b != 0))
        }
        Some(DataType::MacAddress) => {
            let bytes: [u8; 6] = field_data.try_into().unwrap_or([0; 6]);
            FieldValue::MacAddress(MacAddr6::from(bytes))
        }
        Some(DataType::String) => {
            let s = String::from_utf8_lossy(field_data)
                .trim_end_matches('\0')
                .to_string();
            FieldValue::String(s)
        }
        Some(DataType::Ipv4Address) => {
            let bytes: [u8; 4] = field_data.try_into().unwrap_or([0; 4]);
            FieldValue::Ipv4Address(Ipv4Addr::from(bytes))
        }
        Some(DataType::Ipv6Address) => {
            let bytes: [u8; 16] = field_data.try_into().unwrap_or([0; 16]);
            FieldValue::Ipv6Address(Ipv6Addr::from(bytes))
        }
        Some(DataType::DateTimeSeconds) => {
            let secs = parse_unsigned_raw(field_data, length);
            let dt = Utc.timestamp_opt(secs as i64, 0).single().ok_or_else(|| {
                nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
            })?;
            FieldValue::DateTimeSeconds(dt)
        }
        Some(DataType::DateTimeMilliseconds) => {
            let millis = parse_unsigned_raw(field_data, length);
            let secs = (millis / 1000) as i64;
            let nanos = ((millis % 1000) * 1_000_000) as u32;
            let dt = Utc.timestamp_opt(secs, nanos).single().ok_or_else(|| {
                nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
            })?;
            FieldValue::DateTimeMilliseconds(dt)
        }
        Some(DataType::DateTimeMicroseconds) => {
            let micros = parse_unsigned_raw(field_data, length);
            let secs = (micros / 1_000_000) as i64;
            let nanos = ((micros % 1_000_000) * 1_000) as u32;
            let dt = Utc.timestamp_opt(secs, nanos).single().ok_or_else(|| {
                nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
            })?;
            FieldValue::DateTimeMicroseconds(dt)
        }
        Some(DataType::DateTimeNanoseconds) => {
            let nanos = parse_unsigned_raw(field_data, length);
            let secs = (nanos / 1_000_000_000) as i64;
            let nanos = (nanos % 1_000_000_000) as u32;
            let dt = Utc.timestamp_opt(secs, nanos).single().ok_or_else(|| {
                nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
            })?;
            FieldValue::DateTimeNanoseconds(dt)
        }
        Some(DataType::OctetArray) | None => FieldValue::OctetArray(field_data.to_vec()),
        Some(DataType::BasicList) => {
            if let Some(ctx) = ctx {
                match parse_basic_list(field_data, ctx) {
                    Ok((_, list)) => FieldValue::BasicList(list),
                    Err(_) => FieldValue::OctetArray(field_data.to_vec()),
                }
            } else {
                FieldValue::OctetArray(field_data.to_vec())
            }
        }
        Some(DataType::SubTemplateList) => {
            if let Some(ctx) = ctx {
                match parse_subtemplate_list(field_data, ctx) {
                    Ok((_, list)) => FieldValue::SubTemplateList(list),
                    Err(_) => FieldValue::OctetArray(field_data.to_vec()),
                }
            } else {
                FieldValue::OctetArray(field_data.to_vec())
            }
        }
        Some(DataType::SubTemplateMultiList) => {
            if let Some(ctx) = ctx {
                match parse_subtemplate_multi_list(field_data, ctx) {
                    Ok((_, list)) => FieldValue::SubTemplateMultiList(list),
                    Err(_) => FieldValue::OctetArray(field_data.to_vec()),
                }
            } else {
                FieldValue::OctetArray(field_data.to_vec())
            }
        }
    };

    Ok((input, value))
}
