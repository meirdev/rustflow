use std::cell::RefCell;

use chrono::{DateTime, Utc};
use nom::bytes::complete::take;
use nom::combinator::{fail, map, map_opt, verify};
use nom::multi::{fold_many1, many, many0, many1};
use nom::number::complete::{be_u16, be_u32};
use nom::{IResult, Parser, ToUsize};
use rustc_hash::FxHashMap;

use crate::netflow::v9_types::{
    FieldDefinition, Message, OptionsTemplateRecord, Record, Set, TemplateRecord,
};
use crate::parser::{ParserContext, parse_field_value_with_context};
use crate::templates_manager::TemplatesManager;
use crate::types::{DataRecord, FieldSpecifier};

const NETFLOW_V9_VERSION: u16 = 9;

const TEMPLATE_FLOW_SET_ID: u16 = 0;

const OPTIONS_TEMPLATE_FLOW_SET_ID: u16 = 1;

const DATA_FLOW_SET_ID_RANGE: std::ops::RangeInclusive<u16> = 256..=65535;

fn parse_timestamp(input: &[u8]) -> IResult<&[u8], DateTime<Utc>> {
    map_opt(be_u32, |t| DateTime::<Utc>::from_timestamp_millis(t as i64)).parse(input)
}

pub fn parse_message<'a>(
    input: &'a [u8],
    templates_manager: &'a RefCell<TemplatesManager>,
) -> IResult<&'a [u8], Message> {
    let (input, version) = verify(be_u16, |i| *i == NETFLOW_V9_VERSION).parse(input)?;
    let (input, count) = be_u16(input)?;
    let (input, sys_uptime) = parse_timestamp(input)?;
    let (input, unix_time) = parse_timestamp(input)?;
    let (input, sequence_number) = be_u32(input)?;
    let (input, source_id) = be_u32(input)?;

    let (input, sets) =
        many0(|i| parse_set(i, &mut templates_manager.borrow_mut(), source_id)).parse(input)?;

    Ok((
        input,
        Message {
            version,
            count,
            sys_uptime,
            unix_time,
            sequence_number,
            source_id,
            sets,
        },
    ))
}

fn parse_set<'a>(
    input: &'a [u8],
    templates_manager: &mut TemplatesManager,
    source_id: u32,
) -> IResult<&'a [u8], Set> {
    let (input, set_id) = be_u16(input)?;
    let (input, length) = be_u16(input)?;

    let (input, set_body) = take(length - 4)(input)?;

    let (_, records) = match set_id {
        TEMPLATE_FLOW_SET_ID => fold_many1(
            map(parse_template_record, |i| {
                templates_manager.add_template(
                    (source_id, i.template_id),
                    i.fields
                        .iter()
                        .map(|i| FieldSpecifier {
                            enterprise_bit: false,
                            information_element_identifier: i.field_type,
                            field_length: i.field_length,
                            enterprise_number: None,
                        })
                        .collect(),
                );
                i
            }),
            || Vec::with_capacity(16),
            |mut acc, record| {
                acc.push(Record::Template(record));
                acc
            },
        )
        .parse(set_body)?,
        OPTIONS_TEMPLATE_FLOW_SET_ID => fold_many1(
            map(parse_options_template_record, |i| {
                templates_manager.add_template(
                    (source_id, i.template_id),
                    i.fields
                        .iter()
                        .map(|i| FieldSpecifier {
                            enterprise_bit: false,
                            information_element_identifier: i.field_type,
                            field_length: i.field_length,
                            enterprise_number: None,
                        })
                        .collect(),
                );
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
                .get_template((source_id, set_id))
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
                observation_domain_id: source_id,
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
    let (input, template_id) = be_u16(input)?;
    let (input, field_count) = be_u16(input)?;
    let (input, fields) = many(field_count.to_usize(), parse_field_definition).parse(input)?;

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
    let (input, template_id) = be_u16(input)?;
    let (input, option_scope_length) = be_u16(input)?;
    let (input, option_length) = be_u16(input)?;

    let (input, scope_fields) = take(option_scope_length)(input)?;
    let (_, mut scope_fields) = many0(parse_field_definition).parse(scope_fields)?;

    let (input, option_fields) = take(option_length)(input)?;
    let (_, mut option_fields) = many0(parse_field_definition).parse(option_fields)?;

    let mut fields = vec![];
    fields.append(&mut scope_fields);
    fields.append(&mut option_fields);

    Ok((
        input,
        OptionsTemplateRecord {
            template_id,
            field_count: fields.len() as u16,
            scope_field_count: scope_fields.len() as u16,
            fields,
        },
    ))
}

fn parse_field_definition(input: &[u8]) -> IResult<&[u8], FieldDefinition> {
    let (input, field_type) = be_u16(input)?;
    let (input, field_length) = be_u16(input)?;

    Ok((
        input,
        FieldDefinition {
            field_type,
            field_length,
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
        let key = (0, field.information_element_identifier);

        let data_type = ctx
            .ie_registry
            .lookup(field.information_element_identifier, None)
            .map(|def| &def.data_type);

        let (rest, value) =
            parse_field_value_with_context(remaining, field.field_length, data_type, Some(ctx))?;
        record.insert(key, value);
        remaining = rest;
    }

    Ok((remaining, DataRecord(record)))
}
