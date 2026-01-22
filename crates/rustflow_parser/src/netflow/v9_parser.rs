use std::cell::RefCell;

use chrono::{DateTime, Utc};
use nom::bytes::complete::take;
use nom::combinator::{map, map_opt, verify};
use nom::multi::{fold_many1, many0};
use nom::number::complete::{be_u16, be_u32};
use nom::{IResult, Parser};

use crate::parser::{ParserContext, parse_data_record_with_context, parse_template_record};
use crate::templates_manager::TemplatesManager;
use crate::types::{FieldSpecifier, Message, OptionsTemplateRecord, Record, Set};

const NETFLOW_V9_VERSION: u16 = 9;

const TEMPLATE_FLOW_SET_ID: u16 = 0;

const OPTIONS_TEMPLATE_FLOW_SET_ID: u16 = 1;

fn parse_timestamp_millis(input: &[u8]) -> IResult<&[u8], DateTime<Utc>> {
    map_opt(be_u32, |t| DateTime::<Utc>::from_timestamp_millis(t as i64)).parse(input)
}

fn parse_timestamp_secs(input: &[u8]) -> IResult<&[u8], DateTime<Utc>> {
    map_opt(be_u32, |t| DateTime::<Utc>::from_timestamp_secs(t as i64)).parse(input)
}

pub fn parse_message<'a>(
    input: &'a [u8],
    templates_manager: &'a RefCell<TemplatesManager>,
) -> IResult<&'a [u8], Message> {
    let (input, version) = verify(be_u16, |i| *i == NETFLOW_V9_VERSION).parse(input)?;
    let (input, count) = be_u16(input)?;
    let (input, system_uptime) = parse_timestamp_millis(input)?;
    let (input, unix_secs) = parse_timestamp_secs(input)?;
    let (input, sequence_number) = be_u32(input)?;
    let (input, source_id) = be_u32(input)?;

    let (input, sets) =
        many0(|i| parse_set(i, &mut templates_manager.borrow_mut(), source_id)).parse(input)?;

    Ok((
        input,
        Message {
            version,
            length: 0,
            export_time: unix_secs,
            sequence_number,
            observation_domain_id: source_id,
            nf_count: count,
            nf_system_uptime: Some(system_uptime),
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
                templates_manager.add_template((source_id, i.template_id), i.fields.clone());
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
                templates_manager.add_template((source_id, i.template_id), i.fields.clone());
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

fn parse_field_definition(input: &[u8]) -> IResult<&[u8], FieldSpecifier> {
    let (input, field_type) = be_u16(input)?;
    let (input, field_length) = be_u16(input)?;

    Ok((
        input,
        FieldSpecifier {
            enterprise_bit: false,
            information_element_identifier: field_type,
            field_length,
            enterprise_number: None,
        },
    ))
}
