use std::collections::HashMap;

use nom::Parser;
use nom::bytes::complete::take;
use nom::combinator::{cond, fail, peek, verify};
use nom::multi::{length_data, many, many1};
use nom::number::complete::{be_u16, be_u32};
use nom::sequence::preceded;
use nom::{IResult, ToUsize};

use crate::ipfix::packet::{
    DataRecord, DataRecordField, FieldSpecifier, IPFIX_VERSION, Ipfix, MessageHeader,
    OPTIONS_TEMPLATE_SET_ID, OptionsTemplateRecord, OptionsTemplateRecordHeader, Record, Set,
    SetHeader, TEMPLATE_SET_ID, TemplateRecord, TemplateRecordHeader, TemplateRecordType,
};

type ObservationDomain = u32;
type TemplateId = u16;
type TemplateKey = (ObservationDomain, TemplateId);

type Templates = HashMap<TemplateKey, TemplateRecordType>;

#[derive(Debug, Clone)]
pub struct IpfixParser {
    templates: Templates,
}

impl Default for IpfixParser {
    fn default() -> Self {
        IpfixParser {
            templates: HashMap::new(),
        }
    }
}

impl IpfixParser {
    pub fn parse<'a>(&'a self, input: &'a [u8]) -> IResult<&'a [u8], Ipfix> {
        parse_ipfix(&self.templates)(input)
    }

    pub fn register_template(
        &mut self,
        source_id: ObservationDomain,
        template_id: TemplateId,
        template_record: TemplateRecordType,
    ) {
        self.templates
            .insert((source_id, template_id), template_record);
    }

    pub fn remove_template(&mut self, source_id: ObservationDomain, template_id: TemplateId) {
        self.templates.remove(&(source_id, template_id));
    }
}

fn parse_message_header(input: &[u8]) -> IResult<&[u8], MessageHeader> {
    let (input, version) = verify(be_u16, |i| *i == IPFIX_VERSION).parse(input)?;
    let (input, length) = be_u16(input)?;
    let (input, export_time) = be_u32(input)?;
    let (input, sequence_number) = be_u32(input)?;
    let (input, observation_domain_id) = be_u32(input)?;

    Ok((
        input,
        MessageHeader {
            version,
            length,
            export_time,
            sequence_number,
            observation_domain_id,
        },
    ))
}

fn parse_set_header(input: &[u8]) -> IResult<&[u8], SetHeader> {
    let (input, set_id) = be_u16(input)?;
    let (input, length) = be_u16(input)?;

    Ok((input, SetHeader { set_id, length }))
}

fn parse_set(templates: &Templates) -> impl Fn(&[u8]) -> IResult<&[u8], Set> {
    move |input| {
        let (rest, input) = length_data(peek(preceded(be_u16, be_u16))).parse(input)?;

        let (input, set_header) = parse_set_header(input)?;

        let (_, records) = match set_header.set_id {
            TEMPLATE_SET_ID => many1(parse_template_record).parse(input)?,
            OPTIONS_TEMPLATE_SET_ID => many1(parse_options_template_record).parse(input)?,
            _ => {
                if let Some(template) = templates.get(&(0, set_header.set_id)) {
                    many1(parse_data_record(template)).parse(input)?
                } else {
                    fail().parse(input)?
                }
            }
        };

        Ok((
            rest,
            Set {
                set_header,
                records,
            },
        ))
    }
}

fn parse_field_specifier(input: &[u8]) -> IResult<&[u8], FieldSpecifier> {
    let (input, enterprise_bit_and_information_element_identifier) = be_u16(input)?;

    let enterprise_bit: u16 = if enterprise_bit_and_information_element_identifier & 0x8000 != 0 {
        1
    } else {
        0
    };

    let information_element_identifier = enterprise_bit_and_information_element_identifier & 0x7FFF;

    let (input, field_length) = be_u16(input)?;
    let (input, enterprise_number) = cond(enterprise_bit == 1, be_u32).parse(input)?;

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

fn parse_template_record_header(input: &[u8]) -> IResult<&[u8], TemplateRecordHeader> {
    let (input, template_id) = verify(be_u16, |i| *i > 255).parse(input)?;
    let (input, field_count) = be_u16(input)?;

    Ok((
        input,
        TemplateRecordHeader {
            template_id,
            field_count,
        },
    ))
}

fn parse_template_record(input: &[u8]) -> IResult<&[u8], Record> {
    let (input, template_record_header) = parse_template_record_header.parse(input)?;
    let (input, fields) = many(
        0..=template_record_header.field_count.to_usize(),
        parse_field_specifier,
    )
    .parse(input)?;

    Ok((
        input,
        Record::Template(TemplateRecord {
            template_record_header,
            fields,
        }),
    ))
}

fn parse_options_template_record_header(
    input: &[u8],
) -> IResult<&[u8], OptionsTemplateRecordHeader> {
    let (input, template_id) = verify(be_u16, |i| *i > 255).parse(input)?;
    let (input, field_count) = be_u16(input)?;
    let (input, scope_field_count) = be_u16(input)?;

    Ok((
        input,
        OptionsTemplateRecordHeader {
            template_id,
            field_count,
            scope_field_count,
        },
    ))
}

fn parse_options_template_record(input: &[u8]) -> IResult<&[u8], Record> {
    let (input, options_template_record_header) =
        parse_options_template_record_header.parse(input)?;
    let (input, fields) = many(
        0..=options_template_record_header.field_count.to_usize(),
        parse_field_specifier,
    )
    .parse(input)?;
    let (input, scope_fields) = many(
        0..=options_template_record_header.scope_field_count.to_usize(),
        parse_field_specifier,
    )
    .parse(input)?;

    Ok((
        input,
        Record::OptionsTemplate(OptionsTemplateRecord {
            options_template_record_header,
            fields,
            scope_fields,
        }),
    ))
}

fn parse_defined_fields<'a>(
    mut input: &'a [u8],
    field_specifiers: &[FieldSpecifier],
) -> IResult<&'a [u8], Vec<DataRecordField>> {
    let mut values = Vec::new();

    for field_spec in field_specifiers {
        let mut value_bytes: &'a [u8];

        if field_spec.field_length == 0xffff {
            let (input_, value_length) = be_u8(input)?;

            if value_length < 0xff {
                let (input_, value_bytes) = take(value_length as usize)(input)?;

                input = input_;
            } else {
                let (input_, value_length) = be_u16(input)?;
                let (input_, value_bytes) = take(value_length as usize)(input)?;

                input = input_;
            }
        } else {
            let (input_, value_bytes) = take(field_spec.field_length)(input)?;

            input = input_;
        }

        values.push(DataRecordField(
            field_spec.information_element_identifier,
            value_bytes.into(),
        ));
    }

    Ok((input, values))
}

fn parse_data_record(template: &TemplateRecordType) -> impl Fn(&[u8]) -> IResult<&[u8], Record> {
    move |input| match template {
        TemplateRecordType::Template(template_record) => {
            let (input, fields) = parse_defined_fields(input, &template_record.fields)?;

            Ok((input, Record::Data(DataRecord { fields })))
        }
        TemplateRecordType::OptionsTemplate(options_template_record) => {
            let (input, fields) = parse_defined_fields(input, &options_template_record.fields)?;
            let (input, scope_fields) =
                parse_defined_fields(input, &options_template_record.scope_fields)?;

            Ok((
                input,
                Record::Data(DataRecord {
                    fields: [fields, scope_fields].concat(),
                }),
            ))
        }
    }
}

fn parse_ipfix(templates: &Templates) -> impl FnMut(&[u8]) -> IResult<&[u8], Ipfix> {
    move |input| {
        let (input, message_header) = parse_message_header(input)?;
        let (input, sets) = many1(parse_set(templates)).parse(input)?;

        Ok((
            input,
            Ipfix {
                message_header,
                sets,
            },
        ))
    }
}
