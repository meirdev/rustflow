// RPC-7011
// https://datatracker.ietf.org/doc/html/rfc7011

use nom::bytes::complete::take;
use nom::combinator::{cond, peek, verify};
use nom::multi::{length_data, many, many0, many1};
use nom::number::complete::{be_u16, be_u32};
use nom::sequence::preceded;
use nom::Parser;
use nom::{IResult, ToUsize};
use rustflow_types::ipfix::{
    DataRecord, FieldSpecifier, Header, OptionsTemplateRecord, OptionsTemplateRecordHeader, Record,
    Set, SetHeader, TemplateRecord, TemplateRecordHeader, TemplateRecordType, IPFIX, IPFIX_VERSION,
    OPTIONS_TEMPLATE_SET_ID, TEMPLATE_SET_ID,
};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct IPFIXParser {
    templates: HashMap<u16, TemplateRecordType>,
}

impl Default for IPFIXParser {
    fn default() -> Self {
        IPFIXParser {
            templates: HashMap::new(),
        }
    }
}

impl<'a> IPFIXParser {
    pub fn parse(&'a mut self, input: &'a [u8]) -> IResult<&'a [u8], IPFIX<'a>> {
        parse_ipfix(&mut self.templates)(input)
    }
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, version) = verify(be_u16, |i| *i == IPFIX_VERSION).parse(input)?;
    let (input, length) = be_u16(input)?;
    let (input, export_time) = be_u32(input)?;
    let (input, sequence_number) = be_u32(input)?;
    let (input, observation_domain_id) = be_u32(input)?;

    Ok((
        input,
        Header {
            version,
            length,
            export_time,
            sequence_number,
            observation_domain_id,
        },
    ))
}

fn parse_length(input: &[u8]) -> IResult<&[u8], &[u8]> {
    length_data(peek(preceded(be_u16, be_u16))).parse(input)
}

fn parse_set_header(input: &[u8]) -> IResult<&[u8], SetHeader> {
    let (input, set_id) = be_u16(input)?;
    let (input, length) = be_u16(input)?;

    Ok((input, SetHeader { set_id, length }))
}

fn parse_set(
    templates: &HashMap<u16, TemplateRecordType>,
) -> impl Fn(&[u8]) -> IResult<&[u8], Set> {
    move |input| {
        let (rest, input) = parse_length(input)?;

        let (input, header) = parse_set_header(input)?;

        return if header.set_id == TEMPLATE_SET_ID {
            let (_, records) = many0(parse_template_record).parse(input)?;
            Ok((rest, Set { header, records }))
        } else if header.set_id == OPTIONS_TEMPLATE_SET_ID {
            let (_, records) = many0(parse_options_template_record).parse(input)?;
            Ok((rest, Set { header, records }))
        } else {
            let template = templates.get(&header.set_id).ok_or_else(|| {
                nom::Err::Error(nom::error::make_error(input, nom::error::ErrorKind::Tag))
            })?;

            let (_, records) = many0(parse_data_record(template)).parse(input)?;

            Ok((rest, Set { header, records }))
        };
    }
}

fn parse_field_specifier(input: &[u8]) -> IResult<&[u8], FieldSpecifier> {
    let (input, information_element_identifier) = be_u16(input)?;
    let (input, field_length) = be_u16(input)?;
    let (input, enterprise_number) =
        cond(information_element_identifier & 0x8000 == 1, be_u32).parse(input)?;

    Ok((
        input,
        FieldSpecifier {
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
    let (input, header) = parse_template_record_header.parse(input)?;
    let (input, fields) =
        many(0..=header.field_count.to_usize(), parse_field_specifier).parse(input)?;

    Ok((input, Record::Template(TemplateRecord { header, fields })))
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
    let (input, header) = parse_options_template_record_header.parse(input)?;
    let (input, fields) =
        many(0..=header.field_count.to_usize(), parse_field_specifier).parse(input)?;
    let (input, scope_fields) = many(
        0..=header.scope_field_count.to_usize(),
        parse_field_specifier,
    )
    .parse(input)?;

    Ok((
        input,
        Record::OptionsTemplate(OptionsTemplateRecord {
            header,
            fields,
            scope_fields,
        }),
    ))
}

fn parse_data_record(template: &TemplateRecordType) -> impl Fn(&[u8]) -> IResult<&[u8], Record> {
    move |input| {
        let mut input = input;

        match template {
            TemplateRecordType::Template(template_record) => {
                let mut values = Vec::new();

                for field in template_record.fields.iter() {
                    let (input_, value) = take(field.field_length)(input)?;

                    values.push(value);

                    input = input_;
                }

                Ok((input, Record::Data(DataRecord { fields: values })))
            }
            TemplateRecordType::OptionsTemplate(options_template_record) => {
                let mut values = Vec::new();

                for field in options_template_record.fields.iter() {
                    let (input_, value) = take(field.field_length)(input)?;

                    values.push(value);

                    input = input_;
                }

                for field in options_template_record.scope_fields.iter() {
                    let (input_, value) = take(field.field_length)(input)?;

                    values.push(value);

                    input = input_;
                }

                Ok((input, Record::Data(DataRecord { fields: values })))
            }
        }
    }
}

fn parse_ipfix(
    templates: &mut HashMap<u16, TemplateRecordType>,
) -> impl FnMut(&[u8]) -> IResult<&[u8], IPFIX> {
    move |input| {
        let (input, header) = parse_header(input)?;
        let (input, sets) = many0(parse_set(templates)).parse(input)?;

        for set in sets.iter() {
            for record in set.records.iter() {
                match record {
                    Record::Template(template_record) => {
                        templates.insert(
                            template_record.header.template_id,
                            TemplateRecordType::Template(template_record.clone()),
                        );
                    }
                    Record::OptionsTemplate(options_template_record) => {
                        templates.insert(
                            options_template_record.header.template_id,
                            TemplateRecordType::OptionsTemplate(options_template_record.clone()),
                        );
                    }
                    _ => {}
                }
            }
        }

        Ok((input, IPFIX { header, sets }))
    }
}
