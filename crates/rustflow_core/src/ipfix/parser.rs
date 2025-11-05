use std::ops::RangeInclusive;

use nom::bytes::complete::take;
use nom::combinator::{cond, fail, map, verify};
use nom::error::Error;
use nom::multi::{fold_many1, many};
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom::{IResult, Parser};
use rustc_hash::FxHashMap;
use serde::Serialize;

use crate::ipfix::fields::{EnterpriseNumber, FieldId, FieldsMap};
use crate::ipfix::types::DataValue;

pub const IPFIX_VERSION: u16 = 10;

pub const TEMPLATE_SET_ID: u16 = 2;

pub const OPTIONS_TEMPLATE_SET_ID: u16 = 3;

pub const VALID_TEMPLATE_ID_RANGE: RangeInclusive<u16> = 256..=65535;

pub const VARIABLE_LENGTH: u16 = 0xffff;

pub type ObservationDomainId = u32;
pub type TemplateId = u16;

pub type TemplateKey = (ObservationDomainId, TemplateId);

#[derive(Debug, Clone, Serialize)]
pub enum TemplateValue {
    Template(TemplateRecord),
    OptionsTemplate(OptionsTemplateRecord),
}

pub type TemplatesMap = FxHashMap<TemplateKey, TemplateValue>;

#[derive(Debug, Clone)]
pub struct IpfixParser {
    pub templates: TemplatesMap,
    pub fields: FieldsMap,
    pub options: FxHashMap<(EnterpriseNumber, FieldId), DataValue>,
}

impl IpfixParser {
    pub fn new(fields: FieldsMap) -> Self {
        let templates = FxHashMap::default();
        let options = FxHashMap::default();

        IpfixParser {
            templates,
            fields,
            options,
        }
    }
}

impl IpfixParser {
    pub fn parse<'a>(
        &'a mut self,
        input: &'a [u8],
    ) -> Result<Ipfix, nom::Err<Error<&'a [u8]>, Error<&'a [u8]>>> {
        parse_ipfix(&mut self.templates, &self.fields)(input).map(|(_, packet)| packet)
    }

    pub fn parse_data_records<'a>(
        &'a mut self,
        input: &'a [u8],
    ) -> Result<
        Vec<FxHashMap<(EnterpriseNumber, FieldId), DataValue>>,
        nom::Err<Error<&'a [u8]>, Error<&'a [u8]>>,
    > {
        let packet =
            parse_ipfix(&mut self.templates, &self.fields)(input).map(|(_, packet)| packet)?;

        let mut records = Vec::with_capacity(16);

        packet.sets.iter().for_each(|set| {
            let is_data_options = self
                .templates
                .get(&(packet.observation_domain_id, set.set_id))
                .map_or(false, |template| {
                    matches!(template, TemplateValue::OptionsTemplate(_))
                });

            set.records.iter().for_each(|record| match record {
                Record::Data(record) => {
                    if is_data_options {
                        self.options.clear();

                        for (field, value) in record.0.clone().into_iter() {
                            self.options.insert(field, value);
                        }
                    } else {
                        records.push(FxHashMap::from_iter(record.0.clone()));
                    }
                }
                _ => {}
            });
        });

        Ok(records)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Ipfix {
    pub version: u16,
    pub length: u16,
    pub export_time: u32,
    pub sequence_number: u32,
    pub observation_domain_id: u32,
    pub sets: Vec<Set>,
}

pub fn parse_ipfix<'a>(
    templates: &'a mut TemplatesMap,
    fields: &'a FieldsMap,
) -> impl FnMut(&[u8]) -> IResult<&[u8], Ipfix> + 'a {
    move |input| {
        let (input, version) = verify(be_u16, |i| *i == IPFIX_VERSION).parse(input)?;
        let (input, length) = be_u16(input)?;

        let (_, input) = take(length as usize - 4)(input)?;

        let (input, export_time) = be_u32(input)?;
        let (input, sequence_number) = be_u32(input)?;
        let (input, observation_domain_id) = be_u32(input)?;

        let (input, sets) = fold_many1(
            parse_set(templates, observation_domain_id, fields),
            || Vec::with_capacity(16),
            |mut acc: Vec<Set>, set| {
                acc.push(set);
                acc
            },
        )
        .parse(input)?;

        Ok((
            input,
            Ipfix {
                version,
                length,
                export_time,
                sequence_number,
                observation_domain_id,
                sets,
            },
        ))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Set {
    pub set_id: u16,
    pub length: u16,
    pub records: Vec<Record>,
}

pub fn parse_set(
    templates: &mut TemplatesMap,
    observation_domain_id: ObservationDomainId,
    fields: &FieldsMap,
) -> impl FnMut(&[u8]) -> IResult<&[u8], Set> {
    move |input| {
        let (input, set_id) = be_u16(input)?;
        let (input, length) = be_u16(input)?;

        let (input, set_body) = take(length as usize - 4)(input)?;

        let (_, records) = match set_id {
            TEMPLATE_SET_ID => fold_many1(
                map(parse_template_record, |i| {
                    templates.insert(
                        (observation_domain_id, i.template_id),
                        TemplateValue::Template(i.clone()),
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
            OPTIONS_TEMPLATE_SET_ID => fold_many1(
                map(parse_options_template_record, |i| {
                    templates.insert(
                        (observation_domain_id, i.template_id),
                        TemplateValue::OptionsTemplate(i.clone()),
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
                if let Some(template_value) = templates.get(&(observation_domain_id, set_id)) {
                    fold_many1(
                        parse_data_record(template_value, fields),
                        || Vec::with_capacity(16),
                        |mut acc, record| {
                            acc.push(Record::Data(record));
                            acc
                        },
                    )
                    .parse(set_body)?
                } else {
                    fail().parse(set_body)?
                }
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
    pub fields: Vec<FieldSpecifier>,
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

#[derive(Debug, Clone, Serialize)]
pub struct OptionsTemplateRecord {
    pub template_id: u16,
    pub field_count: u16,
    pub scope_field_count: u16,
    pub fields: Vec<FieldSpecifier>,
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

#[derive(Debug, Clone, Serialize)]
pub struct FieldSpecifier {
    pub enterprise_bit: bool,
    pub information_element_identifier: u16,
    pub field_length: u16,
    pub enterprise_number: Option<u32>,
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

#[derive(Debug, Clone, Serialize)]
pub struct DataRecord(pub Vec<((EnterpriseNumber, FieldId), DataValue)>);

fn parse_data_record(
    template: &TemplateValue,
    fields: &FieldsMap,
) -> impl Fn(&[u8]) -> IResult<&[u8], DataRecord> {
    move |input| match template {
        TemplateValue::Template(template_record) => {
            let (input, data) = parse_defined_fields(input, &template_record.fields, fields)?;

            Ok((input, DataRecord(data)))
        }
        TemplateValue::OptionsTemplate(options_template_record) => {
            let (input, data) =
                parse_defined_fields(input, &options_template_record.fields, fields)?;

            Ok((input, DataRecord(data)))
        }
    }
}

fn parse_defined_fields<'a>(
    mut input: &'a [u8],
    field_specifiers: &[FieldSpecifier],
    fields: &FieldsMap,
) -> IResult<&'a [u8], Vec<((EnterpriseNumber, FieldId), DataValue)>> {
    let mut values = Vec::with_capacity(field_specifiers.len());

    for field_spec in field_specifiers {
        let mut value_length: u16;
        let value_bytes: &'a [u8];
        let input_: &'a [u8];

        if field_spec.field_length == VARIABLE_LENGTH {
            (input, value_length) = map(be_u8, |i| i as u16).parse(input)?;

            if value_length < 0xff {
                (input_, value_bytes) = take(value_length as usize)(input)?;

                input = input_;
            } else {
                (input, value_length) = be_u16(input)?;
                (input_, value_bytes) = take(value_length as usize)(input)?;

                input = input_;
            }
        } else {
            (input_, value_bytes) = take(field_spec.field_length)(input)?;

            input = input_;
        }

        let field_id = (
            field_spec.enterprise_number,
            field_spec.information_element_identifier,
        );

        // TODO: add support for basicList, subTemplateList, and subTemplateMultiList

        values.push((
            field_id,
            fields
                .get(&field_id)
                .map(|i| {
                    i.to_data_type(field_spec.field_length)
                        .decode(value_bytes)
                        .unwrap()
                })
                .unwrap(),
        ));
    }

    Ok((input, values))
}
