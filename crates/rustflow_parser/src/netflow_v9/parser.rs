use std::collections::HashMap;

use nom::branch::alt;
use nom::bytes::complete::take;
use nom::combinator::{all_consuming, map_parser, peek, verify};
use nom::multi::{length_data, many, many0, many1};
use nom::number::complete::{be_u16, be_u32};
use nom::sequence::preceded;
use nom::Parser;
use nom::{IResult, ToUsize};

use crate::netflow_v9::packet::{
    DataFlowSet, DataRecord, DataRecordField, DataRecordFieldType, FieldDefinition, FieldType,
    FlowSet, Header, NetFlowV9, OptionsTemplateFlowSet, OptionsTemplateRecord, ScopeFieldType,
    TemplateFlowSet, TemplateRecord, TemplateRecordType, NETFLOW_V9_VERSION,
    OPTIONS_TEMPLATE_FLOW_SET_ID, TEMPLATE_FLOW_SET_ID,
};

type ObservationDomain = u32;
type TemplateId = u16;
type TemplateKey = (ObservationDomain, TemplateId);

type Templates = HashMap<TemplateKey, TemplateRecordType>;

#[derive(Debug, Clone)]
pub struct NetFlowV9Parser {
    templates: Templates,
    options_templates: Templates,
}

impl Default for NetFlowV9Parser {
    fn default() -> Self {
        NetFlowV9Parser {
            templates: HashMap::new(),
            options_templates: HashMap::new(),
        }
    }
}

impl NetFlowV9Parser {
    pub fn parse<'a>(&'a self, input: &'a [u8]) -> IResult<&'a [u8], NetFlowV9> {
        parse_netflow_v9(&self.templates)(input)
    }

    pub fn register_template(
        &mut self,
        source_id: ObservationDomain,
        template_id: TemplateId,
        template_record: TemplateRecord,
    ) {
        self.templates.insert(
            (source_id, template_id),
            TemplateRecordType::Template(template_record),
        );
    }

    pub fn remove_template(&mut self, source_id: ObservationDomain, template_id: TemplateId) {
        self.templates.remove(&(source_id, template_id));
    }

    pub fn register_options_template(
        &mut self,
        source_id: ObservationDomain,
        template_id: TemplateId,
        template_record: OptionsTemplateRecord,
    ) {
        self.options_templates.insert(
            (source_id, template_id),
            TemplateRecordType::OptionsTemplate(template_record),
        );
    }

    pub fn remove_options_template(
        &mut self,
        source_id: ObservationDomain,
        template_id: TemplateId,
    ) {
        self.options_templates.remove(&(source_id, template_id));
    }
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, version) = verify(be_u16, |i| *i == NETFLOW_V9_VERSION).parse(input)?;
    let (input, count) = be_u16(input)?;
    let (input, sys_up_time) = be_u32(input)?;
    let (input, unix_secs) = be_u32(input)?;
    let (input, sequence_number) = be_u32(input)?;
    let (input, source_id) = be_u32(input)?;

    Ok((
        input,
        Header {
            version,
            count,
            sys_up_time,
            unix_secs,
            sequence_number,
            source_id,
        },
    ))
}

fn parse_template_flow_set(input: &[u8]) -> IResult<&[u8], FlowSet> {
    let (input, flow_set_id) = verify(be_u16, |i| *i == TEMPLATE_FLOW_SET_ID).parse(input)?;
    let (input, length) = be_u16(input)?;

    let (input, records) = all_consuming(many0(parse_template_record)).parse(input)?;

    Ok((
        input,
        FlowSet::Template(TemplateFlowSet {
            flow_set_id,
            length,
            records,
        }),
    ))
}

fn parse_template_record(input: &[u8]) -> IResult<&[u8], TemplateRecord> {
    let (input, template_id) = be_u16(input)?;
    let (input, field_count) = be_u16(input)?;
    let (input, fields) =
        many(0..=field_count.to_usize(), parse_template_record_field).parse(input)?;

    Ok((
        input,
        TemplateRecord {
            template_id,
            field_count,
            fields,
        },
    ))
}

fn parse_template_record_field(input: &[u8]) -> IResult<&[u8], FieldDefinition<FieldType>> {
    let (input, field_type) = be_u16(input)?;
    let (input, field_length) = be_u16(input)?;

    Ok((
        input,
        FieldDefinition {
            field_type: field_type.into(),
            field_length,
        },
    ))
}

fn parse_data_record(
    template: &TemplateRecordType,
) -> impl Fn(&[u8]) -> IResult<&[u8], DataRecord> {
    move |input| {
        let mut input = input;

        match template {
            TemplateRecordType::Template(template_record) => {
                let mut values = Vec::new();

                for field in template_record.fields.iter() {
                    let (input_, value) = take(field.field_length)(input)?;

                    values.push(DataRecordField(
                        DataRecordFieldType::Field(field.field_type.clone()),
                        value.into(),
                    ));

                    input = input_;
                }

                Ok((input, values))
            }
            TemplateRecordType::OptionsTemplate(options_template_record) => {
                let mut values = Vec::new();

                for field in options_template_record.scope_fields.iter() {
                    let (input_, value) = take(field.field_length)(input)?;

                    values.push(DataRecordField(
                        DataRecordFieldType::ScopeField(field.field_type.clone()),
                        value.into(),
                    ));

                    input = input_;
                }

                for field in options_template_record.option_fields.iter() {
                    let (input_, value) = take(field.field_length)(input)?;

                    values.push(DataRecordField(
                        DataRecordFieldType::Field(field.field_type.clone()),
                        value.into(),
                    ));

                    input = input_;
                }

                Ok((input, values))
            }
        }
    }
}

fn parse_data_flow_set(
    templates: &Templates,
    source_id: ObservationDomain,
) -> impl Fn(&[u8]) -> IResult<&[u8], FlowSet> {
    move |input| {
        let (input, flow_set_id) = be_u16(input)?;
        let (input, length) = be_u16(input)?;

        let template_key = (source_id, flow_set_id);
        let template_record = templates.get(&template_key).ok_or_else(|| {
            nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Fail))
        })?;

        let (input, records) = many0(parse_data_record(template_record)).parse(input)?;

        Ok((
            input,
            FlowSet::Data(DataFlowSet {
                flow_set_id,
                length,
                records,
            }),
        ))
    }
}

fn parse_options_template_record_scope_field(
    input: &[u8],
) -> IResult<&[u8], FieldDefinition<ScopeFieldType>> {
    let (input, field_type) = be_u16(input)?;
    let (input, field_length) = be_u16(input)?;

    Ok((
        input,
        FieldDefinition {
            field_type: field_type.into(),
            field_length,
        },
    ))
}

fn parse_options_template_record_option_field(
    input: &[u8],
) -> IResult<&[u8], FieldDefinition<FieldType>> {
    let (input, field_type) = be_u16(input)?;
    let (input, field_length) = be_u16(input)?;

    Ok((
        input,
        FieldDefinition {
            field_type: field_type.into(),
            field_length,
        },
    ))
}

fn parse_options_template_record(input: &[u8]) -> IResult<&[u8], OptionsTemplateRecord> {
    let (input, template_id) = be_u16(input)?;
    let (input, option_scope_length) = be_u16(input)?;
    let (input, option_length) = be_u16(input)?;

    let (input, scope_fields) = take(option_scope_length)(input)?;
    let (_, scope_fields) = many0(parse_options_template_record_scope_field).parse(scope_fields)?;

    let (input, option_fields) = take(option_length)(input)?;
    let (_, option_fields) =
        many0(parse_options_template_record_option_field).parse(option_fields)?;

    Ok((
        input,
        OptionsTemplateRecord {
            template_id,
            option_scope_length,
            option_length,
            scope_fields,
            option_fields,
        },
    ))
}

fn parse_options_template_flow_set(input: &[u8]) -> IResult<&[u8], FlowSet> {
    let (input, flow_set_id) =
        verify(be_u16, |i| *i == OPTIONS_TEMPLATE_FLOW_SET_ID).parse(input)?;
    let (input, length) = be_u16(input)?;
    let (input, records) = many0(parse_options_template_record).parse(input)?;

    Ok((
        input,
        FlowSet::OptionsTemplate(OptionsTemplateFlowSet {
            flow_set_id,
            length,
            records,
        }),
    ))
}

pub fn parse_netflow_v9(templates: &Templates) -> impl FnMut(&[u8]) -> IResult<&[u8], NetFlowV9> {
    move |input| {
        let (input, header) = parse_header(input)?;

        let (input, flow_sets) = all_consuming(many1(map_parser(
            length_data(peek(preceded(be_u16, be_u16))),
            alt((
                parse_template_flow_set,
                parse_options_template_flow_set,
                parse_data_flow_set(templates, header.source_id),
            )),
        )))
        .parse(input)?;

        Ok((input, NetFlowV9 { header, flow_sets }))
    }
}
