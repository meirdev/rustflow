use nom::branch::alt;
use nom::bytes::complete::take;
use nom::combinator::{peek, verify};
use nom::multi::{length_data, many, many0, many1};
use nom::number::complete::{be_u16, be_u32};
use nom::sequence::preceded;
use nom::Parser;
use nom::{IResult, ToUsize};
use rustflow_types::netflow_v9::{
    DataFlowSet, DataFlowSetRecord, FieldDefinition, FieldType, FieldValue, FlowSet, Header,
    NetFlowV9, OptionsTemplateFlowSet, OptionsTemplateRecord, ScopeFieldType, TemplateFlowSet,
    TemplateRecord, TemplateRecordType, NETFLOW_V9_VERSION, OPTIONS_TEMPLATE_FLOW_SET_ID,
    TEMPLATE_FLOW_SET_ID,
};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct NetFlowV9Parser {
    templates: HashMap<u16, TemplateRecordType>,
}

impl Default for NetFlowV9Parser {
    fn default() -> Self {
        NetFlowV9Parser {
            templates: HashMap::new(),
        }
    }
}

impl<'a> NetFlowV9Parser {
    pub fn parse(&'a mut self, input: &'a [u8]) -> IResult<&'a [u8], NetFlowV9<'a>> {
        parse_netflow_v9(&mut self.templates)(input)
    }
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, version) = verify(be_u16, |i| *i == NETFLOW_V9_VERSION).parse(input)?;
    let (input, count) = be_u16(input)?;
    let (input, sysuptime) = be_u32(input)?;
    let (input, unix_secs) = be_u32(input)?;
    let (input, sequence_number) = be_u32(input)?;
    let (input, source_id) = be_u32(input)?;

    Ok((
        input,
        Header {
            version,
            count,
            sysuptime,
            unix_secs,
            sequence_number,
            source_id,
        },
    ))
}

fn parse_length(input: &[u8]) -> IResult<&[u8], &[u8]> {
    length_data(peek(preceded(be_u16, be_u16))).parse(input)
}

fn parse_template_flow_set(input: &[u8]) -> IResult<&[u8], FlowSet> {
    let (rest, input) = parse_length(input)?;

    let (input, flow_set_id) = verify(be_u16, |i| *i == TEMPLATE_FLOW_SET_ID).parse(input)?;
    let (input, length) = be_u16(input)?;

    let (_, records) = many0(parse_template_record).parse(input)?;

    Ok((
        rest,
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
) -> impl Fn(&[u8]) -> IResult<&[u8], DataFlowSetRecord> {
    move |input| {
        let mut input = input;

        match template {
            TemplateRecordType::Template(template_record) => {
                let mut values = Vec::new();

                for field in template_record.fields.iter() {
                    let (input_, value) = take(field.field_length)(input)?;

                    values.push(FieldValue {
                        field_type: field.field_type.clone(),
                        value: value.into(),
                    });

                    input = input_;
                }

                Ok((input, DataFlowSetRecord(values)))
            }
            TemplateRecordType::OptionsTemplate(options_template_record) => {
                let mut values = Vec::new();

                for field in options_template_record.scope_fields.iter() {
                    let (input_, value) = take(field.field_length)(input)?;

                    values.push(FieldValue {
                        field_type: FieldType::Unknown(1),
                        value: value.into(),
                    });

                    input = input_;
                }

                for field in options_template_record.option_fields.iter() {
                    let (input_, value) = take(field.field_length)(input)?;

                    values.push(FieldValue {
                        field_type: field.field_type.clone(),
                        value: value.into(),
                    });

                    input = input_;
                }

                Ok((input, DataFlowSetRecord(values)))
            }
        }
    }
}

fn parse_data_flow_set(
    templates: &mut HashMap<u16, TemplateRecordType>,
) -> impl Fn(&[u8]) -> IResult<&[u8], FlowSet> {
    move |input| {
        let (rest, input) = parse_length(input)?;

        let (input, flow_set_id) = verify(be_u16, |i| templates.contains_key(i)).parse(input)?;
        let (input, length) = be_u16(input)?;

        let template_record = templates.get(&flow_set_id).unwrap();

        let (input, records) = many0(parse_data_record(template_record)).parse(input)?;
        // let (_, padding) = all_consuming(take_while(|i: u8| i == 0)).parse(input)?;

        Ok((
            rest,
            FlowSet::Data(DataFlowSet {
                flow_set_id,
                length,
                records,
                padding: &[],
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
    let (input, template_id) = verify(be_u16, |i| *i > 255).parse(input)?;
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
    let (rest, input) = parse_length(input)?;

    let (input, flow_set_id) =
        verify(be_u16, |i| *i == OPTIONS_TEMPLATE_FLOW_SET_ID).parse(input)?;
    let (input, length) = be_u16(input)?;
    let (input, records) = many0(parse_options_template_record).parse(input)?;
    // let (_, padding) = all_consuming(take_while(|i: u8| i == 0)).parse(input)?;

    Ok((
        rest,
        FlowSet::OptionsTemplate(OptionsTemplateFlowSet {
            flow_set_id,
            length,
            records,
            padding: &[],
        }),
    ))
}

pub fn parse_netflow_v9(
    templates: &mut HashMap<u16, TemplateRecordType>,
) -> impl FnMut(&[u8]) -> IResult<&[u8], NetFlowV9> {
    move |input| {
        let (input, header) = parse_header(input)?;
        let (input, flow_sets) = many1(alt((
            parse_template_flow_set,
            parse_options_template_flow_set,
            parse_data_flow_set(templates),
        )))
        .parse(input)?;

        for flow_set in flow_sets.iter() {
            match flow_set {
                FlowSet::Template(template_flow_set) => {
                    for record in template_flow_set.records.iter() {
                        let template = TemplateRecordType::Template(record.clone());
                        templates.insert(record.template_id, template);
                    }
                }
                FlowSet::OptionsTemplate(options_template_flow_set) => {
                    for record in options_template_flow_set.records.iter() {
                        let template = TemplateRecordType::OptionsTemplate(record.clone());
                        templates.insert(record.template_id, template);
                    }
                }
                _ => {}
            }
        }

        Ok((input, NetFlowV9 { header, flow_sets }))
    }
}
