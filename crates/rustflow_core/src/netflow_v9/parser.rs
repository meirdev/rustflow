use std::sync::Arc;
use std::time::Instant;

use winnow::binary::{be_u16, be_u32};
use winnow::combinator::{empty, repeat, seq};
use winnow::error::{ContextError, StrContext, StrContextValue};
use winnow::token::take;
use winnow::{Parser as _, Result};

use super::*;
use crate::information_element::{DataType, Registry};
use crate::set::DataSet;
use crate::template::{FieldSpecifier, OptionsTemplate, Template};
use crate::timed_map::BoundedTimedMap;
use crate::value::{Value, parse_value};

type SourceId = u32;
type TemplateId = u16;

#[derive(Debug)]
pub struct Parser {
    registry: Registry,
    templates: BoundedTimedMap<(SourceId, TemplateId), TemplateRef>,
    now: Instant,
}

impl Parser {
    pub fn new(
        registry: Registry,
        templates: BoundedTimedMap<(SourceId, TemplateId), TemplateRef>,
    ) -> Self {
        Self {
            registry,
            templates,
            now: Instant::now(),
        }
    }

    pub fn parse(&mut self, input: &[u8]) -> Result<Packet> {
        self.parse_at(input, Instant::now())
    }

    pub fn parse_at(&mut self, input: &[u8], now: Instant) -> Result<Packet> {
        self.now = now;

        let mut input = input;
        let header = parse_header(&mut input)?;

        let mut flow_sets = Vec::new();
        while input.len() >= usize::from(FLOW_SET_HEADER_LENGTH) {
            flow_sets.push(self.parse_flow_set(&mut input, header.source_id)?);
        }

        Ok(Packet { header, flow_sets })
    }

    fn parse_flow_set(&mut self, input: &mut &[u8], source_id: SourceId) -> Result<FlowSet> {
        let flow_set_id = be_u16.parse_next(input)?;
        let length = be_u16
            .verify(|&length| length >= FLOW_SET_HEADER_LENGTH)
            .context(StrContext::Label("flow set length"))
            .context(StrContext::Expected(StrContextValue::Description(
                "at least the 4-octet flow set header",
            )))
            .parse_next(input)?;
        let mut body = take(length - FLOW_SET_HEADER_LENGTH)
            .context(StrContext::Label("flow set body"))
            .parse_next(input)?;

        let flow_set = match flow_set_id {
            TEMPLATE_FLOW_SET_ID => {
                let templates = parse_records(
                    &mut body,
                    TEMPLATE_RECORD_HEADER_LENGTH,
                    parse_template.map(Arc::new),
                )?;
                for template in &templates {
                    self.insert(
                        source_id,
                        template.template_id,
                        TemplateRef::Data(Arc::clone(template)),
                    );
                }
                FlowSet::Templates(templates)
            }
            OPTIONS_TEMPLATE_FLOW_SET_ID => {
                let templates = parse_records(
                    &mut body,
                    OPTIONS_TEMPLATE_RECORD_HEADER_LENGTH,
                    parse_options_template.map(Arc::new),
                )?;
                for template in &templates {
                    self.insert(
                        source_id,
                        template.template_id,
                        TemplateRef::Options(Arc::clone(template)),
                    );
                }
                FlowSet::OptionsTemplates(templates)
            }
            id if id >= MIN_TEMPLATE_ID => self.decode_data_flow_set(source_id, id, body),
            id => FlowSet::Unknown(id),
        };
        Ok(flow_set)
    }

    fn insert(&mut self, source_id: SourceId, template_id: TemplateId, template: TemplateRef) {
        self.templates
            .insert_at((source_id, template_id), template, self.now);
    }

    fn decode_data_flow_set(&self, source_id: SourceId, flow_set_id: u16, body: &[u8]) -> FlowSet {
        let undecoded = || FlowSet::Undecoded {
            set_id: flow_set_id,
            body: body.to_vec(),
        };
        let Some(template) = self.templates.get_at(&(source_id, flow_set_id), self.now) else {
            return undecoded();
        };
        let record_length = record_length(template);
        if record_length == 0 {
            return undecoded();
        }

        let mut input = body;
        let mut records = Vec::new();
        while input.len() >= record_length {
            match self.parse_record(&mut input, template) {
                Ok(record) => records.push(record),
                Err(_) => return undecoded(),
            }
        }

        match template {
            TemplateRef::Data(template) => FlowSet::Data(DataSet {
                template: Arc::clone(template),
                records,
            }),
            TemplateRef::Options(template) => FlowSet::OptionsData(DataSet {
                template: Arc::clone(template),
                records,
            }),
        }
    }

    fn parse_record(&self, input: &mut &[u8], template: &TemplateRef) -> Result<Vec<Value>> {
        let mut record = Vec::new();
        match template {
            TemplateRef::Data(template) => {
                for field in &template.fields {
                    record.push(self.parse_field(input, field)?);
                }
            }
            TemplateRef::Options(template) => {
                for scope in &template.scope_fields {
                    record.push(parse_scope_value(input, *scope)?);
                }
                for field in &template.option_fields {
                    record.push(self.parse_field(input, field)?);
                }
            }
        }
        Ok(record)
    }

    fn parse_field(&self, input: &mut &[u8], field: &FieldSpecifier) -> Result<Value> {
        let data_type = self
            .registry
            .get(field.element_id())
            .map_or(DataType::OctetArray, |element| element.data_type);
        parse_value(data_type, field.field_length.into()).parse_next(input)
    }
}

fn parse_scope_value(input: &mut &[u8], scope: ScopeField) -> Result<Value> {
    parse_value(DataType::Unsigned64, scope.length.into()).parse_next(input)
}

fn parse_records<'i, T>(
    body: &mut &'i [u8],
    min_record_length: usize,
    mut record: impl winnow::Parser<&'i [u8], T, ContextError>,
) -> Result<Vec<T>> {
    let mut records = Vec::new();
    while body.len() >= min_record_length {
        records.push(record.parse_next(body)?);
    }
    Ok(records)
}

fn record_length(template: &TemplateRef) -> usize {
    match template {
        TemplateRef::Data(template) => fields_length(&template.fields),
        TemplateRef::Options(template) => {
            let scope: usize = template
                .scope_fields
                .iter()
                .map(|scope| usize::from(scope.length))
                .sum();
            scope + fields_length(&template.option_fields)
        }
    }
}

fn fields_length(fields: &[FieldSpecifier]) -> usize {
    fields
        .iter()
        .map(|field| usize::from(field.field_length))
        .sum()
}

fn parse_header(input: &mut &[u8]) -> Result<Header> {
    seq!(Header {
        version: be_u16
            .verify(|&version| version == VERSION)
            .context(StrContext::Label("version"))
            .context(StrContext::Expected(StrContextValue::Description("9"))),
        count: be_u16,
        sys_uptime: be_u32,
        unix_secs: be_u32,
        sequence_number: be_u32,
        source_id: be_u32,
    })
    .parse_next(input)
}

fn parse_field_specifier(input: &mut &[u8]) -> Result<FieldSpecifier> {
    seq!(FieldSpecifier {
        information_element_id: be_u16,
        field_length: be_u16,
        enterprise_number: empty.value(None),
    })
    .parse_next(input)
}

fn parse_template_id(input: &mut &[u8]) -> Result<u16> {
    be_u16
        .verify(|&template_id| template_id >= MIN_TEMPLATE_ID)
        .context(StrContext::Label("template ID"))
        .context(StrContext::Expected(StrContextValue::Description(
            "256 or above",
        )))
        .parse_next(input)
}

fn parse_template(input: &mut &[u8]) -> Result<Template> {
    let template_id = parse_template_id(input)?;
    let field_count = be_u16.parse_next(input)?;
    let fields = repeat(usize::from(field_count), parse_field_specifier).parse_next(input)?;

    Ok(Template {
        template_id,
        fields,
    })
}

fn parse_options_template(input: &mut &[u8]) -> Result<OptionsTemplate<ScopeField>> {
    let template_id = parse_template_id(input)?;
    let scope_length = parse_fields_length(input, "option scope length")?;
    let option_length = parse_fields_length(input, "option length")?;

    let scope_fields =
        repeat(usize::from(scope_length / 4), parse_scope_field).parse_next(input)?;
    let option_fields =
        repeat(usize::from(option_length / 4), parse_field_specifier).parse_next(input)?;

    Ok(OptionsTemplate {
        template_id,
        scope_fields,
        option_fields,
    })
}

fn parse_fields_length(input: &mut &[u8], label: &'static str) -> Result<u16> {
    be_u16
        .verify(|&length| length % 4 == 0)
        .context(StrContext::Label(label))
        .context(StrContext::Expected(StrContextValue::Description(
            "a multiple of 4 octets",
        )))
        .parse_next(input)
}

fn parse_scope_field(input: &mut &[u8]) -> Result<ScopeField> {
    seq!(ScopeField {
        field_type: be_u16.map(ScopeType::from),
        length: be_u16,
    })
    .parse_next(input)
}
