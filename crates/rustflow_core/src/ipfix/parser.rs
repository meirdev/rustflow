use std::borrow::Cow;
use std::sync::Arc;
use std::time::Instant;

use num_enum::TryFromPrimitive;
use winnow::binary::{be_u16, be_u32, u8};
use winnow::combinator::{cond, repeat, seq};
use winnow::error::{ContextError, StrContext, StrContextValue};
use winnow::token::take;
use winnow::{Parser as _, Result};

use super::*;
use crate::information_element::{DataType, ElementId, InformationElement, ListSemantic, Registry};
use crate::set::DataSet;
use crate::template::TemplateRef;
use crate::timed_map::BoundedTimedMap;
use crate::value::{BasicList, ListRecords, SubTemplateList, SubTemplateMultiList, Value};

type DomainId = u32;
type TemplateId = u16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LearnedElement {
    Element(InformationElement),
    Conflicting,
}

#[derive(Debug)]
pub struct Parser {
    registry: Registry,
    learned: BoundedTimedMap<ElementId, LearnedElement>,
    templates: BoundedTimedMap<(DomainId, TemplateId), TemplateRef>,
    now: Instant,
}

impl Parser {
    pub fn new(
        registry: Registry,
        templates: BoundedTimedMap<(DomainId, TemplateId), TemplateRef>,
        learned: BoundedTimedMap<ElementId, LearnedElement>,
    ) -> Self {
        Self {
            registry,
            learned,
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
        let mut body = take(header.length - HEADER_LENGTH)
            .context(StrContext::Label("message body"))
            .parse_next(&mut input)?;

        let mut sets = Vec::new();
        while !body.is_empty() {
            sets.push(self.parse_set(&mut body, header.observation_domain_id)?);
        }

        Ok(Packet { header, sets })
    }

    fn parse_set(&mut self, input: &mut &[u8], domain: DomainId) -> Result<Set> {
        let set_id = be_u16.parse_next(input)?;
        let length = be_u16
            .verify(|&length| length >= SET_HEADER_LENGTH)
            .context(StrContext::Label("set length"))
            .context(StrContext::Expected(StrContextValue::Description(
                "at least the 4-octet set header",
            )))
            .parse_next(input)?;
        let mut body = take(length - SET_HEADER_LENGTH)
            .context(StrContext::Label("set body"))
            .parse_next(input)?;

        let set = match set_id {
            TEMPLATE_SET_ID => {
                let templates = parse_records(&mut body, parse_template.map(Arc::new))?;
                for template in templates.iter().filter(|t| !is_withdrawal(t)) {
                    let template_ref = TemplateRef::Data(Arc::clone(template));
                    self.insert(domain, template.template_id, template_ref);
                }
                Set::Templates(templates)
            }
            OPTIONS_TEMPLATE_SET_ID => {
                let templates = parse_records(&mut body, parse_options_template.map(Arc::new))?;
                for template in templates.iter().filter(|t| !is_options_withdrawal(t)) {
                    let template_ref = TemplateRef::Options(Arc::clone(template));
                    self.insert(domain, template.template_id, template_ref);
                }
                Set::OptionsTemplates(templates)
            }
            id if id >= MIN_TEMPLATE_ID => {
                let set = self.decode_data_set(domain, id, body);
                if let Set::OptionsData(data_set) = &set {
                    self.learn_elements(data_set);
                }
                set
            }
            id => Set::Unknown(id),
        };
        Ok(set)
    }

    fn learn_elements(&mut self, data_set: &DataSet<OptionsTemplate>) {
        if !is_type_template(&data_set.template) {
            return;
        }
        for record in &data_set.records {
            let Some(element) = type_record_element(&data_set.template, record) else {
                continue;
            };
            if self.registry.get(element.id).is_some() || element.check().is_err() {
                continue;
            }
            // Inserting again also refreshes the expiry, like a resent template.
            let id = element.id;
            let learned = match self.learned.get_at(&id, self.now) {
                Some(LearnedElement::Element(known)) if *known != element => {
                    LearnedElement::Conflicting
                }
                Some(LearnedElement::Conflicting) => LearnedElement::Conflicting,
                _ => LearnedElement::Element(element),
            };
            self.learned.insert_at(id, learned, self.now);
        }
    }

    fn element(&self, id: ElementId) -> Option<&InformationElement> {
        self.registry
            .get(id)
            .or_else(|| match self.learned.get_at(&id, self.now)? {
                LearnedElement::Element(element) => Some(element),
                LearnedElement::Conflicting => None,
            })
    }

    fn insert(&mut self, domain: DomainId, template_id: TemplateId, template: TemplateRef) {
        self.templates
            .insert_at((domain, template_id), template, self.now);
    }

    fn template(&self, domain: DomainId, template_id: TemplateId) -> Option<&TemplateRef> {
        self.templates.get_at(&(domain, template_id), self.now)
    }

    fn data_type(&self, field: &FieldSpecifier) -> DataType {
        self.element(field.element_id())
            .map_or(DataType::OctetArray, |element| element.data_type)
    }

    fn decode_data_set(&self, domain: DomainId, set_id: TemplateId, body: &[u8]) -> Set {
        let undecoded = || Set::Undecoded {
            set_id,
            body: body.to_vec(),
        };
        let Some(template) = self.template(domain, set_id) else {
            return undecoded();
        };
        let min_length = min_record_length(template);
        if min_length == 0 {
            // Every record would be empty; there is nothing to decode.
            return undecoded();
        }

        let mut input = body;
        let mut records = Vec::new();
        // Fewer octets than the smallest record are padding (RFC 7011 §3.3.1).
        while input.len() >= min_length {
            match self.parse_record(&mut input, domain, template, 0) {
                Ok(record) => records.push(record),
                Err(_) => return undecoded(),
            }
        }

        match template {
            TemplateRef::Data(template) => Set::Data(DataSet {
                template: Arc::clone(template),
                records,
            }),
            TemplateRef::Options(template) => Set::OptionsData(DataSet {
                template: Arc::clone(template),
                records,
            }),
        }
    }

    fn parse_record(
        &self,
        input: &mut &[u8],
        domain: DomainId,
        template: &TemplateRef,
        depth: usize,
    ) -> Result<Vec<Value>> {
        template
            .fields()
            .map(|field| {
                let length = parse_field_length(input, field.field_length)?;
                let bytes = take(length).parse_next(input)?;
                Ok(self.decode_field(domain, self.data_type(field), bytes, depth))
            })
            .collect()
    }

    fn decode_field(
        &self,
        domain: DomainId,
        data_type: DataType,
        bytes: &[u8],
        depth: usize,
    ) -> Value {
        let list = match data_type {
            DataType::BasicList | DataType::SubTemplateList | DataType::SubTemplateMultiList
                if depth < MAX_LIST_DEPTH =>
            {
                self.decode_list(domain, data_type, bytes, depth)
            }
            _ => None,
        };
        list.unwrap_or_else(|| data_type.decode_or_octets(bytes))
    }

    fn decode_list(
        &self,
        domain: DomainId,
        data_type: DataType,
        bytes: &[u8],
        depth: usize,
    ) -> Option<Value> {
        let mut input = bytes;
        let value = match data_type {
            DataType::BasicList => Value::BasicList(Box::new(
                self.parse_basic_list(&mut input, domain, depth).ok()?,
            )),
            DataType::SubTemplateList => Value::SubTemplateList(Box::new(
                self.parse_sub_template_list(&mut input, domain, depth)
                    .ok()?,
            )),
            DataType::SubTemplateMultiList => Value::SubTemplateMultiList(Box::new(
                self.parse_sub_template_multi_list(&mut input, domain, depth)
                    .ok()?,
            )),
            _ => return None,
        };
        Some(value)
    }

    fn parse_basic_list(
        &self,
        input: &mut &[u8],
        domain: DomainId,
        depth: usize,
    ) -> Result<BasicList> {
        let semantic = parse_list_semantic(input)?;
        let field = parse_field_specifier(input)?;
        let data_type = self.data_type(&field);
        let values = parse_all(input, |input| {
            let length = parse_field_length(input, field.field_length)?;
            let bytes = take(length).parse_next(input)?;
            Ok(self.decode_field(domain, data_type, bytes, depth + 1))
        })?;

        Ok(BasicList {
            semantic,
            field,
            values,
        })
    }

    fn parse_sub_template_list(
        &self,
        input: &mut &[u8],
        domain: DomainId,
        depth: usize,
    ) -> Result<SubTemplateList> {
        let semantic = parse_list_semantic(input)?;
        let template_id = be_u16.parse_next(input)?;
        let records = self.parse_list_records(input, domain, template_id, depth)?;

        Ok(SubTemplateList { semantic, records })
    }

    fn parse_sub_template_multi_list(
        &self,
        input: &mut &[u8],
        domain: DomainId,
        depth: usize,
    ) -> Result<SubTemplateMultiList> {
        let semantic = parse_list_semantic(input)?;
        let groups = parse_all(input, |input| {
            let template_id = be_u16.parse_next(input)?;
            // RFC 6313 gives an empty group's length as both 4 and 0; a
            // length between them is shorter than the group's own header.
            let length = be_u16
                .map(usize::from)
                .verify(|&length: &usize| !(1..LIST_GROUP_HEADER_SIZE).contains(&length))
                .context(StrContext::Label("list group length"))
                .parse_next(input)?;
            let mut records = take(length.saturating_sub(LIST_GROUP_HEADER_SIZE))
                .context(StrContext::Label("list group records"))
                .parse_next(input)?;
            self.parse_list_records(&mut records, domain, template_id, depth)
        })?;

        Ok(SubTemplateMultiList { semantic, groups })
    }

    fn parse_list_records(
        &self,
        input: &mut &[u8],
        domain: DomainId,
        template_id: TemplateId,
        depth: usize,
    ) -> Result<ListRecords> {
        Ok(match self.template(domain, template_id) {
            Some(template) => ListRecords::Decoded {
                template: template.clone(),
                records: parse_all(input, |input| {
                    self.parse_record(input, domain, template, depth + 1)
                })?,
            },
            None => ListRecords::Undecoded {
                template_id,
                data: std::mem::take(input).to_vec(),
            },
        })
    }
}

fn is_type_template(template: &OptionsTemplate) -> bool {
    let has_scope = |id| template.scope_fields.iter().any(|f| f.element_id() == id);
    has_scope(ElementId::INFORMATION_ELEMENT_ID) && has_scope(ElementId::PRIVATE_ENTERPRISE_NUMBER)
}

fn type_record_element(template: &OptionsTemplate, record: &[Value]) -> Option<InformationElement> {
    let (mut id, mut enterprise, mut data_type) = (None, None, None);
    let (mut semantic, mut unit, mut name, mut description) = (None, None, None, None);
    let (mut range_begin, mut range_end) = (None, None);

    let fields = template.scope_fields.iter().chain(&template.option_fields);
    for (field, value) in fields.zip(record) {
        let number = value.as_u64();
        match field.element_id() {
            ElementId::INFORMATION_ELEMENT_ID => id = number.and_then(|n| u16::try_from(n).ok()),
            ElementId::PRIVATE_ENTERPRISE_NUMBER => {
                enterprise = number.and_then(|n| u32::try_from(n).ok());
            }
            ElementId::INFORMATION_ELEMENT_DATA_TYPE => data_type = number.and_then(enum_value),
            ElementId::INFORMATION_ELEMENT_SEMANTICS => semantic = number.and_then(enum_value),
            ElementId::INFORMATION_ELEMENT_UNITS => unit = number.and_then(enum_value),
            ElementId::INFORMATION_ELEMENT_RANGE_BEGIN => range_begin = number,
            ElementId::INFORMATION_ELEMENT_RANGE_END => range_end = number,
            ElementId::INFORMATION_ELEMENT_NAME => name = text(value),
            ElementId::INFORMATION_ELEMENT_DESCRIPTION => description = text(value),
            _ => {}
        }
    }

    let enterprise = enterprise?;
    let id = ElementId::new((enterprise != 0).then_some(enterprise), id?).ok()?;
    Some(InformationElement {
        id,
        name: name.unwrap_or_else(|| Cow::Owned(id.to_string())),
        data_type: data_type?,
        semantic,
        unit,
        range: range_begin.zip(range_end).map(|(begin, end)| begin..=end),
        description,
    })
}

fn enum_value<T: TryFromPrimitive>(number: u64) -> Option<T>
where
    T::Primitive: TryFrom<u64>,
{
    T::try_from_primitive(T::Primitive::try_from(number).ok()?).ok()
}

fn text(value: &Value) -> Option<Cow<'static, str>> {
    match value {
        Value::String(text) => Some(Cow::Owned(text.clone())),
        _ => None,
    }
}

fn parse_list_semantic(input: &mut &[u8]) -> Result<ListSemantic> {
    u8.map(|byte| ListSemantic::try_from(byte).unwrap_or_default())
        .parse_next(input)
}

fn parse_all<'i, T>(
    input: &mut &'i [u8],
    mut item: impl FnMut(&mut &'i [u8]) -> Result<T>,
) -> Result<Vec<T>> {
    let mut items = Vec::new();
    while !input.is_empty() {
        let before = input.len();
        items.push(item(input)?);
        if input.len() == before {
            return Err(ContextError::new());
        }
    }
    Ok(items)
}

fn min_record_length(template: &TemplateRef) -> usize {
    template
        .fields()
        .map(|field| match field.field_length {
            VARIABLE_LENGTH => 1,
            length => usize::from(length),
        })
        .sum()
}

fn parse_records<'i, T>(
    body: &mut &'i [u8],
    mut record: impl winnow::Parser<&'i [u8], T, ContextError>,
) -> Result<Vec<T>> {
    let mut records = Vec::new();
    while body.len() >= MIN_TEMPLATE_RECORD_LENGTH {
        records.push(record.parse_next(body)?);
    }
    Ok(records)
}

fn parse_header(input: &mut &[u8]) -> Result<Header> {
    seq!(Header {
        version: be_u16
            .verify(|&version| version == VERSION)
            .context(StrContext::Label("version"))
            .context(StrContext::Expected(StrContextValue::Description("10"))),
        length: be_u16
            .verify(|&length| length >= HEADER_LENGTH)
            .context(StrContext::Label("length"))
            .context(StrContext::Expected(StrContextValue::Description(
                "at least the 16-octet header"
            ))),
        export_time: be_u32,
        sequence_number: be_u32,
        observation_domain_id: be_u32,
    })
    .parse_next(input)
}

fn parse_field_specifier(input: &mut &[u8]) -> Result<FieldSpecifier> {
    let (id, field_length) = (be_u16, be_u16).parse_next(input)?;
    let enterprise_number = cond(id & ENTERPRISE_BIT != 0, be_u32).parse_next(input)?;

    Ok(FieldSpecifier {
        information_element_id: id & !ENTERPRISE_BIT,
        field_length,
        enterprise_number,
    })
}

fn parse_field_length(input: &mut &[u8], field_length: u16) -> Result<usize> {
    if field_length != VARIABLE_LENGTH {
        return Ok(usize::from(field_length));
    }
    match u8.parse_next(input)? {
        255 => be_u16.map(usize::from).parse_next(input),
        length => Ok(usize::from(length)),
    }
}

fn parse_template(input: &mut &[u8]) -> Result<Template> {
    let (template_id, field_count) = (be_u16, be_u16)
        .verify(|&(template_id, field_count)| {
            is_valid_template_header(template_id, field_count, TEMPLATE_SET_ID)
        })
        .context(StrContext::Label("template ID"))
        .context(StrContext::Expected(StrContextValue::Description(
            "256 or above, or 2 to withdraw all templates",
        )))
        .parse_next(input)?;
    let fields = repeat(usize::from(field_count), parse_field_specifier).parse_next(input)?;

    Ok(Template {
        template_id,
        fields,
    })
}

fn parse_options_template(input: &mut &[u8]) -> Result<OptionsTemplate> {
    let (template_id, field_count) = (be_u16, be_u16)
        .verify(|&(template_id, field_count)| {
            is_valid_template_header(template_id, field_count, OPTIONS_TEMPLATE_SET_ID)
        })
        .context(StrContext::Label("options template ID"))
        .context(StrContext::Expected(StrContextValue::Description(
            "256 or above, or 3 to withdraw all options templates",
        )))
        .parse_next(input)?;

    // Withdrawal has no scope field count.
    if field_count == 0 {
        return Ok(OptionsTemplate {
            template_id,
            scope_fields: Vec::new(),
            option_fields: Vec::new(),
        });
    }

    let scope_field_count = be_u16
        .verify(|&count| count != 0 && count <= field_count)
        .context(StrContext::Label("scope field count"))
        .context(StrContext::Expected(StrContextValue::Description(
            "between 1 and the field count",
        )))
        .parse_next(input)?;
    let scope_fields =
        repeat(usize::from(scope_field_count), parse_field_specifier).parse_next(input)?;
    let option_fields = repeat(
        usize::from(field_count - scope_field_count),
        parse_field_specifier,
    )
    .parse_next(input)?;

    Ok(OptionsTemplate {
        template_id,
        scope_fields,
        option_fields,
    })
}
