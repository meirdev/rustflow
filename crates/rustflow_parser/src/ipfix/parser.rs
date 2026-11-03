use std::sync::Arc;
use std::time::Duration;

use rustflow_reader::{Reader, Truncated};

use super::type_records::ElementTypes;
use super::*;
use crate::information_element::{DataType, InformationElement, Registry};
use crate::template_cache::TemplateCache;
use crate::value::{Value, decode};
use crate::{DataSet, Error};

/// Parses IPFIX messages, keeping the templates each exporter sends for the
/// messages after it. Use one parser per exporter address: templates are
/// told apart only by observation domain ID.
///
/// A parser holds templates of 65,536 fields at most: one that does not fit
/// is refused, and the template it would replace is dropped.
///
/// Template withdrawals are parsed but not applied: a collector receiving
/// over UDP must ignore them (RFC 7011 section 8.4), and lets templates
/// expire instead.
///
/// Type records (RFC 5610) describe elements the registry lacks: from then
/// on, the domain's templates decode those elements by the described type,
/// templates received earlier included.
pub struct Parser {
    registry: Registry,
    element_types: ElementTypes,
    templates: TemplateCache<Entry>,
}

struct Entry {
    template: TemplateRef,
    layout: Box<[Slot]>,
}

#[derive(Clone, Copy)]
struct Slot {
    field_length: u16,
    data_type: DataType,
}

impl Parser {
    /// Fields are looked up in `registry`; values of elements it lacks are
    /// kept as octet arrays. A template expires `timeout` after it was last
    /// received.
    pub fn new(registry: Registry, timeout: Duration) -> Self {
        Self {
            registry,
            element_types: ElementTypes::default(),
            templates: TemplateCache::new(timeout),
        }
    }

    /// Parses an IPFIX message. Parsing stops at the first set that is
    /// malformed or truncated; the sets before it are kept. Bytes after the
    /// message's length are ignored.
    pub fn parse(&mut self, datagram: &[u8]) -> Result<Packet, Error> {
        let mut r = Reader::new(datagram);
        let header = parse_header(&mut r)?;
        let body_length = usize::from(header.length)
            .checked_sub(HEADER_SIZE)
            .ok_or(Error::MessageLength(header.length))?;
        let mut body = r.sub(body_length)?;
        let sets = body.many(|r| self.parse_set(r, header.observation_domain_id));

        Ok(Packet { header, sets })
    }

    fn parse_set(&mut self, r: &mut Reader, domain: u32) -> Result<Set, Error> {
        let set_id = r.u16()?;
        let length = r.u16()?;
        let body_length = usize::from(length)
            .checked_sub(SET_HEADER_SIZE)
            .ok_or(Error::SetLength(length))?;
        let mut body = r.sub(body_length)?;

        let set = match set_id {
            TEMPLATE_SET_ID => {
                let templates: Vec<_> = body
                    .many(parse_template)
                    .into_iter()
                    .map(Arc::new)
                    .collect();
                for template in templates.iter().filter(|t| !t.fields.is_empty()) {
                    let template_ref = TemplateRef::Data(Arc::clone(template));
                    self.insert(domain, template.template_id, template_ref);
                }
                Set::Templates(templates)
            }
            OPTIONS_TEMPLATE_SET_ID => {
                let templates: Vec<_> = body
                    .many(parse_options_template)
                    .into_iter()
                    .map(Arc::new)
                    .collect();
                for template in templates.iter().filter(|t| !t.scope_fields.is_empty()) {
                    let template_ref = TemplateRef::Options(Arc::clone(template));
                    self.insert(domain, template.template_id, template_ref);
                }
                Set::OptionsTemplates(templates)
            }
            id if id >= MIN_TEMPLATE_ID => {
                let Some(entry) = self.templates.get(domain, id) else {
                    return Ok(Set::Unknown(id));
                };
                let records = body.many(|r| self.parse_record(r, domain, &entry.layout, 0));
                match &entry.template {
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
            id => Set::Unknown(id),
        };

        if let Set::OptionsData(data) = &set
            && self
                .element_types
                .learn(domain, &data.template, &data.records, &self.registry)
        {
            self.refresh_layouts(domain);
        }

        Ok(set)
    }

    /// The registry's element for a field of `domain`, or else the one the
    /// exporter's type records described.
    pub fn element(&self, domain: u32, field: &FieldSpecifier) -> Option<&InformationElement> {
        element(&self.registry, &self.element_types, domain, field)
    }

    fn data_type(&self, domain: u32, field: &FieldSpecifier) -> DataType {
        self.element(domain, field)
            .map_or(DataType::OctetArray, |element| element.data_type)
    }

    /// Stores a template, replacing any earlier one with its ID right away.
    fn insert(&mut self, domain: u32, template_id: u16, template: TemplateRef) {
        let layout = layout(
            &self.registry,
            &self.element_types,
            domain,
            template.fields(),
        );
        let fields = layout.len();
        let entry = Entry { template, layout };
        self.templates.insert(domain, template_id, entry, fields);
    }

    fn refresh_layouts(&mut self, domain: u32) {
        let (registry, element_types) = (&self.registry, &self.element_types);
        for entry in self.templates.domain_mut(domain) {
            entry.layout = layout(registry, element_types, domain, entry.template.fields());
        }
    }

    fn parse_record(
        &self,
        r: &mut Reader,
        domain: u32,
        layout: &[Slot],
        depth: usize,
    ) -> Result<Vec<Value>, Truncated> {
        layout
            .iter()
            .map(|slot| {
                let length = parse_field_length(r, slot.field_length)?;
                Ok(self.decode_field(domain, slot.data_type, r.bytes(length)?, depth))
            })
            .collect()
    }

    /// Decodes a field, lists included; a malformed list keeps its bytes.
    fn decode_field(&self, domain: u32, data_type: DataType, bytes: &[u8], depth: usize) -> Value {
        let mut r = Reader::new(bytes);
        let list = match data_type {
            _ if depth >= MAX_LIST_DEPTH => None,
            DataType::BasicList => self
                .parse_basic_list(&mut r, domain, depth)
                .ok()
                .map(|list| Value::BasicList(Box::new(list))),
            DataType::SubTemplateList => self
                .parse_sub_template_list(&mut r, domain, depth)
                .ok()
                .map(|list| Value::SubTemplateList(Box::new(list))),
            DataType::SubTemplateMultiList => self
                .parse_sub_template_multi_list(&mut r, domain, depth)
                .ok()
                .map(|list| Value::SubTemplateMultiList(Box::new(list))),
            _ => None,
        };
        list.unwrap_or_else(|| decode(data_type, bytes))
    }

    fn parse_basic_list(
        &self,
        r: &mut Reader,
        domain: u32,
        depth: usize,
    ) -> Result<BasicList, Truncated> {
        let semantic = ListSemantic::from(r.u8()?);
        let field = parse_field_specifier(r)?;
        let data_type = self.data_type(domain, &field);
        let values = r.many(|r| {
            let length = parse_field_length(r, field.field_length)?;
            Ok::<_, Truncated>(self.decode_field(domain, data_type, r.bytes(length)?, depth + 1))
        });

        Ok(BasicList {
            semantic,
            field,
            values,
        })
    }

    fn parse_sub_template_list(
        &self,
        r: &mut Reader,
        domain: u32,
        depth: usize,
    ) -> Result<SubTemplateList, Truncated> {
        let semantic = ListSemantic::from(r.u8()?);
        let template_id = r.u16()?;
        let records = self.parse_list_records(r, domain, template_id, depth);

        Ok(SubTemplateList { semantic, records })
    }

    fn parse_sub_template_multi_list(
        &self,
        r: &mut Reader,
        domain: u32,
        depth: usize,
    ) -> Result<SubTemplateMultiList, Truncated> {
        let semantic = ListSemantic::from(r.u8()?);
        let groups = r.many(|r| {
            let template_id = r.u16()?;
            let length = r.u16()?;
            // RFC 6313 gives an empty group's length as both 4 and 0.
            let mut records = r.sub(usize::from(length).saturating_sub(LIST_GROUP_HEADER_SIZE))?;
            Ok::<_, Truncated>(self.parse_list_records(&mut records, domain, template_id, depth))
        });

        Ok(SubTemplateMultiList { semantic, groups })
    }

    fn parse_list_records(
        &self,
        r: &mut Reader,
        domain: u32,
        template_id: u16,
        depth: usize,
    ) -> ListRecords {
        match self.templates.get(domain, template_id) {
            Some(entry) => ListRecords::Decoded {
                template: entry.template.clone(),
                records: r.many(|r| self.parse_record(r, domain, &entry.layout, depth + 1)),
            },
            None => ListRecords::Undecoded {
                template_id,
                data: r.remaining().to_vec(),
            },
        }
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new(Registry::iana(), Duration::from_mins(10))
    }
}

fn element<'a>(
    registry: &'a Registry,
    element_types: &'a ElementTypes,
    domain: u32,
    field: &FieldSpecifier,
) -> Option<&'a InformationElement> {
    let (enterprise_number, id) = (field.enterprise_number, field.information_element_id);
    registry
        .get(enterprise_number, id)
        .or_else(|| element_types.get(domain, enterprise_number, id))
}

fn layout<'f>(
    registry: &Registry,
    element_types: &ElementTypes,
    domain: u32,
    fields: impl IntoIterator<Item = &'f FieldSpecifier>,
) -> Box<[Slot]> {
    fields
        .into_iter()
        .map(|field| Slot {
            field_length: field.field_length,
            data_type: element(registry, element_types, domain, field)
                .map_or(DataType::OctetArray, |element| element.data_type),
        })
        .collect()
}

fn parse_header(r: &mut Reader) -> Result<Header, Error> {
    let version = r.u16()?;
    if version != VERSION {
        return Err(Error::Version(version.into()));
    }
    let length = r.u16()?;
    let export_time = r.u32()?;
    let sequence_number = r.u32()?;
    let observation_domain_id = r.u32()?;

    Ok(Header {
        version,
        length,
        export_time,
        sequence_number,
        observation_domain_id,
    })
}

/// Template IDs start at [`MIN_TEMPLATE_ID`], except that a withdrawal of
/// every template of a kind carries its set ID. Rejecting the rest keeps
/// padding at the end of a set from being read as a template.
fn check_template_id(template_id: u16, field_count: u16, set_id: u16) -> Result<(), Error> {
    if template_id >= MIN_TEMPLATE_ID || (field_count == 0 && template_id == set_id) {
        Ok(())
    } else {
        Err(Error::TemplateId(template_id))
    }
}

fn parse_template(r: &mut Reader) -> Result<Template, Error> {
    let template_id = r.u16()?;
    let field_count = r.u16()?;
    check_template_id(template_id, field_count, TEMPLATE_SET_ID)?;
    let fields = r.repeat(usize::from(field_count), parse_field_specifier)?;

    Ok(Template {
        template_id,
        fields,
    })
}

fn parse_options_template(r: &mut Reader) -> Result<OptionsTemplate, Error> {
    let template_id = r.u16()?;
    let field_count = r.u16()?;
    check_template_id(template_id, field_count, OPTIONS_TEMPLATE_SET_ID)?;
    // A withdrawal has no scope field count (RFC 7011 section 8.1).
    if field_count == 0 {
        return Ok(OptionsTemplate {
            template_id,
            scope_fields: Vec::new(),
            option_fields: Vec::new(),
        });
    }
    let scope_field_count = r.u16()?;
    if scope_field_count == 0 || scope_field_count > field_count {
        return Err(Error::ScopeFieldCount(scope_field_count));
    }
    let scope_fields = r.repeat(usize::from(scope_field_count), parse_field_specifier)?;
    let option_fields = r.repeat(
        usize::from(field_count - scope_field_count),
        parse_field_specifier,
    )?;

    Ok(OptionsTemplate {
        template_id,
        scope_fields,
        option_fields,
    })
}

fn parse_field_specifier(r: &mut Reader) -> Result<FieldSpecifier, Truncated> {
    let id = r.u16()?;
    let field_length = r.u16()?;
    let enterprise_number = if id & ENTERPRISE_BIT == 0 {
        None
    } else {
        Some(r.u32()?)
    };

    Ok(FieldSpecifier {
        information_element_id: id & !ENTERPRISE_BIT,
        field_length,
        enterprise_number,
    })
}

/// A variable-length value is preceded by its length: one octet, or 255
/// followed by two (RFC 7011 section 7).
fn parse_field_length(r: &mut Reader, field_length: u16) -> Result<usize, Truncated> {
    if field_length != VARIABLE_LENGTH {
        return Ok(usize::from(field_length));
    }
    match r.u8()? {
        255 => Ok(usize::from(r.u16()?)),
        length => Ok(usize::from(length)),
    }
}
