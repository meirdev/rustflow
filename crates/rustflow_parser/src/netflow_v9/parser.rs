use std::sync::Arc;
use std::time::Duration;

use rustflow_reader::{Reader, Truncated};

use super::*;
use crate::information_element::{DataType, Registry};
use crate::template_cache::TemplateCache;
use crate::value::{Value, decode};
use crate::{DataSet, Error};

/// Parses NetFlow v9 packets, keeping the templates each exporter sends for
/// the packets after it. Use one parser per exporter address: templates are
/// told apart only by source ID.
///
/// A parser holds templates of 65,536 fields at most: one that does not fit
/// is refused, and the template it would replace is dropped.
pub struct Parser {
    registry: Registry,
    templates: TemplateCache<Entry>,
}

struct Entry {
    template: CachedTemplate,
    layout: Box<[(usize, DataType)]>,
}

enum CachedTemplate {
    Data(Arc<Template>),
    Options(Arc<OptionsTemplate>),
}

impl Parser {
    /// Field types are looked up in `registry` as IANA elements; values of
    /// field types it lacks are kept as octet arrays. A template expires
    /// `timeout` after it was last received.
    pub fn new(registry: Registry, timeout: Duration) -> Self {
        Self {
            registry,
            templates: TemplateCache::new(timeout),
        }
    }

    /// Parses a NetFlow v9 datagram. Parsing stops at the first FlowSet
    /// that is malformed or truncated; the FlowSets before it are kept.
    pub fn parse(&mut self, datagram: &[u8]) -> Result<Packet, Error> {
        let mut r = Reader::new(datagram);
        let header = parse_header(&mut r)?;
        let flow_sets = r.many(|r| self.parse_flow_set(r, header.source_id));

        Ok(Packet { header, flow_sets })
    }

    fn parse_flow_set(&mut self, r: &mut Reader, source_id: u32) -> Result<FlowSet, Error> {
        let flow_set_id = r.u16()?;
        let length = r.u16()?;
        let body_length = usize::from(length)
            .checked_sub(FLOW_SET_HEADER_SIZE)
            .ok_or(Error::SetLength(length))?;
        let mut body = r.sub(body_length)?;

        let flow_set = match flow_set_id {
            TEMPLATE_FLOW_SET_ID => {
                let templates: Vec<_> = body
                    .many(parse_template)
                    .into_iter()
                    .map(Arc::new)
                    .collect();
                for template in &templates {
                    let layout = self.layout(&template.fields).collect();
                    self.insert(
                        source_id,
                        template.template_id,
                        CachedTemplate::Data(Arc::clone(template)),
                        layout,
                    );
                }
                FlowSet::Templates(templates)
            }
            OPTIONS_TEMPLATE_FLOW_SET_ID => {
                let templates: Vec<_> = body
                    .many(parse_options_template)
                    .into_iter()
                    .map(Arc::new)
                    .collect();
                for template in &templates {
                    let scope = template
                        .scope_fields
                        .iter()
                        .map(|field| (usize::from(field.length), DataType::Unsigned64));
                    let layout = scope.chain(self.layout(&template.option_fields)).collect();
                    self.insert(
                        source_id,
                        template.template_id,
                        CachedTemplate::Options(Arc::clone(template)),
                        layout,
                    );
                }
                FlowSet::OptionsTemplates(templates)
            }
            id if id >= MIN_TEMPLATE_ID => {
                let Some(entry) = self.templates.get(source_id, id) else {
                    return Ok(FlowSet::Unknown(id));
                };
                let records = body.many(|r| parse_record(r, &entry.layout));
                match &entry.template {
                    CachedTemplate::Data(template) => FlowSet::Data(DataSet {
                        template: Arc::clone(template),
                        records,
                    }),
                    CachedTemplate::Options(template) => FlowSet::OptionsData(DataSet {
                        template: Arc::clone(template),
                        records,
                    }),
                }
            }
            id => FlowSet::Unknown(id),
        };

        Ok(flow_set)
    }

    fn layout(&self, fields: &[Field]) -> impl Iterator<Item = (usize, DataType)> {
        fields.iter().map(|field| {
            let data_type = self
                .registry
                .get(None, field.field_type)
                .map_or(DataType::OctetArray, |element| element.data_type);
            (usize::from(field.length), data_type)
        })
    }

    /// Stores a template, replacing any earlier one with its ID right away.
    fn insert(
        &mut self,
        source_id: u32,
        template_id: u16,
        template: CachedTemplate,
        layout: Box<[(usize, DataType)]>,
    ) {
        let fields = layout.len();
        let entry = Entry { template, layout };
        self.templates.insert(source_id, template_id, entry, fields);
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new(Registry::iana(), Duration::from_mins(10))
    }
}

fn parse_header(r: &mut Reader) -> Result<Header, Error> {
    let version = r.u16()?;
    if version != VERSION {
        return Err(Error::Version(version.into()));
    }
    let count = r.u16()?;
    let sys_uptime = r.u32()?;
    let unix_secs = r.u32()?;
    let sequence_number = r.u32()?;
    let source_id = r.u32()?;

    Ok(Header {
        version,
        count,
        sys_uptime,
        unix_secs,
        sequence_number,
        source_id,
    })
}

/// A template ID below [`MIN_TEMPLATE_ID`] is an error, so that padding at
/// the end of a FlowSet is not read as a template.
fn parse_template_id(r: &mut Reader) -> Result<u16, Error> {
    let template_id = r.u16()?;
    if template_id < MIN_TEMPLATE_ID {
        return Err(Error::TemplateId(template_id));
    }
    Ok(template_id)
}

fn parse_template(r: &mut Reader) -> Result<Template, Error> {
    let template_id = parse_template_id(r)?;
    let field_count = r.u16()?;
    let fields = r.repeat(usize::from(field_count), parse_field)?;

    Ok(Template {
        template_id,
        fields,
    })
}

fn parse_options_template(r: &mut Reader) -> Result<OptionsTemplate, Error> {
    let template_id = parse_template_id(r)?;
    let option_scope_length = r.u16()?;
    let option_length = r.u16()?;
    let scope_fields = r.sub(usize::from(option_scope_length))?.many(parse_field);
    let option_fields = r.sub(usize::from(option_length))?.many(parse_field);

    Ok(OptionsTemplate {
        template_id,
        scope_fields,
        option_fields,
    })
}

fn parse_field(r: &mut Reader) -> Result<Field, Truncated> {
    let field_type = r.u16()?;
    let length = r.u16()?;

    Ok(Field { field_type, length })
}

fn parse_record(r: &mut Reader, layout: &[(usize, DataType)]) -> Result<Vec<Value>, Truncated> {
    layout
        .iter()
        .map(|&(length, data_type)| Ok(decode(data_type, r.bytes(length)?)))
        .collect()
}
