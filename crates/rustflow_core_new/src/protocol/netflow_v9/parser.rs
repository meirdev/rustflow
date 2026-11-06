use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::bytes::{Reader, Truncated};
use crate::protocol::information_element::{DataType, ElementId, Registry};
use crate::protocol::template_cache::{Entry, SPARE_FIELDS, Slot, TemplateCache, records_in};
use crate::protocol::value::{Value, decode};
use crate::protocol::{DataSet, ParseError};

/// Parses NetFlow v9 packets, keeping the templates each exporter sends for
/// the packets after it. Use one parser per exporter address: templates are
/// told apart only by source ID.
///
/// A parser holds templates of 65,536 fields at most: one that does not fit
/// is refused, and the template it would replace is dropped.
pub struct Parser {
    registry: Registry,
    templates: TemplateCache<Entry<CachedTemplate>>,
    /// When the packet being parsed arrived, which decides which templates
    /// have expired.
    now: Instant,
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
            now: Instant::now(),
        }
    }

    /// Parses a NetFlow v9 datagram. Parsing stops at the first FlowSet
    /// that is malformed or truncated; the FlowSets before it are kept.
    pub fn parse(&mut self, datagram: &[u8]) -> Result<Packet, ParseError> {
        self.parse_at(datagram, Instant::now())
    }

    /// [`parse`](Self::parse) as of `now`, which decides which templates
    /// have expired: for a caller that has the time already.
    pub fn parse_at(&mut self, datagram: &[u8], now: Instant) -> Result<Packet, ParseError> {
        self.now = now;
        let mut r = Reader::new(datagram);
        let header = parse_header(&mut r)?;
        let flow_sets = r.many(|r| self.parse_flow_set(r, header.source_id));

        Ok(Packet { header, flow_sets })
    }

    fn parse_flow_set(&mut self, r: &mut Reader, source_id: u32) -> Result<FlowSet, ParseError> {
        let flow_set_id = r.u16()?;
        let length = r.u16()?;
        let body_length = usize::from(length)
            .checked_sub(FLOW_SET_HEADER_SIZE)
            .ok_or(ParseError::SetLength(length))?;
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
                    self.templates.insert_entry(
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
                    let scope = template.scope_fields.iter().map(|field| Slot {
                        field_length: field.length,
                        data_type: DataType::Unsigned64,
                    });
                    let layout = scope.chain(self.layout(&template.option_fields)).collect();
                    self.templates.insert_entry(
                        source_id,
                        template.template_id,
                        CachedTemplate::Options(Arc::clone(template)),
                        layout,
                    );
                }
                FlowSet::OptionsTemplates(templates)
            }
            id if id >= MIN_TEMPLATE_ID => self
                .decode_data(source_id, id, &mut body)
                .unwrap_or_else(|| FlowSet::Undecoded {
                    flow_set_id: id,
                    body: body.remaining().to_vec(),
                }),
            id => FlowSet::Unknown(id),
        };

        Ok(flow_set)
    }

    /// Retries only missing templates, without replaying template records
    /// or changing the interpretation of data that was already decoded.
    pub(crate) fn resolve(&mut self, packet: &mut Packet) {
        self.now = Instant::now();
        for set in &mut packet.flow_sets {
            if let FlowSet::Undecoded { flow_set_id, body } = set
                && let Some(decoded) = self.decode_data(
                    packet.header.source_id,
                    *flow_set_id,
                    &mut Reader::new(body),
                )
            {
                *set = decoded;
            }
        }
    }

    fn decode_data(&self, source_id: u32, id: u16, body: &mut Reader) -> Option<FlowSet> {
        let entry = self.templates.get(source_id, id, self.now)?;
        let records = body.many_sized(records_in(body.len(), &entry.layout), |r| {
            parse_record(r, &entry.layout)
        });
        Some(match &entry.template {
            CachedTemplate::Data(template) => FlowSet::Data(DataSet {
                template: Arc::clone(template),
                records,
            }),
            CachedTemplate::Options(template) => FlowSet::OptionsData(DataSet {
                template: Arc::clone(template),
                records,
            }),
        })
    }

    fn layout(&self, fields: &[Field]) -> impl Iterator<Item = Slot> {
        fields.iter().map(|field| Slot {
            field_length: field.length,
            data_type: self
                .registry
                .get(ElementId::iana(field.field_type))
                .map_or(DataType::OctetArray, |element| element.data_type),
        })
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new(Registry::iana(), Duration::from_mins(10))
    }
}

fn parse_header(r: &mut Reader) -> Result<Header, ParseError> {
    let version = r.u16()?;
    if version != VERSION {
        return Err(ParseError::Version(version.into()));
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
fn parse_template_id(r: &mut Reader) -> Result<u16, ParseError> {
    let template_id = r.u16()?;
    if template_id < MIN_TEMPLATE_ID {
        return Err(ParseError::TemplateId(template_id));
    }
    Ok(template_id)
}

fn parse_template(r: &mut Reader) -> Result<Template, ParseError> {
    let template_id = parse_template_id(r)?;
    let field_count = r.u16()?;
    let fields = r.repeat(usize::from(field_count), parse_field)?;

    Ok(Template {
        template_id,
        fields,
    })
}

fn parse_options_template(r: &mut Reader) -> Result<OptionsTemplate, ParseError> {
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

fn parse_record(r: &mut Reader, layout: &[Slot]) -> Result<Vec<Value>, Truncated> {
    let mut values = Vec::with_capacity(layout.len() + SPARE_FIELDS);
    for slot in layout {
        let bytes = r.bytes(usize::from(slot.field_length))?;
        values.push(decode(slot.data_type, bytes));
    }
    Ok(values)
}
