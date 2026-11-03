//! NetFlow v9 (RFC 3954): a header followed by FlowSets. Template FlowSets
//! describe the records of later data FlowSets, so the parser keeps the
//! templates each exporter sent.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustflow_reader::{Reader, Truncated};

use crate::information_element::Registry;
use crate::value::{DataType, Value, decode};
use crate::{DataSet, Error};

pub const VERSION: u16 = 9;
pub const TEMPLATE_FLOW_SET_ID: u16 = 0;
pub const OPTIONS_TEMPLATE_FLOW_SET_ID: u16 = 1;

/// The lowest template ID. FlowSet IDs below it are reserved; from it up, a
/// FlowSet ID is the template ID of the data records it holds.
pub const MIN_TEMPLATE_ID: u16 = 256;

/// FlowSet ID and Length.
const FLOW_SET_HEADER_SIZE: usize = 4;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Packet {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub header: Header,
    pub flow_sets: Vec<FlowSet>,
}

/// The packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Header {
    /// Version of Flow Record format exported in this packet.
    pub version: u16,
    /// Total number of records in the packet: template, options template
    /// and data records together.
    pub count: u16,
    /// Time in milliseconds since this device was first booted.
    pub sys_uptime: u32,
    /// Time in seconds since 0000 UTC 1970, at which the packet leaves the
    /// exporter.
    pub unix_secs: u32,
    /// Incremental sequence counter of all packets sent from the current
    /// observation domain.
    pub sequence_number: u32,
    /// The exporter observation domain.
    pub source_id: u32,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FlowSet {
    Templates(Vec<Arc<Template>>),
    OptionsTemplates(Vec<Arc<OptionsTemplate>>),
    Data(DataSet<Template>),
    OptionsData(DataSet<OptionsTemplate>),
    /// A reserved FlowSet ID, or data whose template is unknown or expired.
    Unknown(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Template {
    pub template_id: u16,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Field {
    pub field_type: u16,
    /// The length of the field's values, in bytes.
    pub length: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OptionsTemplate {
    pub template_id: u16,
    /// What the options describe. The field type is a scope type: 1 System,
    /// 2 Interface, 3 Line Card, 4 Cache or 5 Template.
    pub scope_fields: Vec<Field>,
    pub option_fields: Vec<Field>,
}

/// Parses NetFlow v9 packets, keeping the templates each exporter sends for
/// the packets after it. Use one parser per exporter address: templates are
/// told apart only by source ID.
pub struct Parser {
    registry: Registry,
    timeout: Duration,
    templates: HashMap<(u32, u16), Entry>,
}

struct Entry {
    template: CachedTemplate,
    layout: Box<[(usize, DataType)]>,
    received: Instant,
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
            timeout,
            templates: HashMap::new(),
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
                let Some(entry) = self.get(source_id, id) else {
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
        let entry = Entry {
            template,
            layout,
            received: Instant::now(),
        };
        self.templates.insert((source_id, template_id), entry);
    }

    fn get(&self, source_id: u32, template_id: u16) -> Option<&Entry> {
        self.templates
            .get(&(source_id, template_id))
            .filter(|entry| entry.received.elapsed() < self.timeout)
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const SOURCE_ID: u32 = 7;
    const OCTET_DELTA_COUNT: u16 = 1;
    const PACKET_DELTA_COUNT: u16 = 2;
    const IPV4_SRC_ADDR: u16 = 8;
    const SAMPLING_INTERVAL: u16 = 34;
    const SYSTEM_SCOPE: u16 = 1;

    fn parser() -> Parser {
        Parser::new(Registry::iana(), Duration::from_mins(10))
    }

    fn packet(source_id: u32, flow_sets: &[Vec<u8>]) -> Vec<u8> {
        let header = [
            &VERSION.to_be_bytes()[..],
            &3u16.to_be_bytes(),
            &3_600_000u32.to_be_bytes(),
            &1_700_000_000u32.to_be_bytes(),
            &42u32.to_be_bytes(),
            &source_id.to_be_bytes(),
        ]
        .concat();
        [header, flow_sets.concat()].concat()
    }

    fn flow_set(id: u16, body: &[u8]) -> Vec<u8> {
        let length = u16::try_from(FLOW_SET_HEADER_SIZE + body.len()).unwrap();
        [&id.to_be_bytes()[..], &length.to_be_bytes(), body].concat()
    }

    fn fields(fields: &[(u16, u16)]) -> Vec<u8> {
        fields
            .iter()
            .flat_map(|(field_type, length)| [field_type.to_be_bytes(), length.to_be_bytes()])
            .flatten()
            .collect()
    }

    fn template(template_id: u16, template_fields: &[(u16, u16)]) -> Vec<u8> {
        let field_count = u16::try_from(template_fields.len()).unwrap();
        [
            &template_id.to_be_bytes()[..],
            &field_count.to_be_bytes(),
            &fields(template_fields),
        ]
        .concat()
    }

    fn options_template(template_id: u16, scope: &[(u16, u16)], options: &[(u16, u16)]) -> Vec<u8> {
        let (scope, options) = (fields(scope), fields(options));
        [
            &template_id.to_be_bytes()[..],
            &u16::try_from(scope.len()).unwrap().to_be_bytes(),
            &u16::try_from(options.len()).unwrap().to_be_bytes(),
            &scope,
            &options,
        ]
        .concat()
    }

    fn octet_count_template() -> Vec<u8> {
        flow_set(
            TEMPLATE_FLOW_SET_ID,
            &template(256, &[(OCTET_DELTA_COUNT, 4)]),
        )
    }

    fn octet_count_data(count: u32) -> Vec<u8> {
        flow_set(256, &count.to_be_bytes())
    }

    fn data_set(flow_set: &FlowSet) -> &DataSet<Template> {
        let FlowSet::Data(data) = flow_set else {
            panic!("expected a data FlowSet, got {flow_set:?}");
        };
        data
    }

    #[test]
    fn parses_the_header() {
        let packet = parser().parse(&packet(SOURCE_ID, &[])).unwrap();
        assert_eq!(
            packet.header,
            Header {
                version: VERSION,
                count: 3,
                sys_uptime: 3_600_000,
                unix_secs: 1_700_000_000,
                sequence_number: 42,
                source_id: SOURCE_ID,
            }
        );
        assert!(packet.flow_sets.is_empty());
    }

    #[test]
    fn another_version_is_rejected() {
        let mut datagram = packet(SOURCE_ID, &[]);
        datagram[..2].copy_from_slice(&10u16.to_be_bytes());
        assert_eq!(parser().parse(&datagram), Err(Error::Version(10)));
    }

    #[test]
    fn data_decodes_by_the_template_sent_before_it() {
        let template = flow_set(
            TEMPLATE_FLOW_SET_ID,
            &template(
                256,
                &[
                    (IPV4_SRC_ADDR, 4),
                    (OCTET_DELTA_COUNT, 4),
                    (PACKET_DELTA_COUNT, 8),
                ],
            ),
        );
        let record = [
            &[192, 0, 2, 1][..],
            &1500u32.to_be_bytes(),
            &10u64.to_be_bytes(),
        ]
        .concat();
        let data = flow_set(256, &[record.clone(), record].concat());

        let packet = parser()
            .parse(&packet(SOURCE_ID, &[data.clone(), template, data]))
            .unwrap();

        assert_eq!(packet.flow_sets[0], FlowSet::Unknown(256));
        let FlowSet::Templates(templates) = &packet.flow_sets[1] else {
            panic!("expected a template FlowSet");
        };
        let data = data_set(&packet.flow_sets[2]);
        assert!(Arc::ptr_eq(&templates[0], &data.template));
        let values = vec![
            Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1)),
            Value::Unsigned32(1500),
            Value::Unsigned64(10),
        ];
        assert_eq!(data.records, [values.clone(), values]);
    }

    #[test]
    fn unknown_field_types_keep_their_bytes() {
        let template = flow_set(TEMPLATE_FLOW_SET_ID, &template(256, &[(0xffff, 3)]));
        let data = flow_set(256, &[0xaa, 0xbb, 0xcc]);
        let packet = parser()
            .parse(&packet(SOURCE_ID, &[template, data]))
            .unwrap();
        assert_eq!(
            data_set(&packet.flow_sets[1]).records,
            [[Value::OctetArray(vec![0xaa, 0xbb, 0xcc])]]
        );
    }

    #[test]
    fn templates_are_kept_per_source_id_across_packets() {
        let mut parser = parser();
        parser
            .parse(&packet(SOURCE_ID, &[octet_count_template()]))
            .unwrap();

        let other_source = parser.parse(&packet(8, &[octet_count_data(42)])).unwrap();
        assert_eq!(other_source.flow_sets, [FlowSet::Unknown(256)]);

        let same_source = parser
            .parse(&packet(SOURCE_ID, &[octet_count_data(42)]))
            .unwrap();
        assert_eq!(
            data_set(&same_source.flow_sets[0]).records,
            [[Value::Unsigned32(42)]]
        );
    }

    #[test]
    fn a_resent_template_replaces_the_old_one_at_once() {
        let mut parser = parser();
        let first = parser
            .parse(&packet(
                SOURCE_ID,
                &[octet_count_template(), octet_count_data(42)],
            ))
            .unwrap();
        let replacement = flow_set(
            TEMPLATE_FLOW_SET_ID,
            &template(256, &[(PACKET_DELTA_COUNT, 4)]),
        );
        let second = parser
            .parse(&packet(SOURCE_ID, &[replacement, octet_count_data(42)]))
            .unwrap();

        let field_type =
            |packet: &Packet| data_set(&packet.flow_sets[1]).template.fields[0].field_type;
        assert_eq!(field_type(&first), OCTET_DELTA_COUNT);
        assert_eq!(field_type(&second), PACKET_DELTA_COUNT);
    }

    #[test]
    fn expired_templates_do_not_decode_data() {
        let mut parser = Parser::new(Registry::empty(), Duration::ZERO);
        let packet = parser
            .parse(&packet(
                SOURCE_ID,
                &[octet_count_template(), octet_count_data(42)],
            ))
            .unwrap();
        assert_eq!(packet.flow_sets[1], FlowSet::Unknown(256));
    }

    #[test]
    fn options_data_decodes_scope_values_before_option_values() {
        let template = flow_set(
            OPTIONS_TEMPLATE_FLOW_SET_ID,
            &[
                options_template(257, &[(SYSTEM_SCOPE, 4)], &[(SAMPLING_INTERVAL, 4)]),
                vec![0; 2],
            ]
            .concat(),
        );
        let data = flow_set(
            257,
            &[&7u32.to_be_bytes()[..], &100u32.to_be_bytes()].concat(),
        );

        let packet = parser()
            .parse(&packet(SOURCE_ID, &[template, data]))
            .unwrap();

        let FlowSet::OptionsTemplates(templates) = &packet.flow_sets[0] else {
            panic!("expected an options template FlowSet");
        };
        assert_eq!(
            *templates[0],
            OptionsTemplate {
                template_id: 257,
                scope_fields: vec![Field {
                    field_type: SYSTEM_SCOPE,
                    length: 4
                }],
                option_fields: vec![Field {
                    field_type: SAMPLING_INTERVAL,
                    length: 4
                }],
            }
        );
        let FlowSet::OptionsData(data) = &packet.flow_sets[1] else {
            panic!("expected an options data FlowSet");
        };
        assert!(Arc::ptr_eq(&templates[0], &data.template));
        assert_eq!(
            data.records,
            [[Value::Unsigned32(7), Value::Unsigned32(100)]]
        );
    }

    #[test]
    fn a_template_id_can_move_between_template_kinds() {
        let mut parser = parser();
        parser
            .parse(&packet(SOURCE_ID, &[octet_count_template()]))
            .unwrap();
        let options = flow_set(
            OPTIONS_TEMPLATE_FLOW_SET_ID,
            &options_template(256, &[(SYSTEM_SCOPE, 4)], &[]),
        );
        let packet = parser
            .parse(&packet(SOURCE_ID, &[options, octet_count_data(7)]))
            .unwrap();
        assert!(matches!(packet.flow_sets[1], FlowSet::OptionsData(_)));
    }

    #[test]
    fn padding_does_not_become_records_or_templates() {
        let template = flow_set(
            TEMPLATE_FLOW_SET_ID,
            &[template(256, &[(OCTET_DELTA_COUNT, 8)]), vec![0; 4]].concat(),
        );
        let data = flow_set(
            256,
            &[&42u64.to_be_bytes()[..], &43u64.to_be_bytes(), &[0; 4]].concat(),
        );

        let packet = parser()
            .parse(&packet(
                SOURCE_ID,
                &[template, data, octet_count_template()],
            ))
            .unwrap();

        let FlowSet::Templates(templates) = &packet.flow_sets[0] else {
            panic!("expected a template FlowSet");
        };
        assert_eq!(templates.len(), 1);
        assert_eq!(
            data_set(&packet.flow_sets[1]).records,
            [[Value::Unsigned64(42)], [Value::Unsigned64(43)]]
        );
        assert!(matches!(packet.flow_sets[2], FlowSet::Templates(_)));
    }

    #[test]
    fn a_template_without_fields_yields_no_records() {
        let template = flow_set(TEMPLATE_FLOW_SET_ID, &template(256, &[]));
        let packet = parser()
            .parse(&packet(
                SOURCE_ID,
                &[template, flow_set(256, &[0; 4]), octet_count_template()],
            ))
            .unwrap();
        assert!(data_set(&packet.flow_sets[1]).records.is_empty());
        assert_eq!(packet.flow_sets.len(), 3);
    }

    #[test]
    fn reserved_flow_set_ids_are_unknown() {
        let packet = parser()
            .parse(&packet(SOURCE_ID, &[flow_set(2, &[1, 2, 3, 4])]))
            .unwrap();
        assert_eq!(packet.flow_sets, [FlowSet::Unknown(2)]);
    }

    #[test]
    fn parsing_stops_at_a_truncated_flow_set() {
        let mut truncated = octet_count_data(42);
        truncated.truncate(6);
        let mut parser = parser();
        let parsed = parser
            .parse(&packet(SOURCE_ID, &[octet_count_template(), truncated]))
            .unwrap();

        assert_eq!(parsed.flow_sets.len(), 1);
        let later = parser
            .parse(&packet(SOURCE_ID, &[octet_count_data(42)]))
            .unwrap();
        assert!(matches!(later.flow_sets[0], FlowSet::Data(_)));
    }

    #[test]
    fn parsing_stops_at_a_flow_set_shorter_than_its_header() {
        let short = [&256u16.to_be_bytes()[..], &3u16.to_be_bytes()].concat();
        let packet = parser()
            .parse(&packet(
                SOURCE_ID,
                &[octet_count_template(), short, octet_count_template()],
            ))
            .unwrap();
        assert_eq!(packet.flow_sets.len(), 1);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn round_trips_through_serde() {
        let packet = parser()
            .parse(&packet(
                SOURCE_ID,
                &[octet_count_template(), octet_count_data(42)],
            ))
            .unwrap();
        let json = serde_json::to_value(&packet).unwrap();
        assert_eq!(json["source_id"], SOURCE_ID);
        assert_eq!(
            json["flow_sets"][1]["Data"]["records"],
            serde_json::json!([[{ "Unsigned32": 42 }]])
        );
        assert_eq!(serde_json::from_value::<Packet>(json).unwrap(), packet);
    }
}
