//! IPFIX (RFC 7011): a message header followed by sets. Template sets
//! describe the records of later data sets, so the parser keeps the
//! templates each exporter sent. A field may be variable-length, and may
//! hold a list of values or of records (RFC 6313).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustflow_reader::{Reader, Truncated};

use crate::information_element::Registry;
use crate::value::{DataType, Value, decode};
use crate::{DataSet, Error};

pub const VERSION: u16 = 10;
pub const TEMPLATE_SET_ID: u16 = 2;
pub const OPTIONS_TEMPLATE_SET_ID: u16 = 3;
/// The lowest template ID. Set IDs below it are reserved; from it up, a set
/// ID is the template ID of the data records it holds.
pub const MIN_TEMPLATE_ID: u16 = 256;
/// The field length of a variable-length field, whose values each carry
/// their own length.
pub const VARIABLE_LENGTH: u16 = 65535;

/// Version, Length, Export Time, Sequence Number and Observation Domain ID.
const HEADER_SIZE: usize = 16;
/// Set ID and Length.
const SET_HEADER_SIZE: usize = 4;
/// Template ID and Data Records Length.
const LIST_GROUP_HEADER_SIZE: usize = 4;
const ENTERPRISE_BIT: u16 = 0x8000;
/// How deep lists may nest before the rest is kept undecoded. The exporter
/// controls the nesting, and each level costs stack.
const MAX_LIST_DEPTH: usize = 8;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Packet {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub header: Header,
    pub sets: Vec<Set>,
}

/// The message header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Header {
    /// Version of the IPFIX format of the message.
    pub version: u16,
    /// Total length of the message in octets, header and sets included.
    pub length: u16,
    /// Seconds since 0000 UTC 1970, modulo 2^32, at which the message
    /// left the exporter.
    pub export_time: u32,
    /// Counter, modulo 2^32, of the data records the exporter sent from the
    /// observation domain before this message.
    pub sequence_number: u32,
    /// The observation domain the message's records come from, unique
    /// within the exporter.
    pub observation_domain_id: u32,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Set {
    Templates(Vec<Arc<Template>>),
    OptionsTemplates(Vec<Arc<OptionsTemplate>>),
    Data(DataSet<Template>),
    OptionsData(DataSet<OptionsTemplate>),
    /// A reserved set ID, or data whose template is unknown or expired.
    Unknown(u16),
}

/// A template, or with no fields, a template withdrawal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Template {
    pub template_id: u16,
    pub fields: Vec<FieldSpecifier>,
}

/// An options template, or with no fields, an options template withdrawal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OptionsTemplate {
    pub template_id: u16,
    /// The fields saying what the options describe.
    pub scope_fields: Vec<FieldSpecifier>,
    pub option_fields: Vec<FieldSpecifier>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FieldSpecifier {
    /// The information element's ID, without the enterprise bit.
    pub information_element_id: u16,
    /// In octets, or [`VARIABLE_LENGTH`].
    pub field_length: u16,
    /// The private enterprise number of a vendor's element; `None` for an
    /// IANA element.
    pub enterprise_number: Option<u32>,
}

/// A template held by the parser, of either kind.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TemplateRef {
    Data(Arc<Template>),
    Options(Arc<OptionsTemplate>),
}

/// How a list's elements relate to the record holding it, numbered as in
/// IANA's IPFIX Structured Data Types Semantics registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ListSemantic {
    NoneOf,
    ExactlyOneOf,
    OneOrMoreOf,
    AllOf,
    Ordered,
    Undefined,
    Unassigned(u8),
}

impl From<u8> for ListSemantic {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::NoneOf,
            1 => Self::ExactlyOneOf,
            2 => Self::OneOrMoreOf,
            3 => Self::AllOf,
            4 => Self::Ordered,
            255 => Self::Undefined,
            value => Self::Unassigned(value),
        }
    }
}

/// Values of one information element.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BasicList {
    pub semantic: ListSemantic,
    pub field: FieldSpecifier,
    pub values: Vec<Value>,
}

/// Records of one template.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SubTemplateList {
    pub semantic: ListSemantic,
    pub records: ListRecords,
}

/// Groups of records, each group of one template.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SubTemplateMultiList {
    pub semantic: ListSemantic,
    pub groups: Vec<ListRecords>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ListRecords {
    Decoded {
        template: TemplateRef,
        records: Vec<Vec<Value>>,
    },
    /// Records of a template the parser does not have, kept as sent.
    Undecoded { template_id: u16, data: Vec<u8> },
}

/// Parses IPFIX messages, keeping the templates each exporter sends for the
/// messages after it. Use one parser per exporter address: templates are
/// told apart only by observation domain ID.
///
/// Template withdrawals are parsed but not applied: a collector receiving
/// over UDP must ignore them (RFC 7011 section 8.4), and lets templates
/// expire instead.
pub struct Parser {
    registry: Registry,
    timeout: Duration,
    templates: HashMap<(u32, u16), Entry>,
}

struct Entry {
    template: TemplateRef,
    layout: Box<[Slot]>,
    received: Instant,
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
            timeout,
            templates: HashMap::new(),
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
                    let layout = self.layout(&template.fields);
                    let template_ref = TemplateRef::Data(Arc::clone(template));
                    self.insert(domain, template.template_id, template_ref, layout);
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
                    let layout =
                        self.layout(template.scope_fields.iter().chain(&template.option_fields));
                    let template_ref = TemplateRef::Options(Arc::clone(template));
                    self.insert(domain, template.template_id, template_ref, layout);
                }
                Set::OptionsTemplates(templates)
            }
            id if id >= MIN_TEMPLATE_ID => {
                let Some(entry) = self.get(domain, id) else {
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

        Ok(set)
    }

    fn layout<'f>(&self, fields: impl IntoIterator<Item = &'f FieldSpecifier>) -> Box<[Slot]> {
        fields
            .into_iter()
            .map(|field| Slot {
                field_length: field.field_length,
                data_type: self.data_type(field),
            })
            .collect()
    }

    fn data_type(&self, field: &FieldSpecifier) -> DataType {
        self.registry
            .get(field.enterprise_number, field.information_element_id)
            .map_or(DataType::OctetArray, |element| element.data_type)
    }

    /// Stores a template, replacing any earlier one with its ID right away.
    fn insert(
        &mut self,
        domain: u32,
        template_id: u16,
        template: TemplateRef,
        layout: Box<[Slot]>,
    ) {
        let entry = Entry {
            template,
            layout,
            received: Instant::now(),
        };
        self.templates.insert((domain, template_id), entry);
    }

    fn get(&self, domain: u32, template_id: u16) -> Option<&Entry> {
        self.templates
            .get(&(domain, template_id))
            .filter(|entry| entry.received.elapsed() < self.timeout)
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
        let data_type = self.data_type(&field);
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
        match self.get(domain, template_id) {
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

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::information_element::{DataTypeSemantics, InformationElement};

    const DOMAIN: u32 = 7;
    const OCTET_DELTA_COUNT: u16 = 1;
    const SOURCE_IPV4_ADDRESS: u16 = 8;
    const SAMPLING_INTERVAL: u16 = 34;
    const INTERFACE_NAME: u16 = 82;
    const OBSERVATION_DOMAIN_ID: u16 = 149;
    const BASIC_LIST: u16 = 291;
    const SUB_TEMPLATE_LIST: u16 = 292;
    const SUB_TEMPLATE_MULTI_LIST: u16 = 293;

    fn message(domain: u32, sets: &[Vec<u8>]) -> Vec<u8> {
        let sets = sets.concat();
        let length = u16::try_from(HEADER_SIZE + sets.len()).unwrap();
        [
            &VERSION.to_be_bytes()[..],
            &length.to_be_bytes(),
            &1_700_000_000u32.to_be_bytes(),
            &42u32.to_be_bytes(),
            &domain.to_be_bytes(),
            &sets,
        ]
        .concat()
    }

    fn set(id: u16, body: &[u8]) -> Vec<u8> {
        let length = u16::try_from(SET_HEADER_SIZE + body.len()).unwrap();
        [&id.to_be_bytes()[..], &length.to_be_bytes(), body].concat()
    }

    fn field(id: u16, length: u16) -> Vec<u8> {
        [id.to_be_bytes(), length.to_be_bytes()].concat()
    }

    fn enterprise_field(id: u16, length: u16, enterprise_number: u32) -> Vec<u8> {
        [
            &(id | ENTERPRISE_BIT).to_be_bytes()[..],
            &length.to_be_bytes(),
            &enterprise_number.to_be_bytes(),
        ]
        .concat()
    }

    fn template(template_id: u16, fields: &[Vec<u8>]) -> Vec<u8> {
        let field_count = u16::try_from(fields.len()).unwrap();
        [
            &template_id.to_be_bytes()[..],
            &field_count.to_be_bytes(),
            &fields.concat(),
        ]
        .concat()
    }

    fn options_template(template_id: u16, scope_field_count: u16, fields: &[Vec<u8>]) -> Vec<u8> {
        let field_count = u16::try_from(fields.len()).unwrap();
        [
            &template_id.to_be_bytes()[..],
            &field_count.to_be_bytes(),
            &scope_field_count.to_be_bytes(),
            &fields.concat(),
        ]
        .concat()
    }

    fn variable(value: &[u8]) -> Vec<u8> {
        match u8::try_from(value.len()) {
            Ok(length) if length < 255 => [&[length][..], value].concat(),
            _ => [
                &[255][..],
                &u16::try_from(value.len()).unwrap().to_be_bytes(),
                value,
            ]
            .concat(),
        }
    }

    fn octet_count_template() -> Vec<u8> {
        set(
            TEMPLATE_SET_ID,
            &template(256, &[field(OCTET_DELTA_COUNT, 4)]),
        )
    }

    fn octet_count_data(count: u32) -> Vec<u8> {
        set(256, &count.to_be_bytes())
    }

    fn data_set(set: &Set) -> &DataSet<Template> {
        let Set::Data(data) = set else {
            panic!("expected a data set, got {set:?}");
        };
        data
    }

    /// The value of the first field of the first record in the last set.
    fn only_value(packet: &Packet) -> &Value {
        &data_set(packet.sets.last().unwrap()).records[0][0]
    }

    #[test]
    fn parses_the_header() {
        let packet = Parser::default().parse(&message(DOMAIN, &[])).unwrap();
        assert_eq!(
            packet.header,
            Header {
                version: VERSION,
                length: 16,
                export_time: 1_700_000_000,
                sequence_number: 42,
                observation_domain_id: DOMAIN,
            }
        );
        assert!(packet.sets.is_empty());
    }

    #[test]
    fn another_version_is_rejected() {
        let mut datagram = message(DOMAIN, &[]);
        datagram[..2].copy_from_slice(&9u16.to_be_bytes());
        assert_eq!(Parser::default().parse(&datagram), Err(Error::Version(9)));
    }

    #[test]
    fn the_message_length_bounds_the_sets() {
        let mut datagram = message(DOMAIN, &[octet_count_template()]);
        datagram.extend([0xff; 3]);
        assert_eq!(Parser::default().parse(&datagram).unwrap().sets.len(), 1);

        let mut short = message(DOMAIN, &[]);
        short[2..4].copy_from_slice(&15u16.to_be_bytes());
        assert_eq!(
            Parser::default().parse(&short),
            Err(Error::MessageLength(15))
        );

        let mut long = message(DOMAIN, &[]);
        long[2..4].copy_from_slice(&20u16.to_be_bytes());
        assert!(matches!(
            Parser::default().parse(&long),
            Err(Error::Truncated(_))
        ));
    }

    #[test]
    fn data_decodes_by_the_template_sent_before_it() {
        let template = set(
            TEMPLATE_SET_ID,
            &template(
                256,
                &[field(SOURCE_IPV4_ADDRESS, 4), field(OCTET_DELTA_COUNT, 8)],
            ),
        );
        let record = [&[192, 0, 2, 1][..], &1500u64.to_be_bytes()].concat();
        let data = set(256, &[record.clone(), record].concat());

        let packet = Parser::default()
            .parse(&message(DOMAIN, &[data.clone(), template, data]))
            .unwrap();

        assert_eq!(packet.sets[0], Set::Unknown(256));
        let Set::Templates(templates) = &packet.sets[1] else {
            panic!("expected a template set");
        };
        let data = data_set(&packet.sets[2]);
        assert!(Arc::ptr_eq(&templates[0], &data.template));
        let values = vec![
            Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1)),
            Value::Unsigned64(1500),
        ];
        assert_eq!(data.records, [values.clone(), values]);
    }

    #[test]
    fn enterprise_fields_are_looked_up_by_their_enterprise_number() {
        let template = set(
            TEMPLATE_SET_ID,
            &template(
                256,
                &[enterprise_field(1, 4, 9), field(OCTET_DELTA_COUNT, 4)],
            ),
        );
        let data = set(256, &[0, 0, 0, 5, 0, 0, 0, 6]);
        let datagram = message(DOMAIN, &[template, data]);

        let packet = Parser::default().parse(&datagram).unwrap();
        let Set::Templates(templates) = &packet.sets[0] else {
            panic!("expected a template set");
        };
        assert_eq!(
            templates[0].fields,
            [
                FieldSpecifier {
                    information_element_id: 1,
                    field_length: 4,
                    enterprise_number: Some(9),
                },
                FieldSpecifier {
                    information_element_id: OCTET_DELTA_COUNT,
                    field_length: 4,
                    enterprise_number: None,
                },
            ]
        );
        assert_eq!(
            data_set(&packet.sets[1]).records,
            [[Value::OctetArray(vec![0, 0, 0, 5]), Value::Unsigned32(6)]]
        );

        let mut registry = Registry::iana();
        registry.insert(InformationElement {
            id: 1,
            enterprise_number: Some(9),
            name: Cow::Borrowed("vendorCounter"),
            data_type: DataType::Unsigned32,
            semantics: Some(DataTypeSemantics::TotalCounter),
        });
        let packet = Parser::new(registry, Duration::from_mins(10))
            .parse(&datagram)
            .unwrap();
        assert_eq!(
            data_set(&packet.sets[1]).records,
            [[Value::Unsigned32(5), Value::Unsigned32(6)]]
        );
    }

    #[test]
    fn variable_length_values_carry_their_length() {
        let template = set(
            TEMPLATE_SET_ID,
            &template(
                256,
                &[
                    field(INTERFACE_NAME, VARIABLE_LENGTH),
                    field(OCTET_DELTA_COUNT, 4),
                ],
            ),
        );
        let long_name = vec![b'a'; 300];
        let data = set(
            256,
            &[
                variable(b"eth0"),
                1u32.to_be_bytes().to_vec(),
                variable(&long_name),
                2u32.to_be_bytes().to_vec(),
                // The three-octet form for a short value.
                vec![255, 0, 3],
                b"abc".to_vec(),
                3u32.to_be_bytes().to_vec(),
            ]
            .concat(),
        );

        let packet = Parser::default()
            .parse(&message(DOMAIN, &[template, data]))
            .unwrap();
        let name = |name: &[u8]| Value::String(String::from_utf8(name.to_vec()).unwrap());
        assert_eq!(
            data_set(&packet.sets[1]).records,
            [
                [name(b"eth0"), Value::Unsigned32(1)],
                [name(&long_name), Value::Unsigned32(2)],
                [name(b"abc"), Value::Unsigned32(3)],
            ]
        );
    }

    #[test]
    fn options_data_decodes_scope_values_before_option_values() {
        let template = set(
            OPTIONS_TEMPLATE_SET_ID,
            &options_template(
                257,
                1,
                &[field(OBSERVATION_DOMAIN_ID, 4), field(SAMPLING_INTERVAL, 4)],
            ),
        );
        let data = set(
            257,
            &[&DOMAIN.to_be_bytes()[..], &100u32.to_be_bytes()].concat(),
        );

        let packet = Parser::default()
            .parse(&message(DOMAIN, &[template, data]))
            .unwrap();

        let Set::OptionsTemplates(templates) = &packet.sets[0] else {
            panic!("expected an options template set");
        };
        let field = |id| FieldSpecifier {
            information_element_id: id,
            field_length: 4,
            enterprise_number: None,
        };
        assert_eq!(
            *templates[0],
            OptionsTemplate {
                template_id: 257,
                scope_fields: vec![field(OBSERVATION_DOMAIN_ID)],
                option_fields: vec![field(SAMPLING_INTERVAL)],
            }
        );
        let Set::OptionsData(data) = &packet.sets[1] else {
            panic!("expected an options data set");
        };
        assert!(Arc::ptr_eq(&templates[0], &data.template));
        assert_eq!(
            data.records,
            [[Value::Unsigned32(DOMAIN), Value::Unsigned32(100)]]
        );
    }

    #[test]
    fn an_options_template_needs_one_to_all_of_its_fields_in_scope() {
        let fields = [field(OBSERVATION_DOMAIN_ID, 4), field(SAMPLING_INTERVAL, 4)];
        for scope_field_count in [0, 3] {
            let template = set(
                OPTIONS_TEMPLATE_SET_ID,
                &options_template(257, scope_field_count, &fields),
            );
            let packet = Parser::default()
                .parse(&message(DOMAIN, &[template, set(257, &[0; 8])]))
                .unwrap();
            assert_eq!(
                packet.sets,
                [Set::OptionsTemplates(Vec::new()), Set::Unknown(257)]
            );
        }
    }

    #[test]
    fn withdrawals_are_parsed_but_not_applied() {
        let mut parser = Parser::default();
        parser
            .parse(&message(DOMAIN, &[octet_count_template()]))
            .unwrap();
        let withdrawals = set(
            TEMPLATE_SET_ID,
            &[template(256, &[]), template(TEMPLATE_SET_ID, &[])].concat(),
        );
        let options_withdrawals = set(
            OPTIONS_TEMPLATE_SET_ID,
            &[
                template(258, &[]),
                options_template(259, 1, &[field(OBSERVATION_DOMAIN_ID, 4)]),
            ]
            .concat(),
        );

        let packet = parser
            .parse(&message(
                DOMAIN,
                &[withdrawals, options_withdrawals, octet_count_data(42)],
            ))
            .unwrap();

        let Set::Templates(templates) = &packet.sets[0] else {
            panic!("expected a template set");
        };
        let withdrawn: Vec<_> = templates
            .iter()
            .map(|t| (t.template_id, t.fields.len()))
            .collect();
        assert_eq!(withdrawn, [(256, 0), (TEMPLATE_SET_ID, 0)]);
        let Set::OptionsTemplates(options_templates) = &packet.sets[1] else {
            panic!("expected an options template set");
        };
        assert_eq!(options_templates.len(), 2);
        assert!(options_templates[0].scope_fields.is_empty());
        assert_eq!(data_set(&packet.sets[2]).records, [[Value::Unsigned32(42)]]);
    }

    #[test]
    fn reserved_template_ids_end_the_template_set() {
        let templates = set(
            TEMPLATE_SET_ID,
            &[
                template(255, &[field(OCTET_DELTA_COUNT, 4)]),
                template(256, &[field(OCTET_DELTA_COUNT, 4)]),
            ]
            .concat(),
        );
        let packet = Parser::default()
            .parse(&message(DOMAIN, &[templates, octet_count_data(1)]))
            .unwrap();
        assert_eq!(packet.sets, [Set::Templates(Vec::new()), Set::Unknown(256)]);
    }

    #[test]
    fn padding_after_the_records_is_skipped() {
        let data = set(
            256,
            &[&1u32.to_be_bytes()[..], &2u32.to_be_bytes(), &[0; 3]].concat(),
        );
        let packet = Parser::default()
            .parse(&message(
                DOMAIN,
                &[octet_count_template(), data, octet_count_data(3)],
            ))
            .unwrap();
        assert_eq!(
            data_set(&packet.sets[1]).records,
            [[Value::Unsigned32(1)], [Value::Unsigned32(2)]]
        );
        assert_eq!(data_set(&packet.sets[2]).records, [[Value::Unsigned32(3)]]);
    }

    #[test]
    fn templates_are_kept_per_domain_until_they_expire() {
        let mut parser = Parser::default();
        parser
            .parse(&message(DOMAIN, &[octet_count_template()]))
            .unwrap();
        let other_domain = parser.parse(&message(8, &[octet_count_data(1)])).unwrap();
        assert_eq!(other_domain.sets, [Set::Unknown(256)]);
        let same_domain = parser
            .parse(&message(DOMAIN, &[octet_count_data(1)]))
            .unwrap();
        assert!(matches!(same_domain.sets[0], Set::Data(_)));

        let mut expiring = Parser::new(Registry::iana(), Duration::ZERO);
        let packet = expiring
            .parse(&message(
                DOMAIN,
                &[octet_count_template(), octet_count_data(1)],
            ))
            .unwrap();
        assert_eq!(packet.sets[1], Set::Unknown(256));
    }

    #[test]
    fn basic_lists_hold_values_of_one_element() {
        let template = set(
            TEMPLATE_SET_ID,
            &template(256, &[field(BASIC_LIST, VARIABLE_LENGTH)]),
        );
        let list = [
            vec![3],
            field(INTERFACE_NAME, VARIABLE_LENGTH),
            variable(b"abc"),
            variable(b""),
            variable(b"def"),
        ]
        .concat();
        let data = set(256, &variable(&list));

        let packet = Parser::default()
            .parse(&message(DOMAIN, &[template, data]))
            .unwrap();

        let name = |name: &str| Value::String(name.to_owned());
        assert_eq!(
            *only_value(&packet),
            Value::BasicList(Box::new(BasicList {
                semantic: ListSemantic::AllOf,
                field: FieldSpecifier {
                    information_element_id: INTERFACE_NAME,
                    field_length: VARIABLE_LENGTH,
                    enterprise_number: None,
                },
                values: vec![name("abc"), name(""), name("def")],
            }))
        );
    }

    #[test]
    fn a_basic_list_of_zero_length_elements_ends() {
        let template = set(
            TEMPLATE_SET_ID,
            &template(256, &[field(BASIC_LIST, VARIABLE_LENGTH)]),
        );
        let list = [vec![255], field(OCTET_DELTA_COUNT, 0), vec![1, 2]].concat();
        let data = set(256, &variable(&list));

        let packet = Parser::default()
            .parse(&message(DOMAIN, &[template, data]))
            .unwrap();

        let Value::BasicList(list) = only_value(&packet) else {
            panic!("expected a basic list");
        };
        assert!(list.values.is_empty());
    }

    #[test]
    fn sub_template_lists_hold_records_of_one_template() {
        let templates = set(
            TEMPLATE_SET_ID,
            &[
                template(256, &[field(OCTET_DELTA_COUNT, 4)]),
                template(257, &[field(SUB_TEMPLATE_LIST, VARIABLE_LENGTH)]),
            ]
            .concat(),
        );
        let known = [
            &[255][..],
            &256u16.to_be_bytes(),
            &1u32.to_be_bytes(),
            &2u32.to_be_bytes(),
        ]
        .concat();
        let unknown = [&[255][..], &300u16.to_be_bytes(), &[9, 9]].concat();
        let data = set(257, &[variable(&known), variable(&unknown)].concat());

        let packet = Parser::default()
            .parse(&message(DOMAIN, &[templates, data]))
            .unwrap();

        let Set::Templates(templates) = &packet.sets[0] else {
            panic!("expected a template set");
        };
        let records = &data_set(&packet.sets[1]).records;
        assert_eq!(
            records[0][0],
            Value::SubTemplateList(Box::new(SubTemplateList {
                semantic: ListSemantic::Undefined,
                records: ListRecords::Decoded {
                    template: TemplateRef::Data(Arc::clone(&templates[0])),
                    records: vec![vec![Value::Unsigned32(1)], vec![Value::Unsigned32(2)]],
                },
            }))
        );
        assert_eq!(
            records[1][0],
            Value::SubTemplateList(Box::new(SubTemplateList {
                semantic: ListSemantic::Undefined,
                records: ListRecords::Undecoded {
                    template_id: 300,
                    data: vec![9, 9],
                },
            }))
        );
    }

    #[test]
    fn sub_template_multi_lists_hold_groups_of_records() {
        let templates = set(
            TEMPLATE_SET_ID,
            &[
                template(256, &[field(OCTET_DELTA_COUNT, 4)]),
                template(257, &[field(SUB_TEMPLATE_MULTI_LIST, VARIABLE_LENGTH)]),
            ]
            .concat(),
        );
        let group = |template_id: u16, records: &[u8]| {
            let length = u16::try_from(LIST_GROUP_HEADER_SIZE + records.len()).unwrap();
            [
                &template_id.to_be_bytes()[..],
                &length.to_be_bytes(),
                records,
            ]
            .concat()
        };
        let list = [
            vec![1],
            group(256, &1u32.to_be_bytes()),
            group(300, &[9, 9]),
            group(256, &[]),
        ]
        .concat();
        let data = set(257, &variable(&list));

        let packet = Parser::default()
            .parse(&message(DOMAIN, &[templates, data]))
            .unwrap();

        let Set::Templates(templates) = &packet.sets[0] else {
            panic!("expected a template set");
        };
        let octet_counts = |records| ListRecords::Decoded {
            template: TemplateRef::Data(Arc::clone(&templates[0])),
            records,
        };
        assert_eq!(
            *only_value(&packet),
            Value::SubTemplateMultiList(Box::new(SubTemplateMultiList {
                semantic: ListSemantic::ExactlyOneOf,
                groups: vec![
                    octet_counts(vec![vec![Value::Unsigned32(1)]]),
                    ListRecords::Undecoded {
                        template_id: 300,
                        data: vec![9, 9],
                    },
                    octet_counts(Vec::new()),
                ],
            }))
        );
    }

    #[test]
    fn lists_nested_too_deep_keep_their_bytes() {
        let template = set(
            TEMPLATE_SET_ID,
            &template(256, &[field(BASIC_LIST, VARIABLE_LENGTH)]),
        );
        let mut list = [
            vec![255],
            field(OCTET_DELTA_COUNT, 4),
            5u32.to_be_bytes().to_vec(),
        ]
        .concat();
        for _ in 0..MAX_LIST_DEPTH + 2 {
            list = [
                vec![255],
                field(BASIC_LIST, VARIABLE_LENGTH),
                variable(&list),
            ]
            .concat();
        }
        let data = set(256, &variable(&list));

        let packet = Parser::default()
            .parse(&message(DOMAIN, &[template, data]))
            .unwrap();

        let mut value = only_value(&packet);
        let mut depth = 0;
        while let Value::BasicList(list) = value {
            depth += 1;
            value = &list.values[0];
        }
        assert_eq!(depth, MAX_LIST_DEPTH);
        assert!(matches!(value, Value::OctetArray(_)));
    }

    #[test]
    fn list_semantics_follow_the_iana_registry() {
        let semantics: Vec<_> = [0, 1, 2, 3, 4, 5, 255].map(ListSemantic::from).into();
        assert_eq!(
            semantics,
            [
                ListSemantic::NoneOf,
                ListSemantic::ExactlyOneOf,
                ListSemantic::OneOrMoreOf,
                ListSemantic::AllOf,
                ListSemantic::Ordered,
                ListSemantic::Unassigned(5),
                ListSemantic::Undefined,
            ]
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn round_trips_through_serde() {
        let template = set(
            TEMPLATE_SET_ID,
            &template(256, &[field(BASIC_LIST, VARIABLE_LENGTH)]),
        );
        let list = [
            vec![4],
            field(OCTET_DELTA_COUNT, 4),
            7u32.to_be_bytes().to_vec(),
        ]
        .concat();
        let packet = Parser::default()
            .parse(&message(DOMAIN, &[template, set(256, &variable(&list))]))
            .unwrap();
        let json = serde_json::to_value(&packet).unwrap();
        assert_eq!(json["observation_domain_id"], DOMAIN);
        assert_eq!(serde_json::from_value::<Packet>(json).unwrap(), packet);
    }
}
