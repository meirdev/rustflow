//! Records and packets as JSON objects, or maps of any format serde writes:
//! Information Elements identified by name (RFC 7373 section 3), each value
//! in its textual representation (section 4), as Appendix A of RFC 7373
//! illustrates.

use std::borrow::Cow;

use serde::ser::{Serialize, SerializeMap, SerializeStruct, Serializer};

use crate::convert::templated::scope_element;
use crate::convert::{Record, Scope};
use crate::protocol::information_element::{ElementId, Registry};
use crate::protocol::netflow_v9::ScopeType;
use crate::protocol::value::{Text, Value};
use crate::protocol::{Packet, ipfix, netflow_v9};

impl Record {
    /// The record as a map from element names to values, for serializing:
    /// `serde_json::to_string(&record.text(&registry))` writes it as a JSON
    /// object. `registry` names the elements.
    pub fn text<'a>(&'a self, registry: &'a Registry) -> TextRecord<'a> {
        TextRecord {
            record: self,
            registry,
        }
    }
}

/// A record serialized as a map from element names to values in their
/// RFC 7373 textual representation, which [`Record::text`] makes.
///
/// - An options record's scope values come first, as on the wire. A NetFlow v9
///   scope of an unassigned type is no Information Element, with no name to be
///   keyed by, and is left out.
/// - An element the registry does not name is keyed by its number alone, the
///   partial IESpec `(id)` or `(pen/id)` of RFC 7013 section 10.1.
/// - Lists, which must not be used in textual representations (RFC 7373 section
///   4.11), and `Null` values are left out.
/// - An element the record holds more than once is keyed once, by an array of
///   its values in record order, as names within a JSON object should be unique
///   (RFC 8259 section 4).
#[derive(Debug, Clone, Copy)]
pub struct TextRecord<'a> {
    record: &'a Record,
    registry: &'a Registry,
}

impl TextRecord<'_> {
    fn key(&self, element: ElementId) -> Cow<'_, str> {
        element_key(self.registry, element)
    }
}

impl Serialize for TextRecord<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let fields = self.record.scope_elements().chain(self.record.iter());
        fields_map(
            serializer,
            fields.map(|(element, value)| (self.key(element), value)),
        )
    }
}

/// Serializes fields as a map: each key once, in order of first appearance,
/// with every value it has, as [`TextRecord`] describes.
fn fields_map<'a, S: Serializer>(
    serializer: S,
    fields: impl Iterator<Item = (Cow<'a, str>, &'a Value)>,
) -> Result<S::Ok, S::Error> {
    let mut entries: Vec<(Cow<str>, Vec<Text>)> = Vec::new();
    for (key, value) in fields.filter(|(_, value)| has_text(value)) {
        match entries.iter_mut().find(|(known, _)| *known == key) {
            Some((_, values)) => values.push(Text(value)),
            None => entries.push((key, vec![Text(value)])),
        }
    }

    let mut map = serializer.serialize_map(Some(entries.len()))?;
    for (key, values) in &entries {
        match values.as_slice() {
            [value] => map.serialize_entry(key, value)?,
            values => map.serialize_entry(key, values)?,
        }
    }
    map.end()
}

impl Packet {
    /// The packet for serializing as text: as the packet is, but for its
    /// NetFlow v9 and IPFIX data records, which go as maps from element
    /// names to values as [`Record::text`] writes them, and the bytes of
    /// sets that lacked a template, which go as hexadecimal.
    pub fn text<'a>(&'a self, registry: &'a Registry) -> TextPacket<'a> {
        TextPacket {
            packet: self,
            registry,
        }
    }
}

/// A packet serialized with its records as text, which [`Packet::text`]
/// makes. A templated packet's sets go as a sequence of maps, each with
/// its `set_id` and then its `templates`, `options_templates`, `records`
/// or undecoded `body`.
#[derive(Debug, Clone, Copy)]
pub struct TextPacket<'a> {
    packet: &'a Packet,
    registry: &'a Registry,
}

impl Serialize for TextPacket<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.packet {
            Packet::NetflowV5(packet) => packet.serialize(serializer),
            Packet::SflowV5(packet) => packet.serialize(serializer),
            Packet::NetflowV9(packet) => {
                let netflow_v9::Header {
                    version,
                    count,
                    sys_uptime,
                    unix_secs,
                    sequence_number,
                    source_id,
                } = packet.header;
                let mut message = serializer.serialize_struct("Packet", 7)?;
                message.serialize_field("version", &version)?;
                message.serialize_field("count", &count)?;
                message.serialize_field("sys_uptime", &sys_uptime)?;
                message.serialize_field("unix_secs", &unix_secs)?;
                message.serialize_field("sequence_number", &sequence_number)?;
                message.serialize_field("source_id", &source_id)?;
                let flow_sets: Vec<_> = packet
                    .flow_sets
                    .iter()
                    .map(|set| TextFlowSet {
                        set,
                        registry: self.registry,
                    })
                    .collect();
                message.serialize_field("flow_sets", &flow_sets)?;
                message.end()
            }
            Packet::Ipfix(packet) => {
                let ipfix::Header {
                    version,
                    length,
                    export_time,
                    sequence_number,
                    observation_domain_id,
                } = packet.header;
                let mut message = serializer.serialize_struct("Packet", 6)?;
                message.serialize_field("version", &version)?;
                message.serialize_field("length", &length)?;
                message.serialize_field("export_time", &export_time)?;
                message.serialize_field("sequence_number", &sequence_number)?;
                message.serialize_field("observation_domain_id", &observation_domain_id)?;
                let sets: Vec<_> = packet
                    .sets
                    .iter()
                    .map(|set| TextSet {
                        set,
                        registry: self.registry,
                    })
                    .collect();
                message.serialize_field("sets", &sets)?;
                message.end()
            }
        }
    }
}

struct TextSet<'a> {
    set: &'a ipfix::Set,
    registry: &'a Registry,
}

impl Serialize for TextSet<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        match self.set {
            ipfix::Set::Templates(templates) => {
                map.serialize_entry("set_id", &ipfix::TEMPLATE_SET_ID)?;
                map.serialize_entry("templates", templates)?;
            }
            ipfix::Set::OptionsTemplates(templates) => {
                map.serialize_entry("set_id", &ipfix::OPTIONS_TEMPLATE_SET_ID)?;
                map.serialize_entry("options_templates", templates)?;
            }
            ipfix::Set::Data(data) => {
                map.serialize_entry("set_id", &data.template.template_id)?;
                let keys: Vec<_> = data
                    .template
                    .fields
                    .iter()
                    .map(|field| element_key(self.registry, field.element_id()))
                    .collect();
                map.serialize_entry(
                    "records",
                    &TextRecords {
                        keys,
                        records: &data.records,
                    },
                )?;
            }
            ipfix::Set::OptionsData(data) => {
                map.serialize_entry("set_id", &data.template.template_id)?;
                let keys: Vec<_> = data
                    .template
                    .scope_fields
                    .iter()
                    .chain(&data.template.option_fields)
                    .map(|field| element_key(self.registry, field.element_id()))
                    .collect();
                map.serialize_entry(
                    "records",
                    &TextRecords {
                        keys,
                        records: &data.records,
                    },
                )?;
            }
            ipfix::Set::Undecoded { set_id, body } => {
                map.serialize_entry("set_id", set_id)?;
                map.serialize_entry("body", &hex(body))?;
            }
            ipfix::Set::Unknown(set_id) => map.serialize_entry("set_id", set_id)?,
        }
        map.end()
    }
}

struct TextFlowSet<'a> {
    set: &'a netflow_v9::FlowSet,
    registry: &'a Registry,
}

impl Serialize for TextFlowSet<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        match self.set {
            netflow_v9::FlowSet::Templates(templates) => {
                map.serialize_entry("flow_set_id", &netflow_v9::TEMPLATE_FLOW_SET_ID)?;
                map.serialize_entry("templates", templates)?;
            }
            netflow_v9::FlowSet::OptionsTemplates(templates) => {
                map.serialize_entry("flow_set_id", &netflow_v9::OPTIONS_TEMPLATE_FLOW_SET_ID)?;
                map.serialize_entry("options_templates", templates)?;
            }
            netflow_v9::FlowSet::Data(data) => {
                map.serialize_entry("flow_set_id", &data.template.template_id)?;
                let keys: Vec<_> = data
                    .template
                    .fields
                    .iter()
                    .map(|field| element_key(self.registry, ElementId::iana(field.field_type)))
                    .collect();
                map.serialize_entry(
                    "records",
                    &TextRecords {
                        keys,
                        records: &data.records,
                    },
                )?;
            }
            netflow_v9::FlowSet::OptionsData(data) => {
                map.serialize_entry("flow_set_id", &data.template.template_id)?;
                // A scope field is keyed by the element its scope type
                // stands for, or by the type itself when it has none.
                let scopes = data.template.scope_fields.iter().map(|field| {
                    match scope_element(ScopeType::from(field.field_type)) {
                        Scope::Element(element) => element_key(self.registry, element),
                        Scope::Type(scope_type) => Cow::Owned(format!("{scope_type:?}")),
                    }
                });
                let options = data
                    .template
                    .option_fields
                    .iter()
                    .map(|field| element_key(self.registry, ElementId::iana(field.field_type)));
                let keys: Vec<_> = scopes.chain(options).collect();
                map.serialize_entry(
                    "records",
                    &TextRecords {
                        keys,
                        records: &data.records,
                    },
                )?;
            }
            netflow_v9::FlowSet::Undecoded { flow_set_id, body } => {
                map.serialize_entry("flow_set_id", flow_set_id)?;
                map.serialize_entry("body", &hex(body))?;
            }
            netflow_v9::FlowSet::Unknown(flow_set_id) => {
                map.serialize_entry("flow_set_id", flow_set_id)?;
            }
        }
        map.end()
    }
}

/// The records of a data set, each a map of its values by `keys`.
struct TextRecords<'a> {
    keys: Vec<Cow<'a, str>>,
    records: &'a [Vec<Value>],
}

impl Serialize for TextRecords<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Keys repeat in few templates; the rest need no gathering by key.
        let unique = self
            .keys
            .iter()
            .enumerate()
            .all(|(i, key)| !self.keys[..i].contains(key));
        serializer.collect_seq(self.records.iter().map(|values| TextFields {
            keys: &self.keys,
            values,
            unique,
        }))
    }
}

struct TextFields<'a> {
    keys: &'a [Cow<'a, str>],
    values: &'a [Value],
    unique: bool,
}

impl Serialize for TextFields<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let fields = self.keys.iter().zip(self.values);
        if self.unique {
            let mut map = serializer.serialize_map(None)?;
            for (key, value) in fields.filter(|(_, value)| has_text(value)) {
                map.serialize_entry(key, &Text(value))?;
            }
            return map.end();
        }
        fields_map(
            serializer,
            fields.map(|(key, value)| (Cow::Borrowed(key.as_ref()), value)),
        )
    }
}

fn element_key(registry: &Registry, element: ElementId) -> Cow<'_, str> {
    match registry.get(element) {
        Some(known) => Cow::Borrowed(&known.name),
        None => Cow::Owned(element.to_string()),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        text.push(DIGITS[usize::from(byte >> 4)]);
        text.push(DIGITS[usize::from(byte & 0xf)]);
    }
    String::from_utf8(text).expect("hex digits are ASCII")
}

fn has_text(value: &Value) -> bool {
    !matches!(
        value,
        Value::BasicList(_)
            | Value::SubTemplateList(_)
            | Value::SubTemplateMultiList(_)
            | Value::Null
    )
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::convert::Scope;
    use crate::protocol::Protocol;
    use crate::protocol::information_element::iana;
    use crate::protocol::netflow_v9::ScopeType;

    fn record(scope: Vec<(Scope, Value)>, fields: Vec<(ElementId, Value)>) -> Record {
        let (elements, values): (Vec<_>, Vec<_>) = fields.into_iter().unzip();
        Record {
            protocol: Protocol::Ipfix,
            sequence_number: 0,
            scope,
            elements: Arc::new(elements.into()),
            values,
        }
    }

    fn json(record: &Record) -> String {
        serde_json::to_string(&record.text(&Registry::iana())).unwrap()
    }

    /// RFC 7373 Appendix A, Figures 1 and 2, but for `protocolIdentifier`:
    /// the name of a codepoint is a choice section 4.2 allows, not made
    /// here.
    #[test]
    fn a_packet_goes_as_text_with_its_records_named() {
        use std::sync::Arc;

        use crate::protocol::ipfix::{FieldSpecifier, Set, Template};
        use crate::protocol::netflow_v9::{self, Field, FlowSet, OptionsTemplate, ScopeType};
        use crate::protocol::{DataSet, Packet};

        let template = Arc::new(Template {
            template_id: 256,
            fields: vec![
                FieldSpecifier {
                    information_element_id: iana::OCTET_DELTA_COUNT.id,
                    field_length: 4,
                    enterprise_number: None,
                },
                FieldSpecifier {
                    information_element_id: 1,
                    field_length: 2,
                    enterprise_number: Some(9),
                },
            ],
        });
        let message = Packet::Ipfix(crate::protocol::ipfix::Packet {
            header: crate::protocol::ipfix::Header {
                version: 10,
                length: 0,
                export_time: 1_700_000_000,
                sequence_number: 7,
                observation_domain_id: 1,
            },
            sets: vec![
                Set::Templates(vec![Arc::clone(&template)]),
                Set::Data(DataSet {
                    template,
                    records: vec![vec![Value::Unsigned32(5), Value::Unsigned16(6)]],
                }),
                Set::Undecoded {
                    set_id: 300,
                    body: vec![0xab, 0x01],
                },
            ],
        });
        let text = serde_json::to_value(message.text(&Registry::iana())).unwrap();
        assert_eq!(text["sequence_number"], 7);
        assert_eq!(text["sets"][0]["set_id"], 2);
        assert_eq!(text["sets"][0]["templates"][0]["template_id"], 256);
        assert_eq!(
            text["sets"][1],
            json!({"set_id": 256, "records": [{"octetDeltaCount": 5, "(9/1)": 6}]})
        );
        assert_eq!(text["sets"][2], json!({"set_id": 300, "body": "ab01"}));

        let options = Arc::new(OptionsTemplate {
            template_id: 257,
            scope_fields: vec![Field {
                field_type: ScopeType::System.into(),
                length: 4,
            }],
            option_fields: vec![Field {
                field_type: iana::SAMPLING_INTERVAL.id,
                length: 4,
            }],
        });
        let packet = Packet::NetflowV9(netflow_v9::Packet {
            header: netflow_v9::Header {
                version: 9,
                count: 1,
                sys_uptime: 1,
                unix_secs: 2,
                sequence_number: 3,
                source_id: 4,
            },
            flow_sets: vec![FlowSet::OptionsData(DataSet {
                template: options,
                records: vec![vec![Value::Unsigned32(1), Value::Unsigned32(100)]],
            })],
        });
        let text = serde_json::to_value(packet.text(&Registry::iana())).unwrap();
        assert_eq!(text["source_id"], 4);
        assert_eq!(
            text["flow_sets"][0],
            json!({"flow_set_id": 257, "records": [{"exportingProcessId": 1, "samplingInterval": 100}]})
        );
    }

    #[test]
    fn the_flow_of_rfc_7373_appendix_a() {
        let host = |last| Ipv6Addr::new(0x2001, 0xdb8, 0xc, 0x1337, 0, 0, 0, last);
        let flow = record(
            Vec::new(),
            vec![
                (
                    iana::FLOW_START_MILLISECONDS,
                    Value::DateTimeMilliseconds(1_352_140_261_135),
                ),
                (
                    iana::FLOW_END_MILLISECONDS,
                    Value::DateTimeMilliseconds(1_352_140_262_880),
                ),
                (iana::OCTET_DELTA_COUNT, Value::Unsigned64(195_383)),
                (iana::PACKET_DELTA_COUNT, Value::Unsigned64(88)),
                (iana::SOURCE_IPV6_ADDRESS, Value::Ipv6Address(host(2))),
                (iana::DESTINATION_IPV6_ADDRESS, Value::Ipv6Address(host(3))),
                (iana::SOURCE_TRANSPORT_PORT, Value::Unsigned16(80)),
                (iana::DESTINATION_TRANSPORT_PORT, Value::Unsigned16(32991)),
                (iana::PROTOCOL_IDENTIFIER, Value::Unsigned8(6)),
                (iana::TCP_CONTROL_BITS, Value::Unsigned16(19)),
                (iana::FLOW_END_REASON, Value::Unsigned8(3)),
            ],
        );

        let expected = json!({
            "flowStartMilliseconds": "2012-11-05T18:31:01.135",
            "flowEndMilliseconds": "2012-11-05T18:31:02.880",
            "octetDeltaCount": 195383,
            "packetDeltaCount": 88,
            "sourceIPv6Address": "2001:db8:c:1337::2",
            "destinationIPv6Address": "2001:db8:c:1337::3",
            "sourceTransportPort": 80,
            "destinationTransportPort": 32991,
            "protocolIdentifier": 6,
            "tcpControlBits": 19,
            "flowEndReason": 3
        });
        let written = json(&flow);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&written).unwrap(),
            expected
        );
        assert!(written.starts_with(r#"{"flowStartMilliseconds":"2012-11-05T18:31:01.135","#));
    }

    #[test]
    fn an_element_held_twice_is_keyed_once_by_an_array() {
        let flow = record(
            Vec::new(),
            vec![
                (
                    iana::MPLS_TOP_LABEL_STACK_SECTION,
                    Value::OctetArray(vec![0, 0x64, 1]),
                ),
                (iana::PACKET_DELTA_COUNT, Value::Unsigned64(1)),
                (
                    iana::MPLS_TOP_LABEL_STACK_SECTION,
                    Value::OctetArray(vec![0, 0xc8, 1]),
                ),
            ],
        );
        assert_eq!(
            json(&flow),
            r#"{"mplsTopLabelStackSection":["006401","00c801"],"packetDeltaCount":1}"#
        );
    }

    #[test]
    fn an_unnamed_element_is_keyed_by_its_number() {
        let flow = record(
            Vec::new(),
            vec![(ElementId::from((35566, 403)), Value::String("sip:a".into()))],
        );
        assert_eq!(json(&flow), r#"{"(35566/403)":"sip:a"}"#);
    }

    #[test]
    fn scope_elements_come_first_and_scope_types_are_left_out() {
        let options = record(
            vec![
                (
                    Scope::Element(iana::OBSERVATION_DOMAIN_ID),
                    Value::Unsigned32(7),
                ),
                (Scope::Type(ScopeType::Unassigned(9)), Value::Unsigned32(2)),
            ],
            vec![(iana::SAMPLING_INTERVAL, Value::Unsigned32(100))],
        );
        assert_eq!(
            json(&options),
            r#"{"observationDomainId":7,"samplingInterval":100}"#
        );
    }

    #[test]
    fn values_without_a_textual_form_are_left_out() {
        let flow = record(
            Vec::new(),
            vec![
                (iana::FLOW_START_MILLISECONDS, Value::Null),
                (
                    iana::SOURCE_IPV4_ADDRESS,
                    Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1)),
                ),
            ],
        );
        assert_eq!(json(&flow), r#"{"sourceIPv4Address":"192.0.2.1"}"#);
    }
}
