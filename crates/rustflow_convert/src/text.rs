//! A record as a JSON object, or a map of any format serde writes: its
//! Information Elements identified by name (RFC 7373 section 3), each value
//! in its textual representation (section 4), as Appendix A of RFC 7373
//! illustrates.

use std::borrow::Cow;

use rustflow_protocol::information_element::{ElementId, Registry};
use rustflow_protocol::value::{Text, Value};
use serde::ser::{Serialize, SerializeMap, Serializer};

use crate::Record;

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
/// - An options record's scope values come first, as on the wire. NetFlow v9
///   scope types are not Information Elements, with no name to be keyed by, and
///   are left out.
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
        match self.registry.get(element) {
            Some(known) => Cow::Borrowed(&known.name),
            None => Cow::Owned(element.to_string()),
        }
    }
}

impl Serialize for TextRecord<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let fields: Vec<(ElementId, &Value)> = self
            .record
            .scope_elements()
            .chain(self.record.iter())
            .filter(|(_, value)| has_text(value))
            .collect();
        let is_first = |index: usize| {
            let element = fields[index].0;
            fields[..index].iter().all(|&(seen, _)| seen != element)
        };

        let keys = (0..fields.len()).filter(|&index| is_first(index)).count();
        let mut map = serializer.serialize_map(Some(keys))?;
        for (index, &(element, value)) in fields.iter().enumerate() {
            if !is_first(index) {
                continue;
            }
            let key = self.key(element);
            let mut repeats = fields[index + 1..]
                .iter()
                .filter(|&&(other, _)| other == element)
                .peekable();
            if repeats.peek().is_none() {
                map.serialize_entry(&key, &Text(value))?;
            } else {
                let values: Vec<Text> = std::iter::once(value)
                    .chain(repeats.map(|&(_, value)| value))
                    .map(Text)
                    .collect();
                map.serialize_entry(&key, &values)?;
            }
        }
        map.end()
    }
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

    use rustflow_protocol::Protocol;
    use rustflow_protocol::information_element::iana;
    use rustflow_protocol::netflow_v9::ScopeType;
    use serde_json::json;

    use super::*;
    use crate::Scope;

    fn record(scope: Vec<(Scope, Value)>, fields: Vec<(ElementId, Value)>) -> Record {
        let (elements, values): (Vec<_>, Vec<_>) = fields.into_iter().unzip();
        Record {
            protocol: Protocol::Ipfix,
            sequence_number: 0,
            scope,
            elements: Arc::from(elements),
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
                (Scope::Type(ScopeType::Interface), Value::Unsigned32(2)),
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
