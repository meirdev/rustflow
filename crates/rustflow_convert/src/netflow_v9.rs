//! NetFlow v9 data records as IPFIX records. Their field types number the
//! same elements as IANA's IPFIX registry, which keeps NetFlow v9's
//! numbers, so their fields are copied, with uptimes made absolute.

use rustflow_protocol::netflow_v9::{self, FlowSet, Packet};

use crate::domain::Domains;
use crate::templated::{Context, Plans, TimeBase, Uptime, convert_data, convert_options};
use crate::{Protocol, Received, Record};

/// Converts one exporter's NetFlow v9 packets, keeping what its options
/// records said of each source ID, as a parser keeps its templates. Use one
/// converter per exporter address.
#[derive(Default)]
pub struct Converter {
    domains: Domains,
    plans: Plans<netflow_v9::Template>,
}

impl Converter {
    /// Converts a packet's records, adding them to `records` in packet
    /// order, after learning from its options records. A data record gets
    /// the sampling that options records gave for its source ID, if any; an
    /// options record comes with its scope.
    pub fn convert(
        &mut self,
        packet: Packet,
        received: &Received,
        records: &mut impl Extend<Record>,
    ) {
        let header = &packet.header;
        for flow_set in &packet.flow_sets {
            if let FlowSet::OptionsData(data) = flow_set {
                for record in data.records() {
                    self.domains.learn(header.source_id, record);
                }
            }
        }

        let context = Context {
            protocol: Protocol::NetflowV9,
            sequence_number: header.sequence_number,
            domain_id: header.source_id,
            received,
            time: TimeBase {
                export_time_ms: u64::from(header.unix_secs) * 1_000,
                uptime: Uptime::AtExport(header.sys_uptime),
            },
        };
        let domain = self.domains.get(header.source_id);
        for flow_set in packet.flow_sets {
            match flow_set {
                FlowSet::Data(data) => {
                    convert_data(&context, domain, &mut self.plans, data, records);
                }
                FlowSet::OptionsData(data) => convert_options(&context, data, records),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use rustflow_protocol::DataSet;
    use rustflow_protocol::information_element::{ElementId, iana};
    use rustflow_protocol::netflow_v9::{
        self, Field, Header, OptionsTemplate, ScopeType, Template,
    };
    use rustflow_protocol::value::Value;

    use super::*;
    use crate::Scope;
    use crate::fixtures::udp_payloads;

    const SOURCE_ID: u32 = 7;
    const SYSTEM_SCOPE: u16 = 1;

    fn field(element: ElementId) -> Field {
        Field {
            field_type: element.id,
            length: 4,
        }
    }

    fn data(fields: &[ElementId], records: Vec<Vec<Value>>) -> FlowSet {
        FlowSet::Data(DataSet {
            template: Arc::new(Template {
                template_id: 256,
                fields: fields.iter().copied().map(field).collect(),
            }),
            records,
        })
    }

    /// Options of the System scope.
    fn options(fields: &[(ElementId, Value)]) -> FlowSet {
        let (elements, values): (Vec<_>, Vec<_>) = fields.iter().cloned().unzip();
        FlowSet::OptionsData(DataSet {
            template: Arc::new(OptionsTemplate {
                template_id: 257,
                scope_fields: vec![Field {
                    field_type: SYSTEM_SCOPE,
                    length: 4,
                }],
                option_fields: elements.into_iter().map(field).collect(),
            }),
            records: vec![[vec![Value::Unsigned32(0)], values].concat()],
        })
    }

    /// Exported at 1_700_000_000 s, an hour after the exporter booted.
    fn packet(source_id: u32, flow_sets: Vec<FlowSet>) -> Packet {
        Packet {
            header: Header {
                version: netflow_v9::VERSION,
                count: 0,
                sys_uptime: 3_600_000,
                unix_secs: 1_700_000_000,
                sequence_number: 42,
                source_id,
            },
            flow_sets,
        }
    }

    fn received() -> Received {
        Received {
            exporter: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)),
            time: None,
        }
    }

    fn converted(converter: &mut Converter, packet: Packet) -> Vec<Record> {
        let mut records = Vec::new();
        converter.convert(packet, &received(), &mut records);
        records
    }

    /// A record of each octet count.
    fn octets_and_uptimes(octets: &[u32]) -> FlowSet {
        data(
            &[
                iana::OCTET_DELTA_COUNT,
                iana::FLOW_START_SYS_UP_TIME,
                iana::FLOW_END_SYS_UP_TIME,
            ],
            octets
                .iter()
                .map(|&octets| {
                    vec![
                        Value::Unsigned32(octets),
                        Value::Unsigned32(3_540_000),
                        Value::Unsigned32(3_599_000),
                    ]
                })
                .collect(),
        )
    }

    #[test]
    fn fields_are_copied_and_uptimes_made_absolute() {
        let records = converted(
            &mut Converter::default(),
            packet(SOURCE_ID, vec![octets_and_uptimes(&[1500, 1600])]),
        );
        let record = &records[0];

        assert_eq!(record.protocol, Protocol::NetflowV9);
        assert_eq!(record.sequence_number, 42);
        assert_eq!(
            record.first(iana::OCTET_DELTA_COUNT),
            Some(&Value::Unsigned32(1500))
        );
        assert_eq!(
            record.first(iana::FLOW_START_MILLISECONDS),
            Some(&Value::DateTimeMilliseconds(1_699_999_940_000))
        );
        assert_eq!(
            record.first(iana::FLOW_END_MILLISECONDS),
            Some(&Value::DateTimeMilliseconds(1_699_999_999_000))
        );
        assert_eq!(record.first(iana::FLOW_START_SYS_UP_TIME), None);
        assert_eq!(
            record.first(iana::ORIGINAL_OBSERVATION_DOMAIN_ID),
            Some(&Value::Unsigned32(SOURCE_ID))
        );
        assert!(Arc::ptr_eq(&records[0].elements, &records[1].elements));
    }

    #[test]
    fn options_records_give_the_sampling_and_are_records_with_a_scope() {
        let sampling = options(&[
            (iana::SAMPLING_INTERVAL, Value::Unsigned32(100)),
            (iana::SAMPLING_ALGORITHM, Value::Unsigned8(2)),
        ]);
        let mut converter = Converter::default();
        let records = converted(
            &mut converter,
            packet(SOURCE_ID, vec![octets_and_uptimes(&[1]), sampling]),
        );

        assert_eq!(records.len(), 2);
        assert_eq!(
            records[1].scope,
            [(Scope::Type(ScopeType::System), Value::Unsigned32(0))]
        );
        assert_eq!(
            records[1].first(iana::SAMPLING_INTERVAL),
            Some(&Value::Unsigned32(100))
        );
        assert_eq!(
            records[0].first(iana::SELECTOR_ALGORITHM),
            Some(&Value::Unsigned16(3))
        );
        assert_eq!(
            records[0].first(iana::SAMPLING_POPULATION),
            Some(&Value::Unsigned32(100))
        );

        let later = converted(
            &mut converter,
            packet(SOURCE_ID, vec![octets_and_uptimes(&[2])]),
        );
        assert_eq!(
            later[0].first(iana::SAMPLING_POPULATION),
            Some(&Value::Unsigned32(100))
        );
        let other_source = converted(&mut converter, packet(8, vec![octets_and_uptimes(&[3])]));
        assert_eq!(other_source[0].first(iana::SAMPLING_POPULATION), None);
        assert_eq!(other_source[0].first(iana::SAMPLING_PACKET_INTERVAL), None);
    }

    #[test]
    fn real_packets_get_their_options_sampling() {
        let mut parser = netflow_v9::Parser::default();
        let mut converter = Converter::default();
        let mut records = Vec::new();
        for datagram in udp_payloads("netflow_v9_sanity.pcap") {
            let packet = parser.parse(&datagram).unwrap();
            converter.convert(packet, &received(), &mut records);
        }

        assert!(!records.is_empty());
        for record in records.iter().filter(|record| !record.is_options()) {
            assert_eq!(record.values.len(), record.elements.len());
            // The fixture's options record states a sampling interval of 100.
            assert_eq!(
                record.first(iana::SAMPLING_PACKET_SPACE),
                Some(&Value::Unsigned32(99))
            );
            assert!(matches!(
                record.first(iana::FLOW_START_MILLISECONDS),
                Some(Value::DateTimeMilliseconds(_))
            ));
            assert_eq!(record.first(iana::FLOW_START_SYS_UP_TIME), None);
        }
        let flow = records.iter().find(|record| !record.is_options()).unwrap();
        assert_eq!(
            flow.first(iana::SOURCE_IPV4_ADDRESS),
            Some(&Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1)))
        );
        let options = records.iter().find(|record| record.is_options()).unwrap();
        assert_eq!(options.scope.len(), 1);
        assert_eq!(
            options.first(iana::SAMPLING_INTERVAL),
            Some(&Value::Unsigned32(100))
        );
    }
}
