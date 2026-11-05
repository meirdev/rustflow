//! IPFIX data records, copied with their relative times made absolute.

use crate::convert::domains::Domains;
use crate::convert::templated::{Context, convert_data, convert_options};
use crate::convert::time::{TimeBase, Uptime};
use crate::convert::{Protocol, Received, Record};
use crate::protocol::ipfix::{Packet, Set};

/// Converts one exporter's IPFIX messages, keeping what its options records
/// said of each observation domain, as a parser keeps its templates. Use
/// one converter per exporter address.
#[derive(Default)]
pub struct Converter {
    domains: Domains,
}

impl Converter {
    /// Converts a message's records, adding them to `records`: its options
    /// records first, with their scope, then its data records, with the
    /// sampling the options records gave their observation domain, if any.
    ///
    /// Times relative to the export time (`flowStartDeltaMicroseconds`) are
    /// made absolute from it; uptimes (`flowStartSysUpTime`) from the
    /// exporter's `systemInitTimeMilliseconds`, once an options record gave
    /// it, and are kept as they are until then.
    pub fn convert(
        &mut self,
        packet: Packet,
        received: &Received,
        records: &mut impl Extend<Record>,
    ) {
        let header = &packet.header;
        let domain_id = header.observation_domain_id;
        let context = |domains: &Domains| Context {
            protocol: Protocol::Ipfix,
            sequence_number: header.sequence_number,
            domain_id,
            received,
            time: TimeBase {
                export_time_ms: u64::from(header.export_time) * 1_000,
                uptime: Uptime::BootedAt(
                    domains
                        .get(domain_id)
                        .and_then(|domain| domain.system_init_time_ms),
                ),
            },
        };
        let (options, data): (Vec<_>, Vec<_>) = packet
            .sets
            .into_iter()
            .partition(|set| matches!(set, Set::OptionsData(_)));
        for set in options {
            if let Set::OptionsData(set) = set {
                let context = context(&self.domains);
                let domains = &mut self.domains;
                records.extend(
                    convert_options(&context, set)
                        .inspect(|record| domains.learn(domain_id, record)),
                );
            }
        }

        let context = context(&self.domains);
        let domain = self.domains.get(domain_id);
        for set in data {
            if let Set::Data(set) = set {
                convert_data(&context, domain, set, records);
            }
        }
    }

    /// The latest options record of each kind the exporter sent, with its
    /// observation domain.
    pub fn options(&self) -> impl Iterator<Item = (u32, &Record)> {
        self.domains.options()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use etherparse::PacketBuilder;

    use super::*;
    use crate::convert::Scope;
    use crate::protocol::DataSet;
    use crate::protocol::information_element::{ElementId, iana};
    use crate::protocol::ipfix::{self, FieldSpecifier, Header, OptionsTemplate, Template};
    use crate::protocol::value::Value;

    const DOMAIN: u32 = 7;
    const EXPORT_TIME_MS: u64 = 1_700_000_000_000;

    fn field(element: ElementId) -> FieldSpecifier {
        FieldSpecifier {
            information_element_id: element.id,
            field_length: 4,
            enterprise_number: element.enterprise_number,
        }
    }

    fn data(fields: &[(ElementId, Value)]) -> Set {
        let (elements, values): (Vec<_>, Vec<_>) = fields.iter().cloned().unzip();
        Set::Data(DataSet {
            template: Arc::new(Template {
                template_id: 256,
                fields: elements.into_iter().map(field).collect(),
            }),
            records: vec![values],
        })
    }

    /// Options scoped to the observation domain.
    fn options(fields: &[(ElementId, Value)]) -> Set {
        let (elements, values): (Vec<_>, Vec<_>) = fields.iter().cloned().unzip();
        Set::OptionsData(DataSet {
            template: Arc::new(OptionsTemplate {
                template_id: 257,
                scope_fields: vec![field(iana::OBSERVATION_DOMAIN_ID)],
                option_fields: elements.into_iter().map(field).collect(),
            }),
            records: vec![[vec![Value::Unsigned32(DOMAIN)], values].concat()],
        })
    }

    /// The flows of `sets`, options records left out.
    fn converted(converter: &mut Converter, sets: Vec<Set>) -> Vec<Record> {
        all_converted(converter, sets)
            .into_iter()
            .filter(|record| !record.is_options())
            .collect()
    }

    fn all_converted(converter: &mut Converter, sets: Vec<Set>) -> Vec<Record> {
        let packet = Packet {
            header: Header {
                version: ipfix::VERSION,
                length: 0,
                export_time: 1_700_000_000,
                sequence_number: 42,
                observation_domain_id: DOMAIN,
            },
            sets,
        };
        let received = Received {
            exporter: SocketAddr::from(([192, 0, 2, 254], 4739)),
            time: None,
        };
        let mut records = Vec::new();
        converter.convert(packet, &received, &mut records);
        records
    }

    fn frame() -> Vec<u8> {
        let mut frame = Vec::new();
        PacketBuilder::ethernet2([2; 6], [4; 6])
            .ipv4([192, 0, 2, 1], [198, 51, 100, 1], 64)
            .tcp(1234, 80, 0, 1024)
            .syn()
            .write(&mut frame, &[0; 8])
            .unwrap();
        frame
    }

    #[test]
    fn a_packet_section_is_dissected_for_what_the_record_lacks() {
        let records = converted(
            &mut Converter::default(),
            vec![data(&[
                (
                    iana::SOURCE_IPV4_ADDRESS,
                    Value::Ipv4Address(Ipv4Addr::LOCALHOST),
                ),
                (iana::DATA_LINK_FRAME_TYPE, Value::Unsigned16(1)),
                (iana::DATA_LINK_FRAME_SECTION, Value::OctetArray(frame())),
            ])],
        );
        let record = &records[0];
        assert_eq!(
            record.first(iana::SOURCE_IPV4_ADDRESS),
            Some(&Value::Ipv4Address(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(record.all(iana::SOURCE_IPV4_ADDRESS).count(), 1);
        assert_eq!(
            record.first(iana::DESTINATION_IPV4_ADDRESS),
            Some(&Value::Ipv4Address(Ipv4Addr::new(198, 51, 100, 1)))
        );
        assert_eq!(
            record.first(iana::SOURCE_MAC_ADDRESS),
            Some(&Value::MacAddress([2; 6]))
        );
        assert_eq!(
            record.first(iana::DESTINATION_TRANSPORT_PORT),
            Some(&Value::Unsigned16(80))
        );
        assert_eq!(
            record.first(iana::TCP_CONTROL_BITS),
            Some(&Value::Unsigned16(0x02))
        );
        assert!(record.first(iana::ORIGINAL_EXPORTER_IPV4_ADDRESS).is_some());
    }

    #[test]
    fn a_section_not_at_the_start_of_the_packet_is_left_alone() {
        let records = converted(
            &mut Converter::default(),
            vec![data(&[
                (iana::SECTION_OFFSET, Value::Unsigned16(4)),
                (iana::DATA_LINK_FRAME_SECTION, Value::OctetArray(frame())),
            ])],
        );
        assert_eq!(records[0].first(iana::SOURCE_IPV4_ADDRESS), None);
        assert_eq!(records[0].first(iana::SOURCE_MAC_ADDRESS), None);
    }

    #[test]
    fn a_frame_yields_the_same_fields_through_ipfix_and_sflow() {
        use crate::protocol::sflow_v5::{
            self, DataSource, FlowRecord, FlowSample, HeaderProtocol, Interface, Sample,
            SampledHeader,
        };

        let by_ipfix = converted(
            &mut Converter::default(),
            vec![data(&[(
                iana::DATA_LINK_FRAME_SECTION,
                Value::OctetArray(frame()),
            )])],
        )
        .remove(0);

        let packet = sflow_v5::Packet {
            header: sflow_v5::Header {
                version: sflow_v5::VERSION,
                agent_address: None,
                sub_agent_id: 0,
                sequence_number: 1,
                uptime: 0,
            },
            samples: vec![Sample::Flow(FlowSample {
                sequence_number: 1,
                source_id: DataSource {
                    source_id_type: 0,
                    source_id_index: 1,
                },
                sampling_rate: 1,
                sample_pool: 0,
                drops: 0,
                input: Interface {
                    format: 0,
                    value: 0,
                },
                output: Interface {
                    format: 0,
                    value: 0,
                },
                records: vec![FlowRecord::SampledHeader(SampledHeader {
                    protocol: HeaderProtocol::EthernetIso88023,
                    frame_length: 64,
                    stripped: 0,
                    header: frame(),
                })],
            })],
        };
        let received = Received {
            exporter: SocketAddr::from(([192, 0, 2, 254], 6343)),
            time: None,
        };
        let mut records = Vec::new();
        crate::convert::sflow_v5::convert(packet, &received, &mut records);
        let by_sflow = records.remove(0);

        for element in [
            iana::SOURCE_MAC_ADDRESS,
            iana::DESTINATION_MAC_ADDRESS,
            iana::ETHERNET_TYPE,
            iana::SOURCE_IPV4_ADDRESS,
            iana::DESTINATION_IPV4_ADDRESS,
            iana::PROTOCOL_IDENTIFIER,
            iana::IP_TTL,
            iana::SOURCE_TRANSPORT_PORT,
            iana::DESTINATION_TRANSPORT_PORT,
            iana::TCP_CONTROL_BITS,
        ] {
            assert!(by_ipfix.first(element).is_some(), "{element:?}");
            assert_eq!(
                by_ipfix.first(element),
                by_sflow.first(element),
                "{element:?}"
            );
        }
    }

    #[test]
    fn options_records_are_records_with_a_scope() {
        let records = all_converted(
            &mut Converter::default(),
            vec![
                options(&[(iana::SAMPLING_INTERVAL, Value::Unsigned32(100))]),
                data(&[(iana::OCTET_DELTA_COUNT, Value::Unsigned64(1))]),
            ],
        );
        assert_eq!(records.len(), 2);
        let options = &records[0];
        assert_eq!(
            options.scope,
            [(
                Scope::Element(iana::OBSERVATION_DOMAIN_ID),
                Value::Unsigned32(DOMAIN)
            )]
        );
        assert_eq!(
            options.first(iana::SAMPLING_INTERVAL),
            Some(&Value::Unsigned32(100))
        );
        assert_eq!(options.first(iana::SAMPLING_PACKET_SPACE), None);
        assert!(
            options
                .first(iana::ORIGINAL_EXPORTER_IPV4_ADDRESS)
                .is_some()
        );
        let flow = &records[1];
        assert!(!flow.is_options());
        assert_eq!(
            flow.first(iana::SAMPLING_PACKET_SPACE),
            Some(&Value::Unsigned32(99))
        );
    }

    #[test]
    fn a_resent_template_converts_by_its_new_fields() {
        let mut converter = Converter::default();
        let before = converted(
            &mut converter,
            vec![data(&[(iana::OCTET_DELTA_COUNT, Value::Unsigned64(1))])],
        );
        let after = converted(
            &mut converter,
            vec![data(&[
                (iana::PACKET_DELTA_COUNT, Value::Unsigned64(2)),
                (iana::OCTET_DELTA_COUNT, Value::Unsigned64(3)),
            ])],
        );
        assert_eq!(
            before[0].first(iana::OCTET_DELTA_COUNT),
            Some(&Value::Unsigned64(1))
        );
        assert_eq!(before[0].first(iana::PACKET_DELTA_COUNT), None);
        assert_eq!(
            after[0].first(iana::PACKET_DELTA_COUNT),
            Some(&Value::Unsigned64(2))
        );
        assert_eq!(
            after[0].first(iana::OCTET_DELTA_COUNT),
            Some(&Value::Unsigned64(3))
        );
        assert_eq!(after[0].elements.len(), before[0].elements.len() + 1);
    }

    #[test]
    fn a_time_that_cannot_be_made_absolute_keeps_its_element() {
        let records = converted(
            &mut Converter::default(),
            vec![Set::Data(DataSet {
                template: Arc::new(Template {
                    template_id: 256,
                    fields: vec![
                        field(iana::FLOW_START_DELTA_MICROSECONDS),
                        field(iana::OCTET_DELTA_COUNT),
                    ],
                }),
                records: vec![
                    vec![Value::Unsigned32(1_500_000), Value::Unsigned64(1)],
                    vec![Value::OctetArray(vec![1, 2, 3]), Value::Unsigned64(2)],
                ],
            })],
        );
        assert_eq!(
            records[0].first(iana::FLOW_START_MILLISECONDS),
            Some(&Value::DateTimeMilliseconds(EXPORT_TIME_MS - 1_500))
        );
        assert_eq!(records[0].first(iana::FLOW_START_DELTA_MICROSECONDS), None);
        assert_eq!(records[1].first(iana::FLOW_START_MILLISECONDS), None);
        assert_eq!(
            records[1].first(iana::FLOW_START_DELTA_MICROSECONDS),
            Some(&Value::OctetArray(vec![1, 2, 3]))
        );
        assert_eq!(
            records[1].first(iana::OCTET_DELTA_COUNT),
            Some(&Value::Unsigned64(2))
        );
    }

    fn uptimes() -> Set {
        data(&[
            (iana::FLOW_START_SYS_UP_TIME, Value::Unsigned32(60_000)),
            (iana::FLOW_END_SYS_UP_TIME, Value::Unsigned32(61_000)),
        ])
    }

    #[test]
    fn uptimes_wait_for_the_exporters_init_time() {
        let mut converter = Converter::default();
        let before = converted(&mut converter, vec![uptimes()]);
        assert_eq!(
            before[0].first(iana::FLOW_START_SYS_UP_TIME),
            Some(&Value::Unsigned32(60_000))
        );
        assert_eq!(before[0].first(iana::FLOW_START_MILLISECONDS), None);

        let boot = options(&[(
            iana::SYSTEM_INIT_TIME_MILLISECONDS,
            Value::DateTimeMilliseconds(1_699_990_000_000),
        )]);
        let after = converted(&mut converter, vec![boot, uptimes()]);
        assert_eq!(
            after[0].first(iana::FLOW_START_MILLISECONDS),
            Some(&Value::DateTimeMilliseconds(1_699_990_060_000))
        );
        assert_eq!(
            after[0].first(iana::FLOW_END_MILLISECONDS),
            Some(&Value::DateTimeMilliseconds(1_699_990_061_000))
        );
        assert_eq!(after[0].first(iana::FLOW_START_SYS_UP_TIME), None);
    }

    #[test]
    fn times_before_the_export_time_are_made_absolute() {
        let records = converted(
            &mut Converter::default(),
            vec![data(&[
                (
                    iana::FLOW_START_DELTA_MICROSECONDS,
                    Value::Unsigned32(1_500_000),
                ),
                (iana::FLOW_END_DELTA_MICROSECONDS, Value::Unsigned32(250)),
            ])],
        );
        assert_eq!(
            records[0].first(iana::FLOW_START_MILLISECONDS),
            Some(&Value::DateTimeMilliseconds(EXPORT_TIME_MS - 1_500))
        );
        assert_eq!(
            records[0].first(iana::FLOW_END_MILLISECONDS),
            Some(&Value::DateTimeMilliseconds(EXPORT_TIME_MS - 1))
        );
    }

    #[test]
    fn records_get_their_selectors_sampling() {
        let selector = |id: u64, population: u32| {
            options(&[
                (iana::SELECTOR_ID, Value::Unsigned64(id)),
                (iana::SELECTOR_ALGORITHM, Value::Unsigned16(3)),
                (iana::SAMPLING_SIZE, Value::Unsigned32(1)),
                (iana::SAMPLING_POPULATION, Value::Unsigned32(population)),
            ])
        };
        let flow = |id: u64| {
            data(&[
                (iana::SELECTOR_ID, Value::Unsigned64(id)),
                (iana::OCTET_DELTA_COUNT, Value::Unsigned64(1)),
            ])
        };
        let records = converted(
            &mut Converter::default(),
            vec![selector(1, 100), selector(2, 1000), flow(2), flow(1)],
        );

        let populations: Vec<_> = records
            .iter()
            .map(|record| record.first(iana::SAMPLING_POPULATION).cloned())
            .collect();
        assert_eq!(
            populations,
            [Some(Value::Unsigned32(1000)), Some(Value::Unsigned32(100))]
        );
        assert_eq!(
            records[0].first(iana::SELECTOR_ALGORITHM),
            Some(&Value::Unsigned16(3))
        );
    }
}
