use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use rustflow_core::common::ie_registry::DataType;
use rustflow_core::ipfix::parser::{DataRecord, FieldValue, ResolvedField};

use crate::capture::Link;
use crate::ipfix::template::{
    FLOW_IPV4_TEMPLATE_ID, FLOW_IPV6_TEMPLATE_ID, packet_fields, packet_template_id,
};
use crate::sampler::Sampling;

#[derive(Debug, Clone)]
pub struct FlowData {
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub protocol: u8,
    pub source_port: u16,
    pub destination_port: u16,
    pub octet_count: u64,
    pub packet_count: u64,
    pub tcp_flags: u16,
    pub flow_start: DateTime<Utc>,
    pub flow_end: DateTime<Utc>,
    pub flow_end_reason: u8,
}

impl FlowData {
    pub fn template_id(&self) -> u16 {
        match self.source_ip {
            IpAddr::V4(_) => FLOW_IPV4_TEMPLATE_ID,
            IpAddr::V6(_) => FLOW_IPV6_TEMPLATE_ID,
        }
    }

    fn ip_version(&self) -> u8 {
        match self.source_ip {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 6,
        }
    }

    pub fn to_data_record(&self) -> DataRecord {
        DataRecord::new(vec![
            address(self.source_ip),
            address(self.destination_ip),
            FieldValue::Unsigned8(self.ip_version()),
            FieldValue::Unsigned8(self.protocol),
            FieldValue::Unsigned16(self.source_port),
            FieldValue::Unsigned16(self.destination_port),
            FieldValue::Unsigned64(self.octet_count),
            FieldValue::Unsigned64(self.packet_count),
            FieldValue::Unsigned16(self.tcp_flags),
            FieldValue::DateTimeMilliseconds(self.flow_start),
            FieldValue::DateTimeMilliseconds(self.flow_end),
            FieldValue::Unsigned8(self.flow_end_reason),
        ])
    }
}

fn address(ip: IpAddr) -> FieldValue {
    match ip {
        IpAddr::V4(v4) => FieldValue::Ipv4Address(v4),
        IpAddr::V6(v6) => FieldValue::Ipv6Address(v6),
    }
}

#[derive(Debug, Clone)]
pub struct PacketData {
    pub link: Link,
    pub length: u32,
    pub section: Vec<u8>,
}

impl PacketData {
    pub fn template_id(&self) -> u16 {
        packet_template_id(self.link)
    }

    pub fn to_data_record(&self) -> DataRecord {
        let fields: Arc<[ResolvedField]> = packet_fields(self.link)
            .into_iter()
            .map(|spec| ResolvedField {
                spec,
                data_type: DataType::OctetArray,
                name: Arc::from(""),
            })
            .collect();
        DataRecord::from_template(
            fields,
            vec![
                FieldValue::Unsigned16(u16::try_from(self.length).unwrap_or(u16::MAX)),
                FieldValue::OctetArray(self.section.clone()),
            ],
        )
    }
}

/// `selectorAlgorithm` for systematic count-based sampling (RFC 5477).
const SYSTEMATIC_COUNT_BASED: u16 = 1;

#[derive(Debug)]
pub struct OptionsData {
    pub observation_domain_id: u32,
    pub sampling: Sampling,
}

impl OptionsData {
    pub fn new(observation_domain_id: u32, sampling: Sampling) -> Self {
        Self {
            observation_domain_id,
            sampling,
        }
    }

    pub fn to_data_record(&self) -> DataRecord {
        let mut values = vec![FieldValue::Unsigned32(self.observation_domain_id)];
        match self.sampling {
            Sampling::Count { interval } => values.extend([
                FieldValue::Unsigned32(interval),
                FieldValue::Unsigned16(SYSTEMATIC_COUNT_BASED),
                FieldValue::Unsigned32(1),
                FieldValue::Unsigned32(interval.saturating_sub(1)),
            ]),
        }
        DataRecord::new(values)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use rustflow_core::common::encoder::Encode;
    use rustflow_core::ipfix::parser::{
        Header, IPFIX_TEMPLATE_SET_ID, IPFIX_VERSION, IpfixPacket, IpfixParser, Record, Set,
    };

    use super::*;
    use crate::ipfix::template::create_templates;
    use crate::meter::Mode;

    fn message(sets: Vec<Set>) -> Vec<u8> {
        let packet = IpfixPacket {
            header: Header {
                version: IPFIX_VERSION,
                length: 0,
                export_time: Utc::now(),
                sequence_number: 0,
                observation_domain_id: 1,
            },
            sets,
        };
        let mut encoded = Vec::new();
        packet.encode(&mut encoded);
        encoded
    }

    #[test]
    fn packet_records_round_trip_at_every_prefix_width() {
        for (link, section_len) in [
            (Link::Ethernet, 254),
            (Link::Ethernet, 255),
            (Link::Ip, 1024),
        ] {
            let packet = PacketData {
                link,
                length: 70_000,
                section: (0..section_len).map(|i| i as u8).collect(),
            };
            let encoded = message(vec![
                Set {
                    id: IPFIX_TEMPLATE_SET_ID,
                    length: 0,
                    records: create_templates(Mode::Packet)
                        .into_iter()
                        .map(Record::Template)
                        .collect(),
                },
                Set {
                    id: packet.template_id(),
                    length: 0,
                    records: vec![Record::Data(packet.to_data_record()); 2],
                },
            ]);

            let (rest, parsed) = IpfixParser::default().parse(&encoded).unwrap();
            assert!(rest.is_empty());
            let set = &parsed.sets[1];
            let prefix = if section_len < 255 { 1 } else { 3 };
            assert_eq!(set.length as usize, 4 + 2 * (2 + prefix + section_len));
            let Record::Data(record) = &set.records[1] else {
                panic!("data record");
            };
            let values = record.values();
            assert!(matches!(values[0], FieldValue::Unsigned16(u16::MAX)));
            assert!(
                matches!(&values[1], FieldValue::OctetArray(bytes) if *bytes == packet.section)
            );
            let names: Vec<_> = record.iter().map(|(_, name, _)| name).collect();
            let section = if link == Link::Ethernet {
                "dataLinkFrameSection"
            } else {
                "ipHeaderPacketSection"
            };
            assert_eq!(names, ["dataLinkFrameSize", section]);
        }
    }
}
