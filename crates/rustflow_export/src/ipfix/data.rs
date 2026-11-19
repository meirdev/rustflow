use std::net::IpAddr;

use chrono::{DateTime, Utc};
use rustflow_core::value::Value;

use crate::capture::Link;
use crate::ipfix::template::{FLOW_IPV4_TEMPLATE_ID, FLOW_IPV6_TEMPLATE_ID, packet_template_id};
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

    pub fn to_record(&self) -> Vec<Value> {
        vec![
            address(self.source_ip),
            address(self.destination_ip),
            Value::Unsigned8(self.ip_version()),
            Value::Unsigned8(self.protocol),
            Value::Unsigned16(self.source_port),
            Value::Unsigned16(self.destination_port),
            Value::Unsigned64(self.octet_count),
            Value::Unsigned64(self.packet_count),
            Value::Unsigned16(self.tcp_flags),
            unix_millis(self.flow_start),
            unix_millis(self.flow_end),
            Value::Unsigned8(self.flow_end_reason),
        ]
    }
}

fn address(ip: IpAddr) -> Value {
    match ip {
        IpAddr::V4(v4) => Value::Ipv4Address(v4),
        IpAddr::V6(v6) => Value::Ipv6Address(v6),
    }
}

/// A time before 1970 cannot be sent, so it is sent as 1970.
fn unix_millis(time: DateTime<Utc>) -> Value {
    Value::DateTimeMilliseconds(u64::try_from(time.timestamp_millis()).unwrap_or(0))
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

    pub fn to_record(&self) -> Vec<Value> {
        vec![
            Value::Unsigned16(u16::try_from(self.length).unwrap_or(u16::MAX)),
            Value::OctetArray(self.section.clone()),
        ]
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

    pub fn to_record(&self) -> Vec<Value> {
        let mut values = vec![Value::Unsigned32(self.observation_domain_id)];
        match self.sampling {
            Sampling::Count { interval } => values.extend([
                Value::Unsigned32(interval),
                Value::Unsigned16(SYSTEMATIC_COUNT_BASED),
                Value::Unsigned32(1),
                Value::Unsigned32(interval.saturating_sub(1)),
            ]),
        }
        values
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rustflow_core::information_element::{ElementId, Registry};
    use rustflow_core::ipfix::{self, DataSet, Header, Packet, Set, VERSION, encode_packet};
    use rustflow_core::timed_map::BoundedTimedMap;

    use super::*;
    use crate::ipfix::template::create_templates;
    use crate::meter::Mode;

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
            let templates = create_templates(Mode::Packet);
            let template = templates
                .iter()
                .find(|template| template.template_id == packet.template_id())
                .unwrap()
                .clone();
            let message = Packet {
                header: Header {
                    version: VERSION,
                    length: 0,
                    export_time: 0,
                    sequence_number: 0,
                    observation_domain_id: 1,
                },
                sets: vec![
                    Set::Templates(templates),
                    Set::Data(DataSet {
                        template,
                        records: vec![packet.to_record(); 2],
                    }),
                ],
            };
            let mut encoded = Vec::new();
            encode_packet(&mut encoded, &message).unwrap();

            let ttl = Duration::from_mins(10);
            let mut parser = ipfix::Parser::new(
                Registry::iana(),
                BoundedTimedMap::new(16, ttl),
                BoundedTimedMap::new(16, ttl),
            );
            let parsed = parser.parse(&encoded).unwrap();
            let set = parsed.sets[1].as_data().unwrap();
            assert_eq!(set.records.len(), 2);
            let values = &set.records[1];
            assert_eq!(values[0], Value::Unsigned16(u16::MAX));
            assert_eq!(values[1], Value::OctetArray(packet.section.clone()));
            let section = if link == Link::Ethernet {
                ElementId::DATA_LINK_FRAME_SECTION
            } else {
                ElementId::IP_HEADER_PACKET_SECTION
            };
            let elements: Vec<_> = set
                .template
                .fields
                .iter()
                .map(|field| field.element_id())
                .collect();
            assert_eq!(elements, [ElementId::DATA_LINK_FRAME_SIZE, section]);
        }
    }
}
