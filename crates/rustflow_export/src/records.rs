//! What the exporter sends, as records of IPFIX information elements: a
//! flow, a sampled packet's start, or the options describing the sampling.

use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use rustflow_core::convert::{Elements, Protocol, Record, Scope};
use rustflow_core::protocol::information_element::iana;
use rustflow_core::protocol::value::{Value, natural_length};

use crate::capture::Link;
use crate::flow::Flow;
use crate::sampler::Sampling;

/// `selectorAlgorithm` for systematic count-based sampling (RFC 5477).
const SYSTEMATIC_COUNT_BASED: u16 = 1;

/// The start of a sampled packet, exported as it was captured.
#[derive(Debug, Clone)]
pub struct PacketData {
    pub link: Link,
    pub length: u32,
    pub section: Vec<u8>,
}

/// The element lists of every record shape sent, made once and shared by
/// the records of each.
pub struct Shapes {
    flow_ipv4: Arc<Elements>,
    flow_ipv6: Arc<Elements>,
    frame: Arc<Elements>,
    ip: Arc<Elements>,
    options: Arc<Elements>,
}

impl Default for Shapes {
    fn default() -> Self {
        let flow = |source, destination| {
            Arc::new(Elements::from(vec![
                source,
                destination,
                iana::IP_VERSION,
                iana::PROTOCOL_IDENTIFIER,
                iana::SOURCE_TRANSPORT_PORT,
                iana::DESTINATION_TRANSPORT_PORT,
                iana::OCTET_DELTA_COUNT,
                iana::PACKET_DELTA_COUNT,
                iana::TCP_CONTROL_BITS,
                iana::FLOW_START_MILLISECONDS,
                iana::FLOW_END_MILLISECONDS,
                iana::FLOW_END_REASON,
            ]))
        };
        let packet = |section| Arc::new(Elements::from(vec![iana::DATA_LINK_FRAME_SIZE, section]));
        Self {
            flow_ipv4: flow(iana::SOURCE_IPV4_ADDRESS, iana::DESTINATION_IPV4_ADDRESS),
            flow_ipv6: flow(iana::SOURCE_IPV6_ADDRESS, iana::DESTINATION_IPV6_ADDRESS),
            frame: packet(iana::DATA_LINK_FRAME_SECTION),
            ip: packet(iana::IP_HEADER_PACKET_SECTION),
            options: Arc::new(Elements::from(vec![
                iana::SAMPLING_INTERVAL,
                iana::SELECTOR_ALGORITHM,
                iana::SAMPLING_PACKET_INTERVAL,
                iana::SAMPLING_PACKET_SPACE,
            ])),
        }
    }
}

impl Shapes {
    /// Flows of both address families and both kinds of packet section,
    /// as samples, so that their templates can be made ahead of them.
    pub fn samples(&self) -> [Record; 4] {
        let flow = |elements: &Arc<Elements>, source, destination| Record {
            protocol: Protocol::Ipfix,
            sequence_number: 0,
            scope: Vec::new(),
            elements: Arc::clone(elements),
            values: vec![
                source,
                destination,
                Value::Unsigned8(0),
                Value::Unsigned8(0),
                Value::Unsigned16(0),
                Value::Unsigned16(0),
                Value::Unsigned64(0),
                Value::Unsigned64(0),
                Value::Unsigned16(0),
                Value::DateTimeMilliseconds(0),
                Value::DateTimeMilliseconds(0),
                Value::Unsigned8(0),
            ],
        };
        let packet = |link| {
            self.packet(&PacketData {
                link,
                length: 0,
                section: Vec::new(),
            })
        };
        [
            flow(
                &self.flow_ipv4,
                Value::Ipv4Address([0; 4].into()),
                Value::Ipv4Address([0; 4].into()),
            ),
            flow(
                &self.flow_ipv6,
                Value::Ipv6Address([0; 16].into()),
                Value::Ipv6Address([0; 16].into()),
            ),
            packet(Link::Ethernet),
            packet(Link::Ip),
        ]
    }

    pub fn flow(&self, flow: &Flow) -> Record {
        let (elements, source, destination) = match (flow.key.source_ip, flow.key.destination_ip) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => (
                &self.flow_ipv4,
                Value::Ipv4Address(source),
                Value::Ipv4Address(destination),
            ),
            (IpAddr::V6(source), IpAddr::V6(destination)) => (
                &self.flow_ipv6,
                Value::Ipv6Address(source),
                Value::Ipv6Address(destination),
            ),
            // A flow's addresses are of one family; mapped ones go as IPv6.
            (source, destination) => (
                &self.flow_ipv6,
                Value::Ipv6Address(ipv6(source)),
                Value::Ipv6Address(ipv6(destination)),
            ),
        };
        let ip_version = if flow.key.source_ip.is_ipv4() { 4 } else { 6 };
        Record {
            protocol: Protocol::Ipfix,
            sequence_number: 0,
            scope: Vec::new(),
            elements: Arc::clone(elements),
            values: vec![
                source,
                destination,
                Value::Unsigned8(ip_version),
                Value::Unsigned8(flow.key.protocol),
                Value::Unsigned16(flow.key.source_port),
                Value::Unsigned16(flow.key.destination_port),
                Value::Unsigned64(flow.octet_count),
                Value::Unsigned64(flow.packet_count),
                Value::Unsigned16(flow.tcp_flags),
                Value::DateTimeMilliseconds(millis(flow.flow_start)),
                Value::DateTimeMilliseconds(millis(flow.flow_end)),
                Value::Unsigned8(flow.flow_end_reason.map_or(0, |reason| reason as u8)),
            ],
        }
    }

    pub fn packet(&self, packet: &PacketData) -> Record {
        let elements = match packet.link {
            Link::Ethernet => &self.frame,
            Link::Ip => &self.ip,
        };
        Record {
            protocol: Protocol::Ipfix,
            sequence_number: 0,
            scope: Vec::new(),
            elements: Arc::clone(elements),
            values: vec![
                Value::Unsigned16(u16::try_from(packet.length).unwrap_or(u16::MAX)),
                Value::OctetArray(packet.section.clone()),
            ],
        }
    }

    /// The options record saying how the observation domain samples.
    pub fn options(&self, observation_domain_id: u32, sampling: Sampling) -> Record {
        let Sampling::Count { interval } = sampling;
        Record {
            protocol: Protocol::Ipfix,
            sequence_number: 0,
            scope: vec![(
                Scope::Element(iana::OBSERVATION_DOMAIN_ID),
                Value::Unsigned32(observation_domain_id),
            )],
            elements: Arc::clone(&self.options),
            values: vec![
                Value::Unsigned32(interval),
                Value::Unsigned16(SYSTEMATIC_COUNT_BASED),
                Value::Unsigned32(1),
                Value::Unsigned32(interval.saturating_sub(1)),
            ],
        }
    }
}

fn ipv6(address: IpAddr) -> std::net::Ipv6Addr {
    match address {
        IpAddr::V4(address) => address.to_ipv6_mapped(),
        IpAddr::V6(address) => address,
    }
}

fn millis(time: DateTime<Utc>) -> u64 {
    u64::try_from(time.timestamp_millis()).unwrap_or(0)
}

/// How many bytes a record takes in a data set: its fixed-width values at
/// their width, and the others with the length that precedes them.
pub fn wire_size(record: &Record) -> usize {
    record
        .scope
        .iter()
        .map(|(_, value)| value)
        .chain(&record.values)
        .map(|value| match value {
            Value::OctetArray(bytes) => variable(bytes.len()),
            Value::String(string) => variable(string.len()),
            _ => natural_length(value).unwrap_or(0),
        })
        .sum()
}

fn variable(length: usize) -> usize {
    length + if length < 255 { 1 } else { 3 }
}
