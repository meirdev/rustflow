//! Records exported as sFlow v5 datagrams, each record a flow sample of one
//! packet.

use std::net::IpAddr;
use std::time::SystemTime;

use etherparse::{
    IpDscp, IpEcn, IpHeaders, IpNumber, Ipv4Extensions, Ipv4Header, Ipv6Extensions, Ipv6FlowLabel,
    Ipv6Header, PacketBuilder, TcpHeader,
};
use rustc_hash::FxHashMap;

use crate::convert::Record;
use crate::export::{ExportError, unix_millis, uptime};
use crate::protocol::information_element::{ElementId, iana};
use crate::protocol::sflow_v5::{
    AsPathSegment, DataSource, ExtendedGateway, ExtendedRouter, ExtendedSwitch, FlowRecord,
    FlowSample, Header, HeaderProtocol, Interface, Packet, Sample, SampledHeader, VERSION,
};
use crate::protocol::value::Value;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
/// How many bytes of a sampled packet agents usually send.
const HEADER_BYTES: usize = 128;
/// A VLAN the agent does not know (sFlow version 5 section 4).
const UNKNOWN_VLAN: u32 = 0xffff_ffff;
/// The largest ifIndex a compact sample's source ID holds.
const COMPACT_SOURCE: u32 = 1 << 24;
/// The largest ifIndex a compact sample's interfaces hold.
const COMPACT_INTERFACE: u32 = 1 << 30;

/// Exports records as the sFlow v5 datagrams of one agent.
///
/// sFlow samples packets, not flows, so each record goes as a flow sample
/// of one packet: a sampled header built from the record's addresses,
/// ports, protocol and TCP flags, as long as the record's octets per
/// packet, with the switch, router and gateway records for the VLANs,
/// next hop, prefix lengths and AS numbers the record has. The sampling
/// rate is the agent's. Each ingress interface is a data source with its
/// own sample sequence.
#[derive(Debug)]
pub struct Agent {
    agent_address: IpAddr,
    sub_agent_id: u32,
    boot_ms: u64,
    sampling_rate: u32,
    /// Datagrams sent so far, modulo 2^32.
    sequence_number: u32,
    sources: FxHashMap<u32, Source>,
}

#[derive(Debug, Default)]
struct Source {
    sequence_number: u32,
    sample_pool: u32,
}

impl Agent {
    pub fn new(agent_address: IpAddr, sub_agent_id: u32, boot: SystemTime) -> Self {
        Self {
            agent_address,
            sub_agent_id,
            boot_ms: unix_millis(boot),
            sampling_rate: 1,
            sequence_number: 0,
            sources: FxHashMap::default(),
        }
    }

    /// One packet in `rate` sampled.
    pub fn with_sampling_rate(mut self, rate: u32) -> Self {
        self.sampling_rate = rate.max(1);
        self
    }

    /// A datagram of `records`, exported at `now`, each a flow sample.
    pub fn export(&mut self, records: &[Record], now: SystemTime) -> Result<Packet, ExportError> {
        let samples = records
            .iter()
            .map(|record| self.sample(record))
            .collect::<Result<Vec<_>, _>>()?;
        let header = Header {
            version: VERSION,
            agent_address: Some(self.agent_address),
            sub_agent_id: self.sub_agent_id,
            sequence_number: self.sequence_number,
            uptime: uptime(unix_millis(now), self.boot_ms),
        };
        self.sequence_number = self.sequence_number.wrapping_add(1);
        Ok(Packet { header, samples })
    }

    fn sample(&mut self, record: &Record) -> Result<Sample, ExportError> {
        let ingress = unsigned32(record, iana::INGRESS_INTERFACE);
        let egress = unsigned32(record, iana::EGRESS_INTERFACE);
        let source = self.sources.entry(ingress).or_default();
        source.sequence_number = source.sequence_number.wrapping_add(1);
        source.sample_pool = source.sample_pool.wrapping_add(self.sampling_rate);

        let mut records = vec![FlowRecord::SampledHeader(sampled_header(record)?)];
        records.extend(extended_switch(record).map(FlowRecord::ExtendedSwitch));
        records.extend(extended_router(record).map(FlowRecord::ExtendedRouter));
        records.extend(extended_gateway(record).map(FlowRecord::ExtendedGateway));

        let sample = FlowSample {
            sequence_number: source.sequence_number,
            source_id: DataSource {
                source_id_type: 0,
                source_id_index: ingress,
            },
            sampling_rate: self.sampling_rate,
            sample_pool: source.sample_pool,
            drops: 0,
            input: Interface {
                format: 0,
                value: ingress,
            },
            output: Interface {
                format: 0,
                value: egress,
            },
            records,
        };
        let compact = ingress < COMPACT_SOURCE && egress < COMPACT_INTERFACE;
        Ok(if compact {
            Sample::Flow(sample)
        } else {
            Sample::ExpandedFlow(sample)
        })
    }
}

fn number(record: &Record, element: ElementId) -> Option<u64> {
    record.first(element).and_then(Value::as_u64)
}

fn unsigned32(record: &Record, element: ElementId) -> u32 {
    number(record, element).map_or(0, |n| u32::try_from(n).unwrap_or(u32::MAX))
}

fn unsigned16(record: &Record, element: ElementId) -> u16 {
    number(record, element).map_or(0, |n| u16::try_from(n).unwrap_or(u16::MAX))
}

fn unsigned8(record: &Record, element: ElementId) -> Option<u8> {
    number(record, element).map(|n| u8::try_from(n).unwrap_or(u8::MAX))
}

fn ip(record: &Record, ipv4: ElementId, ipv6: ElementId) -> Option<IpAddr> {
    match (record.first(ipv4), record.first(ipv6)) {
        (Some(Value::Ipv4Address(address)), _) => Some(IpAddr::V4(*address)),
        (_, Some(Value::Ipv6Address(address))) => Some(IpAddr::V6(*address)),
        _ => None,
    }
}

fn mac(record: &Record, element: ElementId, default: [u8; 6]) -> [u8; 6] {
    match record.first(element) {
        Some(Value::MacAddress(address)) => *address,
        _ => default,
    }
}

/// The first bytes of a packet of the record's flow, as long as the flow's
/// octets per packet: Ethernet, IP and the transport header, then zeros.
fn sampled_header(record: &Record) -> Result<SampledHeader, ExportError> {
    let source = ip(record, iana::SOURCE_IPV4_ADDRESS, iana::SOURCE_IPV6_ADDRESS)
        .ok_or(ExportError::Missing(iana::SOURCE_IPV4_ADDRESS))?;
    let destination = ip(
        record,
        iana::DESTINATION_IPV4_ADDRESS,
        iana::DESTINATION_IPV6_ADDRESS,
    )
    .ok_or(ExportError::Missing(iana::DESTINATION_IPV4_ADDRESS))?;
    let protocol = unsigned8(record, iana::PROTOCOL_IDENTIFIER).unwrap_or(0);
    let ttl = unsigned8(record, iana::IP_TTL).unwrap_or(64);
    let tos = unsigned8(record, iana::IP_CLASS_OF_SERVICE).unwrap_or(0);
    let octets = number(record, iana::OCTET_DELTA_COUNT)
        .or_else(|| number(record, iana::LAYER2_OCTET_DELTA_COUNT))
        .unwrap_or(0);
    let packets = number(record, iana::PACKET_DELTA_COUNT).unwrap_or(1).max(1);
    let frame_length = usize::try_from(octets / packets).unwrap_or(usize::MAX);

    let ethernet = PacketBuilder::ethernet2(
        mac(record, iana::SOURCE_MAC_ADDRESS, [2, 0, 0, 0, 0, 1]),
        mac(record, iana::DESTINATION_MAC_ADDRESS, [2, 0, 0, 0, 0, 2]),
    );
    let ip = match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let mut header = Ipv4Header::new(
                0,
                ttl,
                IpNumber(protocol),
                source.octets(),
                destination.octets(),
            )
            .expect("no payload yet");
            header.dscp = IpDscp::try_new(tos >> 2).expect("six bits");
            header.ecn = IpEcn::try_new(tos & 3).expect("two bits");
            ethernet.ip(IpHeaders::Ipv4(header, Ipv4Extensions::default()))
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let header = Ipv6Header {
                traffic_class: tos,
                flow_label: Ipv6FlowLabel::ZERO,
                payload_length: 0,
                next_header: IpNumber(protocol),
                hop_limit: ttl,
                source: source.octets(),
                destination: destination.octets(),
            };
            ethernet.ip(IpHeaders::Ipv6(header, Ipv6Extensions::default()))
        }
        _ => return Err(ExportError::Missing(iana::DESTINATION_IPV4_ADDRESS)),
    };

    let source_port = unsigned16(record, iana::SOURCE_TRANSPORT_PORT);
    let destination_port = unsigned16(record, iana::DESTINATION_TRANSPORT_PORT);
    let mut frame = Vec::with_capacity(frame_length);
    let written = match protocol {
        IPPROTO_TCP => {
            let mut tcp = TcpHeader::new(source_port, destination_port, 0, 65535);
            let flags = number(record, iana::TCP_CONTROL_BITS).unwrap_or(0);
            tcp.fin = flags & 0x001 != 0;
            tcp.syn = flags & 0x002 != 0;
            tcp.rst = flags & 0x004 != 0;
            tcp.psh = flags & 0x008 != 0;
            tcp.ack = flags & 0x010 != 0;
            tcp.urg = flags & 0x020 != 0;
            tcp.ece = flags & 0x040 != 0;
            tcp.cwr = flags & 0x080 != 0;
            tcp.ns = flags & 0x100 != 0;
            let step = ip.tcp_header(tcp);
            let payload = vec![0; frame_length.saturating_sub(step.size(0))];
            step.write(&mut frame, &payload)
        }
        IPPROTO_UDP => {
            let step = ip.udp(source_port, destination_port);
            let payload = vec![0; frame_length.saturating_sub(step.size(0))];
            step.write(&mut frame, &payload)
        }
        _ => {
            let payload = vec![0; frame_length.saturating_sub(ip.size(0))];
            ip.write(&mut frame, IpNumber(protocol), &payload)
        }
    };
    // Only a payload too long for the IP header's length field fails,
    // which the octets per packet of a flow do not reach.
    written.map_err(|_| ExportError::Missing(iana::OCTET_DELTA_COUNT))?;
    let frame_length = u32::try_from(frame.len()).unwrap_or(u32::MAX);
    frame.truncate(HEADER_BYTES);
    Ok(SampledHeader {
        protocol: HeaderProtocol::EthernetIso88023,
        frame_length,
        stripped: 0,
        header: frame,
    })
}

fn extended_switch(record: &Record) -> Option<ExtendedSwitch> {
    let vlan = |element| {
        number(record, element).map_or(UNKNOWN_VLAN, |n| u32::try_from(n).unwrap_or(UNKNOWN_VLAN))
    };
    let (src_vlan, dst_vlan) = (vlan(iana::VLAN_ID), vlan(iana::POST_VLAN_ID));
    (src_vlan != UNKNOWN_VLAN || dst_vlan != UNKNOWN_VLAN).then_some(ExtendedSwitch {
        src_vlan,
        src_priority: 0,
        dst_vlan,
        dst_priority: 0,
    })
}

fn extended_router(record: &Record) -> Option<ExtendedRouter> {
    let nexthop = ip(
        record,
        iana::IP_NEXT_HOP_IPV4_ADDRESS,
        iana::IP_NEXT_HOP_IPV6_ADDRESS,
    );
    let mask = |ipv4, ipv6| number(record, ipv4).or_else(|| number(record, ipv6));
    let src_mask = mask(
        iana::SOURCE_IPV4_PREFIX_LENGTH,
        iana::SOURCE_IPV6_PREFIX_LENGTH,
    );
    let dst_mask = mask(
        iana::DESTINATION_IPV4_PREFIX_LENGTH,
        iana::DESTINATION_IPV6_PREFIX_LENGTH,
    );
    (nexthop.is_some() || src_mask.is_some() || dst_mask.is_some()).then(|| ExtendedRouter {
        nexthop,
        src_mask_len: src_mask.map_or(0, |n| u32::try_from(n).unwrap_or(0)),
        dst_mask_len: dst_mask.map_or(0, |n| u32::try_from(n).unwrap_or(0)),
    })
}

fn extended_gateway(record: &Record) -> Option<ExtendedGateway> {
    let nexthop = ip(
        record,
        iana::BGP_NEXT_HOP_IPV4_ADDRESS,
        iana::BGP_NEXT_HOP_IPV6_ADDRESS,
    );
    let src_as = number(record, iana::BGP_SOURCE_AS_NUMBER);
    let dst_as = number(record, iana::BGP_DESTINATION_AS_NUMBER);
    (nexthop.is_some() || src_as.is_some() || dst_as.is_some()).then(|| ExtendedGateway {
        nexthop,
        r#as: 0,
        src_as: src_as.map_or(0, |n| u32::try_from(n).unwrap_or(0)),
        src_peer_as: 0,
        dst_as_path: dst_as
            .map(|n| AsPathSegment::AsSequence(vec![u32::try_from(n).unwrap_or(0)]))
            .into_iter()
            .collect(),
        communities: Vec::new(),
        localpref: 0,
    })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use crate::convert::{self, Elements, Protocol, Received};
    use crate::protocol::sflow_v5;

    const BOOT_MS: u64 = 1_700_000_000_000;

    fn at_ms(ms: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(ms)
    }

    fn record(fields: &[(ElementId, Value)]) -> Record {
        let (elements, values): (Vec<_>, Vec<_>) = fields.iter().cloned().unzip();
        Record {
            protocol: Protocol::Ipfix,
            sequence_number: 0,
            scope: Vec::new(),
            elements: Arc::new(Elements::from(elements)),
            values,
        }
    }

    fn flow() -> Record {
        record(&[
            (
                iana::SOURCE_MAC_ADDRESS,
                Value::MacAddress([2, 0, 0, 0, 0, 9]),
            ),
            (
                iana::SOURCE_IPV4_ADDRESS,
                Value::Ipv4Address([10, 0, 0, 1].into()),
            ),
            (
                iana::DESTINATION_IPV4_ADDRESS,
                Value::Ipv4Address([10, 0, 0, 2].into()),
            ),
            (
                iana::IP_NEXT_HOP_IPV4_ADDRESS,
                Value::Ipv4Address([10, 0, 0, 3].into()),
            ),
            (
                iana::BGP_NEXT_HOP_IPV4_ADDRESS,
                Value::Ipv4Address([10, 0, 0, 4].into()),
            ),
            (iana::INGRESS_INTERFACE, Value::Unsigned32(1)),
            (iana::EGRESS_INTERFACE, Value::Unsigned32(2)),
            (iana::PACKET_DELTA_COUNT, Value::Unsigned64(2)),
            (iana::OCTET_DELTA_COUNT, Value::Unsigned64(3000)),
            (iana::SOURCE_TRANSPORT_PORT, Value::Unsigned16(1234)),
            (iana::DESTINATION_TRANSPORT_PORT, Value::Unsigned16(80)),
            (iana::TCP_CONTROL_BITS, Value::Unsigned16(0x12)),
            (iana::PROTOCOL_IDENTIFIER, Value::Unsigned8(6)),
            (iana::IP_CLASS_OF_SERVICE, Value::Unsigned8(0x48)),
            (iana::IP_TTL, Value::Unsigned8(63)),
            (iana::VLAN_ID, Value::Unsigned16(7)),
            (iana::BGP_SOURCE_AS_NUMBER, Value::Unsigned32(64496)),
            (iana::BGP_DESTINATION_AS_NUMBER, Value::Unsigned32(64500)),
            (iana::SOURCE_IPV4_PREFIX_LENGTH, Value::Unsigned8(24)),
            (iana::DESTINATION_IPV4_PREFIX_LENGTH, Value::Unsigned8(16)),
        ])
    }

    fn collected(packet: &Packet) -> Vec<Record> {
        let mut buf = Vec::new();
        sflow_v5::write(packet, &mut buf).unwrap();
        let parsed = sflow_v5::parse(&buf).unwrap();
        let received = Received {
            exporter: SocketAddr::from(([192, 0, 2, 1], 6343)),
            time: None,
        };
        let mut records = Vec::new();
        convert::sflow_v5::convert(parsed, &received, &mut records);
        records
    }

    #[test]
    fn records_come_back_through_a_collector_as_sampled_packets() {
        let mut agent =
            Agent::new([192, 0, 2, 1].into(), 5, at_ms(BOOT_MS)).with_sampling_rate(100);
        let packet = agent
            .export(&[flow(), flow()], at_ms(BOOT_MS + 2_500))
            .unwrap();
        assert_eq!(packet.header.uptime, 2_500);
        assert_eq!(packet.header.sub_agent_id, 5);
        let Sample::Flow(sample) = &packet.samples[1] else {
            unreachable!()
        };
        assert_eq!(sample.sequence_number, 2);
        assert_eq!(sample.sample_pool, 200);
        let FlowRecord::SampledHeader(header) = &sample.records[0] else {
            unreachable!()
        };
        assert_eq!(header.frame_length, 1500, "the octets per packet");
        assert_eq!(header.header.len(), HEADER_BYTES);

        let records = collected(&packet);
        assert_eq!(records.len(), 2);
        let back = &records[0];
        for (element, value) in flow().iter() {
            match element {
                iana::PACKET_DELTA_COUNT => {
                    assert_eq!(back.first(element), Some(&Value::Unsigned64(1)));
                }
                iana::OCTET_DELTA_COUNT => assert_eq!(back.first(element), None),
                _ => assert_eq!(back.first(element), Some(value), "{element}"),
            }
        }
        assert_eq!(
            back.first(iana::LAYER2_OCTET_DELTA_COUNT),
            Some(&Value::Unsigned64(1500))
        );
        assert_eq!(
            back.first(iana::SAMPLING_POPULATION),
            Some(&Value::Unsigned32(100))
        );
        assert_eq!(
            back.first(iana::EXPORTER_IPV4_ADDRESS),
            Some(&Value::Ipv4Address([192, 0, 2, 1].into()))
        );

        let next = agent.export(&[flow()], at_ms(BOOT_MS + 3_000)).unwrap();
        assert_eq!(next.header.sequence_number, 1, "datagrams are counted");
    }

    #[test]
    fn ipv6_and_udp_flows_are_sampled_too() {
        let mut agent = Agent::new([192, 0, 2, 1].into(), 5, at_ms(BOOT_MS));
        let flow = record(&[
            (
                iana::SOURCE_IPV6_ADDRESS,
                Value::Ipv6Address([1; 16].into()),
            ),
            (
                iana::DESTINATION_IPV6_ADDRESS,
                Value::Ipv6Address([2; 16].into()),
            ),
            (iana::SOURCE_TRANSPORT_PORT, Value::Unsigned16(53)),
            (iana::DESTINATION_TRANSPORT_PORT, Value::Unsigned16(5353)),
            (iana::PROTOCOL_IDENTIFIER, Value::Unsigned8(17)),
            (iana::OCTET_DELTA_COUNT, Value::Unsigned64(80)),
        ]);
        let packet = agent
            .export(std::slice::from_ref(&flow), at_ms(BOOT_MS))
            .unwrap();
        let back = &collected(&packet)[0];
        for (element, value) in flow.iter() {
            if element != iana::OCTET_DELTA_COUNT {
                assert_eq!(back.first(element), Some(value), "{element}");
            }
        }
        assert_eq!(
            back.first(iana::LAYER2_OCTET_DELTA_COUNT),
            Some(&Value::Unsigned64(80))
        );
        assert!(back.first(iana::VLAN_ID).is_none(), "no switch record");
    }

    #[test]
    fn a_record_without_addresses_cannot_be_sampled() {
        let mut agent = Agent::new([192, 0, 2, 1].into(), 5, at_ms(BOOT_MS));
        let bare = record(&[(iana::OCTET_DELTA_COUNT, Value::Unsigned64(80))]);
        assert_eq!(
            agent.export(&[bare], at_ms(BOOT_MS)),
            Err(ExportError::Missing(iana::SOURCE_IPV4_ADDRESS))
        );
    }

    #[test]
    fn large_interface_numbers_take_an_expanded_sample() {
        let mut agent = Agent::new([192, 0, 2, 1].into(), 5, at_ms(BOOT_MS));
        let flow = record(&[
            (
                iana::SOURCE_IPV4_ADDRESS,
                Value::Ipv4Address([10, 0, 0, 1].into()),
            ),
            (
                iana::DESTINATION_IPV4_ADDRESS,
                Value::Ipv4Address([10, 0, 0, 2].into()),
            ),
            (iana::INGRESS_INTERFACE, Value::Unsigned32(1 << 25)),
        ]);
        let packet = agent.export(&[flow], at_ms(BOOT_MS)).unwrap();
        assert!(matches!(packet.samples[0], Sample::ExpandedFlow(_)));
        let back = &collected(&packet)[0];
        assert_eq!(
            back.first(iana::INGRESS_INTERFACE),
            Some(&Value::Unsigned32(1 << 25))
        );
    }
}
